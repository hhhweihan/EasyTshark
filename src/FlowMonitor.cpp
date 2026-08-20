#include "FlowMonitor.hpp"

#include <cstdio> // fileno / fclose
#include <ctime>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "loguru/loguru.hpp"
#include "platform/PipeIO.hpp" // 跨平台非阻塞管道读取（替代 fcntl/read）
#include "processUtil.hpp"
#include "tsharkCommand.hpp"
#include "tsharkDataType.hpp"

#if defined(_WIN32)
#include <io.h> // _fileno
// POSIX fileno 在 MSVC 下名为 _fileno；统一到 fileno，POSIX 分支不受影响。
#ifndef fileno
#define fileno _fileno
#endif
#endif

FlowMonitor::FlowMonitor(const std::string& tsharkPath)
    : tsharkPath(tsharkPath), adapterFlowTrendMonitorStartTime(0), stopFlag(false)
{
}

FlowMonitor::~FlowMonitor()
{
    // 兜底：即便调用方忘记 stop，也要确保监控线程退出，避免线程访问已销毁成员
    stopMonitorAdaptersFlowTrend();
}

void FlowMonitor::stopMonitorAdaptersFlowTrend()
{
    // 先置停止标志并 join 监控线程。join 时绝不能持 adapterFlowTrendMapLock——
    // 监控线程内部要拿同一把锁，否则死锁。故先无锁让线程退出，再撕毁 map。
    stopFlag = true;
    if (flowTrendThread.joinable())
    {
        flowTrendThread.join();
    }

    // 线程已退出，可安全清理监控 map（此时无并发访问）
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    for (const auto& adapterPipePair : adapterFlowTrendMonitorMap)
    {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    for (auto& adapterPipePair : adapterFlowTrendMonitorMap)
    {
        if (adapterPipePair.second.monitorTsharkPipe)
        {
            int pipeFd = fileno(adapterPipePair.second.monitorTsharkPipe);
            if (pipeFd != -1)
            {
                flowTrendPoller.remove(pipeFd);
                // 关闭管道（子进程已在上面的 Kill 中回收，这里只需关闭 FILE*）
                fclose(adapterPipePair.second.monitorTsharkPipe);
            }
        }
        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }
    adapterFlowTrendMonitorMap.clear();
    fdToAdapter.clear();
    flowTrendPoller.clear();
}

void FlowMonitor::getAdaptersFlowTrendData(
    std::map<std::string, std::map<long, long>>& flowTrendData)
{
    // 锁保护 adapterFlowTrendMonitorStartTime（startMonitor 在锁内写）与随后对 map 的遍历。
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    long timeNow = time(nullptr);

    // 滑动窗口左右端点：不足 300 秒时从监控起点算起，超过后取 [当前-300, 当前]。
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300
                           ? timeNow - 300
                           : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300
                         ? timeNow
                         : adapterFlowTrendMonitorStartTime + 300;

    for (const auto& adapterPipePair : adapterFlowTrendMonitorMap)
    {
        auto&       targetSeries = flowTrendData[adapterPipePair.first];
        const auto& sourceSeries = adapterPipePair.second.flowTrendData;

        // 稀疏拷贝：只搬运窗口内“确实有流量”的秒（有序 map 用 lower/upper_bound 定位区间），
        // 不逐秒填 0。语义变化：结果中缺失的秒表示该秒无流量。
        auto begin = sourceSeries.lower_bound(startWindow);
        auto end   = sourceSeries.upper_bound(endWindow);
        for (auto it = begin; it != end; ++it)
        {
            targetSeries[it->first] = it->second;
        }
    }
}

void FlowMonitor::startMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMonitorStartTime = time(nullptr);
    stopFlag                         = false;

    // 复用前一次可能残留的注册项（正常 stop 后为空）
    flowTrendPoller.clear();
    fdToAdapter.clear();

    std::vector<AdapterInfo> adapterList = TsharkCommand::listNetworkAdapters(tsharkPath);

    for (const auto& adapter : adapterList)
    {
        adapterFlowTrendMonitorMap.insert(std::make_pair(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap[adapter.name];

        // 启动 tshark 命令：网卡名作为独立 argv 参数，不经过 shell，避免注入
        std::vector<std::string> tsharkArgs = {
            tsharkPath, "-i", adapter.name, "-T", "fields",
            "-e", "frame.time_epoch", "-e", "frame.len"};
        LOG_F(INFO, "Starting tshark for adapter: %s", adapter.name.c_str());

        ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
        FILE*                   pipe      = ProcessUtil::PopenEx(tsharkArgs, &tsharkPid, "r");
        if (!pipe)
        {
            LOG_F(ERROR, "Failed to start tshark for adapter: %s", adapter.name.c_str());
            continue;
        }

        // 获取管道的文件描述符并设置为非阻塞模式（Windows 下为空操作，读时用 PeekNamedPipe）
        int pipeFd = fileno(pipe);
        platform::setPipeNonblocking(pipeFd);

        if (!flowTrendPoller.add(pipeFd))
        {
            LOG_F(ERROR, "Failed to add pipe to poller for adapter: %s", adapter.name.c_str());
            fclose(pipe);
            continue;
        }

        monitorInfo.monitorTsharkPipe = pipe;
        monitorInfo.tsharkPid         = tsharkPid;

        // fd → 网卡监控状态的 O(1) 反查索引（monitorInfo 是 map 内元素，地址稳定）
        fdToAdapter[pipeFd] = &monitorInfo;
    }

    // 启动监控线程（joinable，由 stopMonitor / 析构负责 join）
    flowTrendThread = std::thread(&FlowMonitor::adapterFlowTrendMonitorThreadEntry, this);
}

namespace
{
// 解析一行 "时间戳 长度"，把该包长度累加到对应秒；调用方须持有 map 锁。
void accumulateFlowLine(const std::string& line, AdapterMonitorInfo& info)
{
    if (line.find("Capturing") != std::string::npos ||
        line.find("captured") != std::string::npos)
    {
        return; // tshark 的状态行，非数据
    }

    std::istringstream iss(line);
    std::string        timestampStr, lengthStr;
    if (!(iss >> timestampStr >> lengthStr))
    {
        return; // 空行或字段不足，忽略
    }

    try
    {
        long timestamp    = static_cast<long>(std::stod(timestampStr));
        long packetLength = std::stol(lengthStr);
        info.flowTrendData[timestamp] += packetLength;

        // 保留最近 300 秒的数据（有序 map，begin() 即最旧的一秒）
        while (info.flowTrendData.size() > 300)
        {
            info.flowTrendData.erase(info.flowTrendData.begin());
        }
    }
    catch (const std::exception&)
    {
        // 非数字行忽略，不中断监控
    }
}
} // namespace

void FlowMonitor::adapterFlowTrendMonitorThreadEntry()
{
    // 每 500ms 轮询一次：及时响应新数据，也能在所有管道关闭(size()==0)后干净退出，避免线程泄漏。
    // stopFlag 让 stopMonitor 主动打断轮询、令线程尽快 join。
    while (!stopFlag && flowTrendPoller.size() > 0)
    {
        std::vector<int> readyFds = flowTrendPoller.wait(500);

        for (std::size_t idx = 0; idx < readyFds.size(); ++idx)
        {
            int pipeFd = readyFds[idx];

            // O(1) 定位该 fd 的网卡监控状态。map 元素地址稳定、stopMonitor 会先 join 再动 map，故指针本轮有效。
            AdapterMonitorInfo* info = nullptr;
            {
                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                auto                                   it = fdToAdapter.find(pipeFd);
                if (it != fdToAdapter.end())
                {
                    info = it->second;
                }
            }

            char buffer[256];
            long bytesRead;
            // pipeRead 三态：>0 读到数据；0 暂无数据(EAGAIN)；-1 对端关闭(EOF)/出错。
            while ((bytesRead = platform::pipeRead(pipeFd, buffer, sizeof(buffer))) > 0)
            {
                if (!info)
                {
                    continue; // 理论上不会发生：找不到归属就丢弃这段数据
                }

                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                info->readLeftover.append(buffer, static_cast<size_t>(bytesRead));

                // 一次 read 可能含多行或半行：切出所有完整行逐一解析，未完成的行尾留在 readLeftover 续上。
                size_t nl;
                while ((nl = info->readLeftover.find('\n')) != std::string::npos)
                {
                    std::string oneLine = info->readLeftover.substr(0, nl);
                    info->readLeftover.erase(0, nl + 1);
                    accumulateFlowLine(oneLine, *info);
                }
            }

            // 检查管道是否关闭（tshark 自行退出 → EOF）：pipeRead 返回 -1 即关闭/出错。
            if (bytesRead < 0)
            {
                LOG_F(INFO, "Pipe closed or error occurred for fd: %d", pipeFd);
                flowTrendPoller.remove(pipeFd); // 先从轮询器移除，再关闭 fd

                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                auto                                   it = fdToAdapter.find(pipeFd);
                if (it != fdToAdapter.end())
                {
                    AdapterMonitorInfo* dead = it->second;
                    // 回收子进程避免僵尸，句柄置无效防止 stopMonitor 对复用的 pid 误发信号。
                    if (ProcessUtil::ValidProc(dead->tsharkPid))
                    {
                        ProcessUtil::Kill(dead->tsharkPid);
                        dead->tsharkPid = ProcessUtil::kInvalidProc;
                    }
                    // fclose 连带关闭底层 fd 并置空，绝不能再 close(pipeFd) 造成二次关闭。
                    if (dead->monitorTsharkPipe)
                    {
                        fclose(dead->monitorTsharkPipe);
                        dead->monitorTsharkPipe = nullptr;
                    }
                    fdToAdapter.erase(it);
                }
            }
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry has ended.");
}
