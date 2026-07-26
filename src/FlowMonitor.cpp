#include "FlowMonitor.hpp"

#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <vector>

#include "loguru/loguru.hpp"
#include "processUtil.hpp"
#include "tsharkCommand.hpp"
#include "tsharkDataType.hpp"

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
    // 第一步：置位停止标志并 join 监控线程。
    // 关键：join 时绝不能持 adapterFlowTrendMapLock——监控线程内部要拿同一把锁，
    // 否则死锁。故先在无锁状态下让线程收敛退出，再去撕毁 map。
    stopFlag = true;
    if (flowTrendThread.joinable())
    {
        flowTrendThread.join();
    }

    // 第二步：线程已退出，可安全清理监控 map（此时无并发访问）
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 先杀死对应的tshark进程
    for (const auto& adapterPipePair : adapterFlowTrendMonitorMap)
    {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    // 然后关闭管道并从轮询器中移除
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
    // 先上锁再读 adapterFlowTrendMonitorStartTime：该值由 startMonitor 在锁内写入，
    // 放到锁外读会与之竞态。锁同时保护随后对 adapterFlowTrendMonitorMap 的遍历。
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 获取所有网卡流量统计数据
    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
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

        // 稀疏拷贝：只搬运窗口 [startWindow, endWindow] 内“确实有流量”的秒，
        // 不再对整个窗口逐秒稠密填 0。sourceSeries 是有序 map，用 lower_bound/
        // upper_bound 定位区间端点即可，避免对上千秒的空洞做无谓插入。
        // 语义变化：结果中缺失的秒表示该秒无流量（原实现会显式填 0）。
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
    // 开始监控所有网卡流量统计数据
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMonitorStartTime = time(nullptr);
    stopFlag                         = false;

    // 复用前一次可能残留的注册项（正常 stop 后为空）
    flowTrendPoller.clear();
    fdToAdapter.clear();

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = TsharkCommand::listNetworkAdapters(tsharkPath);

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (const auto& adapter : adapterList)
    {
        adapterFlowTrendMonitorMap.insert(std::make_pair(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap[adapter.name];

        // 启动 tshark 命令：网卡名作为独立 argv 参数，不经过 shell，避免注入
        std::vector<std::string> tsharkArgs = {
            tsharkPath, "-i", adapter.name, "-T", "fields",
            "-e", "frame.time_epoch", "-e", "frame.len"};
        LOG_F(INFO, "Starting tshark for adapter: %s", adapter.name.c_str());

        pid_t tsharkPid = 0;
        FILE* pipe      = ProcessUtil::PopenEx(tsharkArgs, &tsharkPid, "r");
        if (!pipe)
        {
            LOG_F(ERROR, "Failed to start tshark for adapter: %s", adapter.name.c_str());
            continue;
        }

        // 获取管道的文件描述符并设置为非阻塞模式
        int pipeFd = fileno(pipe);
        int flags  = fcntl(pipeFd, F_GETFL, 0);
        fcntl(pipeFd, F_SETFL, flags | O_NONBLOCK);

        // 注册到事件轮询器
        if (!flowTrendPoller.add(pipeFd))
        {
            LOG_F(ERROR, "Failed to add pipe to poller for adapter: %s", adapter.name.c_str());
            fclose(pipe);
            continue;
        }

        // 保存管道和进程 ID
        monitorInfo.monitorTsharkPipe = pipe;
        monitorInfo.tsharkPid         = tsharkPid;

        // 建立 fd → 网卡监控状态的 O(1) 反查索引（monitorInfo 是 map 内元素，地址稳定）
        fdToAdapter[pipeFd] = &monitorInfo;
    }

    // 启动监控线程处理轮询事件（joinable，由 stopMonitor / 析构负责 join）
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
    // 每 500ms 轮询一次：既能及时响应新数据，也能在所有网卡管道都关闭后
    // （size()==0）干净退出线程，避免原先 while(true)+epoll_wait(-1) 的线程泄漏。
    // stopFlag 用于让 stopMonitor 主动打断轮询、令线程尽快 join。
    while (!stopFlag && flowTrendPoller.size() > 0)
    {
        std::vector<int> readyFds = flowTrendPoller.wait(500);

        for (std::size_t idx = 0; idx < readyFds.size(); ++idx)
        {
            int pipeFd = readyFds[idx];

            // 先 O(1) 定位该 fd 对应的网卡监控状态，本轮所有读入都归到它名下。
            // map 元素地址稳定、且 stopMonitor 会先 join 本线程再动 map，故指针在本轮有效。
            AdapterMonitorInfo* info = nullptr;
            {
                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                auto                                   it = fdToAdapter.find(pipeFd);
                if (it != fdToAdapter.end())
                {
                    info = it->second;
                }
            }

            char    buffer[256];
            ssize_t bytesRead;
            while ((bytesRead = read(pipeFd, buffer, sizeof(buffer))) > 0)
            {
                if (!info)
                {
                    continue; // 理论上不会发生：找不到归属就丢弃这段数据
                }

                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                info->readLeftover.append(buffer, static_cast<size_t>(bytesRead));

                // 一次 read 可能含多行，也可能以半行结尾：切出所有完整行逐一解析，
                // 未完成的行尾留在 readLeftover 等下次 read 续上（旧实现只解析首行）。
                size_t nl;
                while ((nl = info->readLeftover.find('\n')) != std::string::npos)
                {
                    std::string oneLine = info->readLeftover.substr(0, nl);
                    info->readLeftover.erase(0, nl + 1);
                    accumulateFlowLine(oneLine, *info);
                }
            }

            // 检查管道是否关闭（tshark 自行退出 → EOF）
            if (bytesRead == 0 || (bytesRead == -1 && errno != EAGAIN))
            {
                LOG_F(INFO, "Pipe closed or error occurred for fd: %d", pipeFd);
                flowTrendPoller.remove(pipeFd); // 先从轮询器移除，再关闭 fd

                std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
                auto                                   it = fdToAdapter.find(pipeFd);
                if (it != fdToAdapter.end())
                {
                    AdapterMonitorInfo* dead = it->second;
                    // 回收子进程避免僵尸，并把 pid 置 0，防止 stopMonitor 再对
                    // 可能被系统复用的 pid 误发信号。
                    if (dead->tsharkPid > 0)
                    {
                        ProcessUtil::Kill(dead->tsharkPid);
                        dead->tsharkPid = 0;
                    }
                    // fclose 连带关闭底层 fd 并置空——绝不能再 close(pipeFd)，否则与
                    // fclose 造成对同一 fd 的二次关闭。置空后 stopMonitor 见空即跳过。
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
