#include "LiveCapture.hpp"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <vector>

#include "loguru/loguru.hpp"
#include "PacketParser.hpp"
#include "processUtil.hpp"
#include "tsharkCommand.hpp"
#include "utils.hpp"

LiveCapture::LiveCapture(const std::string& tsharkPath, const std::string& ip2RegionDbPath)
    : tsharkPath_(tsharkPath),
      ip2RegionDbPath_(ip2RegionDbPath),
      stopFlag_(false),
      startFailed_(false),
      tsharkPid_(-1)
{
}

LiveCapture::~LiveCapture()
{
    stopCapture(); // 兜底：避免析构时线程/子进程悬挂
}

bool LiveCapture::startCapture(const std::string& adapterName, PacketCallback onPacket,
                               const std::string& captureFile)
{
    if (captureWorkThread_)
    {
        LOG_F(WARNING, "已在抓包中，忽略重复的开始请求");
        return false;
    }
    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());
    stopFlag_    = false;
    startFailed_ = false;
    tsharkPid_   = -1;
    captureWorkThread_ = std::make_shared<std::thread>(&LiveCapture::captureWorkThreadEntry, this,
                                                       adapterName, captureFile, std::move(onPacket));

    // 工作线程要过一会儿才真正 fork 出 tshark，这里等它给出确定结果：
    //   成功 → tsharkPid_ 落定(>0)；失败 → startFailed_ 置位。
    // 否则 startCapture 恒返回 true，PopenEx 失败时 isCapturing() 会误报“在抓包”。
    // 极窄启动窗口内轮询，最多约 1s；超时仍未定则乐观返回（tshark 可能只是启动慢）。
    for (int i = 0; i < 200; ++i)
    {
        if (tsharkPid_.load() > 0)
            return true;
        if (startFailed_.load())
        {
            if (captureWorkThread_->joinable())
                captureWorkThread_->join();
            captureWorkThread_.reset();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

bool LiveCapture::stopCapture()
{
    if (!captureWorkThread_)
        return false; // 未在抓包 / 已停止：幂等，避免二次 join 抛异常

    LOG_F(INFO, "即将停止抓包");
    stopFlag_ = true;

    // tshark 往 -w 文件写、几乎不写 stdout，只关管道它不会退出：必须发信号令其收尾，
    // 读循环随之 EOF 退出。极窄的启动窗口内 pid 可能尚未就位，短暂等待其落定。
    pid_t pid = tsharkPid_.load();
    for (int i = 0; pid <= 0 && i < 200; ++i)
    {
        if (!captureWorkThread_->joinable())
            break; // 线程已提前结束（如 Popen 失败），无需再等
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        pid = tsharkPid_.load();
    }
    // 只发信号、不 waitpid —— 交给工作线程里的 PcloseEx 统一回收，避免双重 waitpid。
    if (pid > 0)
        ::kill(pid, SIGTERM);

    if (captureWorkThread_->joinable())
        captureWorkThread_->join();
    captureWorkThread_.reset();
    return true;
}

void LiveCapture::captureWorkThreadEntry(std::string adapterName, std::string captureFile,
                                         PacketCallback onPacket)
{
    try
    {
        // -i 抓指定网卡；-l 行缓冲即时输出；-w + -F pcap 落盘原始报文；
        // -P 令即便写文件也把包摘要打到 stdout；随后接共享字段列表（-T fields -e ...），
        // 字段顺序与 PacketParser::parseLine 严格对应，可与离线路径复用同一解析器。
        std::vector<std::string> tsharkArgs = {tsharkPath_, "-i",   adapterName, "-l", "-w",
                                               captureFile, "-F",   "pcap",      "-P"};
        std::vector<std::string> fieldArgs = TsharkCommand::tsharkFieldArgs();
        tsharkArgs.insert(tsharkArgs.end(), fieldArgs.begin(), fieldArgs.end());

        LOG_F(INFO, "Starting live capture on adapter: %s", adapterName.c_str());
        pid_t tsharkPid = -1;
        FILE* pipe      = ProcessUtil::PopenEx(tsharkArgs, &tsharkPid, "r");
        if (!pipe)
        {
            LOG_F(ERROR, "Failed to run tshark command!");
            startFailed_ = true; // 回传失败，令 startCapture 返回 false、不再误判为“在抓包”
            return;
        }
        tsharkPid_ = tsharkPid; // 就位后 stopCapture 才能对它发信号

        // IP 地理库只需初始化一次；失败则地理位置留空，不影响抓包。
        bool ip2RegionReady = IP2RegionUtil::init(ip2RegionDbPath_);

        char buffer[8192];
        // 报文在 capture.pcap 中的偏移：首包紧随 24 字节全局文件头(sizeof(PcapHeader))之后。
        // 用 64 位累加，避免长时间抓包偏移超过 4GB 溢出。
        uint64_t file_offset = sizeof(PcapHeader);
        while (!stopFlag_ && fgets(buffer, sizeof(buffer), pipe) != nullptr)
        {
            std::shared_ptr<Packet> packet = std::make_shared<Packet>();
            if (!PacketParser::parseLine(buffer, *packet))
            {
                // 实时路径：单行解析失败就跳过（可能是 tshark 的状态行），不中止整轮。
                // 偏移可能就此错位，但实时展示以“尽力而为”为主；停止后会离线重解析纠正。
                continue;
            }
            packet->file_offset = file_offset + sizeof(PacketHeader);
            file_offset         = file_offset + sizeof(PacketHeader) + packet->cap_len;

            if (ip2RegionReady)
            {
                packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
                packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);
            }

            if (onPacket)
                onPacket(packet);
        }

        ProcessUtil::PcloseEx(pipe, tsharkPid); // fclose + waitpid 回收，单点回收
        tsharkPid_ = -1;
        LOG_F(INFO, "Capture thread exiting gracefully.");
    }
    catch (const std::exception& e)
    {
        LOG_F(ERROR, "Exception in captureWorkThreadEntry: %s", e.what());
    }
    catch (...)
    {
        LOG_F(ERROR, "Unknown exception in captureWorkThreadEntry.");
    }
}
