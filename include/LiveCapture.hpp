#ifndef LiveCapture_hpp
#define LiveCapture_hpp

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "processUtil.hpp" // ProcessUtil::ProcHandle（跨平台进程句柄）
#include "tsharkDataType.hpp"

// 实时抓包：在指定网卡上启动 tshark，一边把原始报文写入 pcap 文件（-w），一边用
// -T fields 把每个包的关键字段实时打到 stdout（-l 行缓冲、-P 即便写文件也打印）。
// 工作线程逐行解析成 Packet，并通过回调把每个包**实时**交给调用方（UI），实现边抓边显示。
//
// 停止语义：tshark 是往 -w 文件写、几乎不写 stdout，只关管道它不会退出，必须给它发信号
// 令其收尾（flush 文件 + 关 stdout），读循环随之得到 EOF 优雅结束。stopCapture 只负责
// 发信号 + join，由工作线程内的 PcloseEx 统一 waitpid 回收，避免双重回收。可安全重复调用。
class LiveCapture
{
public:
    // 每解析出一个包就回调一次；回调在**抓包工作线程**上下文执行，调用方需自行加锁。
    using PacketCallback = std::function<void(const std::shared_ptr<Packet>&)>;

    explicit LiveCapture(const std::string& tsharkPath,
                         const std::string& ip2RegionDbPath = "resources/ip2region.xdb");
    ~LiveCapture();

    std::string getTsharkPath() const { return tsharkPath_; }
    void        setTsharkPath(const std::string& path) { tsharkPath_ = path; }

    // 开始抓包。onPacket 可为空（仅落盘不实时回调）。captureFile 为落盘 pcap 路径。
    bool startCapture(const std::string& adapterName, PacketCallback onPacket = nullptr,
                      const std::string& captureFile = "capture.pcap");

    // 停止抓包：发 SIGTERM 令 tshark 收尾，join 工作线程。幂等，可安全重复调用。
    bool stopCapture();

    bool isCapturing() const { return captureWorkThread_ != nullptr; }

private:
    void captureWorkThreadEntry(std::string adapterName, std::string captureFile,
                                PacketCallback onPacket);

private:
    std::string                  tsharkPath_;
    std::string                  ip2RegionDbPath_;
    std::atomic<bool>            stopFlag_;
    std::atomic<bool>            startFailed_; // 工作线程启动 tshark 失败时置位，供 startCapture 回传
    std::atomic<ProcessUtil::ProcHandle> tsharkPid_; // 供 stopCapture 发信号；kInvalidProc 表示未就位
    std::shared_ptr<std::thread> captureWorkThread_;
};

#endif
