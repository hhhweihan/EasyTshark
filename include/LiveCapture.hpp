#ifndef LiveCapture_hpp
#define LiveCapture_hpp

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "processUtil.hpp" // ProcessUtil::ProcHandle（跨平台进程句柄）
#include "tsharkDataType.hpp"

// 实时抓包：启动 tshark 把原始报文写入 pcap（-w），同时用 -T fields 把关键字段实时打到 stdout。
// 工作线程逐行解析成 Packet，通过回调实时交给调用方，实现边抓边显示。
// 停止语义：tshark 只关管道不会退出，必须发信号令其收尾，读循环随之 EOF。
// stopCapture 只负责发信号 + join，由工作线程内的 PcloseEx 统一回收，避免双重回收；可安全重复调用。
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

    // 开始抓包。onPacket 可为空（仅落盘）。captureFile 为落盘路径。
    // durationSeconds > 0 时加 -a duration:N 到时自动停止；0 表示不限时（手动 stopCapture）。
    bool startCapture(const std::string& adapterName, PacketCallback onPacket = nullptr,
                      const std::string& captureFile = "capture.pcap",
                      int durationSeconds = 0);

    // 停止抓包：发 SIGTERM 令 tshark 收尾，join 工作线程。幂等，可安全重复调用。
    bool stopCapture();

    bool isCapturing() const { return running_.load(); }

private:
    void captureWorkThreadEntry(std::string adapterName, std::string captureFile,
                                PacketCallback onPacket, int durationSeconds);

private:
    std::string                  tsharkPath_;
    std::string                  ip2RegionDbPath_;
    std::atomic<bool>            stopFlag_;
    std::atomic<bool>            running_; // 抓包工作线程活跃标志（线程自然退出后为 false，
                                           // 供 isCapturing 区分“线程对象存在”与“真在抓包”）
    std::atomic<bool>            startFailed_; // 工作线程启动 tshark 失败时置位，供 startCapture 回传
    std::atomic<ProcessUtil::ProcHandle> tsharkPid_; // 供 stopCapture 发信号；kInvalidProc 表示未就位
    std::shared_ptr<std::thread> captureWorkThread_;
};

#endif
