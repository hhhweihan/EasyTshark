#ifndef NativeCapture_hpp
#define NativeCapture_hpp

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "tsharkDataType.hpp"

// 自研实时抓包引擎：基于 libpcap，与 LiveCapture 职责平行，供无 tshark 环境兜底。
// 抓包线程 pcap_next_ex 逐包解析后回调，并按经典 pcap 格式落盘（停止后可离线解析）。
// 线程模型：回调在抓包线程执行，调用方自行加锁。
// 无 libpcap 编译（EASYTSHARK_HAVE_LIBPCAP 未定义）时：listAdapters 返回空、startCapture 返回 false。
class NativeCapture
{
public:
    using PacketCallback = std::function<void(const std::shared_ptr<Packet>&)>;

    NativeCapture();
    ~NativeCapture();

    bool startCapture(const std::string& adapterName, PacketCallback onPacket,
                      const std::string& captureFile, int durationSeconds = 0);
    bool stopCapture();
    bool isCapturing() const { return running_.load(); }

    // 网卡枚举（libpcap 实现）；无 libpcap 时返回空。
    static std::vector<AdapterInfo> listAdapters();

private:
    void workThread(std::string adapterName, PacketCallback onPacket,
                    std::string captureFile, int durationSeconds);

    std::atomic<bool> stopFlag_{false};
    std::atomic<bool> running_{false};
    std::shared_ptr<std::thread> thread_;
};

#endif
