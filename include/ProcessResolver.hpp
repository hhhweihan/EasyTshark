#ifndef ProcessResolver_hpp
#define ProcessResolver_hpp

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

struct Packet;

// 实时抓包时把报文反查到本机产生它的进程（Wireshark 式"进程列"）。
// 只能解析当前用户自己的 socket（除非以 root 运行），且只在 macOS / Linux 生效；
// 其他平台 annotate() 恒为 no-op（沿用项目里"不支持平台优雅降级"的惯例）。
class ProcessResolver
{
public:
    // 按包的 src_port/dst_port + transport 查表回填 proc_name/proc_pid；未命中时不改动包。
    void annotate(Packet& packet);

private:
    // 内部按节流间隔重新扫描整张 socket→进程表，避免每包都重新 lsof / 扫 /proc。
    void refreshIfStale();
    void refreshMacOS(); // #if defined(__APPLE__)
    void refreshLinux();  // #elif defined(__linux__)

    std::mutex                                                mutex_;
    std::chrono::steady_clock::time_point                     lastRefresh_{};
    // key = (isUdp ? 1<<16 : 0) | port；value = (进程名, pid)
    std::unordered_map<uint32_t, std::pair<std::string, int>> table_;
};

#endif
