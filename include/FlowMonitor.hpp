#ifndef FlowMonitor_hpp
#define FlowMonitor_hpp

#include <atomic>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "platform/EventPoller.hpp"

// 单块网卡的流量监控状态
class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo()
    {
        monitorTsharkPipe = nullptr;
        tsharkPid         = 0;
    }
    std::string                  adapterName;       // 网卡名称
    std::map<long, long>         flowTrendData;     // 流量趋势数据
    std::shared_ptr<std::thread> monitorThread;     // 负责监控该网卡输出的线程
    FILE*                        monitorTsharkPipe; // 线程与tshark通信的管道
    pid_t                        tsharkPid;         // 负责捕获该网卡数据的tshark进程PID
    // 单次 read 可能只读到半行、也可能一次读到多行；用它跨 read 暂存未完成的行尾，
    // 凑齐一个 '\n' 再解析，避免丢弃同一 read 里的后续行（旧实现只解析第一行）。
    std::string readLeftover;
};

// 网卡流量监控：为每块网卡启动一个 tshark 进程统计流量，用 EventPoller
// 汇聚各管道的可读事件，维护最近 300 秒的流量趋势。
class FlowMonitor
{
public:
    explicit FlowMonitor(const std::string& tsharkPath);

    // 析构兜底：确保监控线程被 join，避免线程悬挂访问已销毁的成员
    ~FlowMonitor();

    std::string getTsharkPath() const { return tsharkPath; }
    void        setTsharkPath(const std::string& path) { tsharkPath = path; }

    // 监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

private:
    // 监控所有网卡流量趋势的工作线程
    void adapterFlowTrendMonitorThreadEntry();

private:
    std::string tsharkPath;
    EventPoller flowTrendPoller; // 网卡流量监控的事件轮询器（替代原 epoll）

    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // fd → 对应网卡监控状态的直接索引：轮询返回就绪 fd 后 O(1) 反查，
    // 取代对 adapterFlowTrendMonitorMap 的线性扫描（fileno==pipeFd）。
    // 值为指向 map 内元素的裸指针——std::map 是 node-based，元素地址在
    // 插入/删除其它键时保持稳定，故指针不会失效。
    std::unordered_map<int, AdapterMonitorInfo*> fdToAdapter;

    std::recursive_mutex adapterFlowTrendMapLock;
    long                 adapterFlowTrendMonitorStartTime;

    // 监控工作线程与其停止标志：改 detach 为 joinable，stop 时先置位再 join，
    // 保证撕毁监控 map 前线程已退出，消除线程读裸指针的竞态。
    std::thread       flowTrendThread;
    std::atomic<bool> stopFlag;
};

#endif
