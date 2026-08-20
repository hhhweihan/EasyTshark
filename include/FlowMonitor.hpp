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
#include "processUtil.hpp" // ProcessUtil::ProcHandle（跨平台进程句柄）

// 单块网卡的流量监控状态
class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo()
    {
        monitorTsharkPipe = nullptr;
        tsharkPid         = ProcessUtil::kInvalidProc;
    }
    std::string                  adapterName;
    std::map<long, long>         flowTrendData;
    std::shared_ptr<std::thread> monitorThread;
    FILE*                        monitorTsharkPipe;
    ProcessUtil::ProcHandle      tsharkPid;
    // 跨 read 暂存未完成的行尾，凑齐 '\n' 再解析，避免丢弃同一 read 里的后续行。
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

    void startMonitorAdaptersFlowTrend();

    void stopMonitorAdaptersFlowTrend();

    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

private:
    void adapterFlowTrendMonitorThreadEntry();

private:
    std::string tsharkPath;
    EventPoller flowTrendPoller;

    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // fd → 网卡监控状态的 O(1) 反查索引，取代对 map 的线性扫描。
    // 值为指向 map 内元素的裸指针——std::map node-based，元素地址插删其它键时稳定，指针不失效。
    std::unordered_map<int, AdapterMonitorInfo*> fdToAdapter;

    std::recursive_mutex adapterFlowTrendMapLock;
    long                 adapterFlowTrendMonitorStartTime;

    // 监控工作线程与停止标志：stop 时先置标志再 join，确保销毁 map 前线程已退出，消除读裸指针竞态。
    std::thread       flowTrendThread;
    std::atomic<bool> stopFlag;
};

#endif
