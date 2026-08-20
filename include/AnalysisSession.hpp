#ifndef AnalysisSession_hpp
#define AnalysisSession_hpp

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "FlowMonitor.hpp"
#include "LiveCapture.hpp"
#include "NativeAnalyzer.hpp"
#include "NativeCapture.hpp"
#include "PcapAnalyzer.hpp"
#include "PdmlToJsonConverter.hpp"
#include "ProcessResolver.hpp"
#include "tsharkDataType.hpp"
#include "utils.hpp"

// “分析会话”门面（Facade）：聚合 PcapAnalyzer / SQLiteUtil / PdmlToJsonConverter /
// LiveCapture / FlowMonitor，对外只暴露面向意图的接口，让 UI 与解析/抓包/入库实现解耦。
//
// 线程约定：packetCount / packetsSnapshot / flowTrendSnapshot 可从任意线程安全调用；
// 载入/抓包等写操作须由调用方串行化。内部 analyzerMutex_ 令 getHex/getDetailTree/
// queryDisplayFilter 与后台 analyzeAndStore 的 analyzer_ 访问互斥；capturing_ 为原子。
class AnalysisSession
{
public:
    // tsharkPath 缺省用平台默认；dataDir 为会话工作目录（存放 capture.pcap / packets.db 等）。
    explicit AnalysisSession(const std::string& tsharkPath, const std::string& dataDir = "data");
    ~AnalysisSession();

    AnalysisSession(const AnalysisSession&)            = delete;
    AnalysisSession& operator=(const AnalysisSession&) = delete;

    // 载入并分析 pcap：按时间戳复制一份到 dataDir/pcaps/（历史不覆盖）再解析入库。
    bool loadPcap(const std::string& srcPath);

    // ---- 报文访问（读快照，线程安全）----
    size_t packetCount() const;
    // 返回共享快照（shared_ptr，无拷贝，内部原子交换，持有期间安全）。
    std::shared_ptr<const std::vector<std::shared_ptr<Packet>>> packetsSnapshot() const;

    // 取指定帧号的原始字节（十六进制视图用）
    bool getHex(uint32_t frameNumber, std::vector<unsigned char>& out);

    // 取指定帧号的协议分层树（详情面板逐层展开用）
    bool getDetailTree(uint32_t frameNumber, DetailNode& root);

    // 用 tshark 显示过滤表达式（-Y）筛选当前报文集，回填匹配子集（沿用快照 file_offset）。
    bool queryDisplayFilter(const std::string&                    displayFilter,
                            std::vector<std::shared_ptr<Packet>>& out,
                            std::string* errorOut = nullptr);

    // 把当前载入/抓包的 pcap 另存到 destPath（工具栏“保存”用）。
    bool savePcapAs(const std::string& destPath);

    // 条件查询（参数化，防注入），结果为 JSON 字符串
    bool query(const std::map<std::string, std::string>& conditions, std::string& jsonOut);

    // 将当前 pcap 导出为详细的 PDML JSON（协议逐层展开），中间产物 XML 写到 xmlPath。
    bool exportDetailJson(const std::string& xmlPath, const std::string& jsonPath);

    // 把当前报文快照导出为 CSV（纯内存序列化，不依赖 tshark）。
    bool exportPacketsCsv(const std::string& csvPath);

    // ---- 实时抓包 ----
    std::vector<AdapterInfo> listAdapters() const;
    // 开始实时抓包。onPacket 非空时每抓到一个包就在抓包线程回调一次（调用方需自行加锁）；
    // 为空则仅落盘、停止后再统一解析。
    bool startLiveCapture(const std::string&           adapterName,
                          LiveCapture::PacketCallback onPacket = nullptr,
                          int durationSeconds = 0);
    // 停止抓包，并把抓到的 capture.pcap 载入分析入库
    bool stopLiveCapture();
    bool isCapturing() const;

    // ---- 网卡流量趋势 ----
    void startFlowMonitor();
    void stopFlowMonitor();
    void flowTrendSnapshot(std::map<std::string, std::map<long, long>>& out);

    const std::string& dataDir() const { return dataDir_; }
    // currentPcapPath_ 可能被后台分析线程改写，返回锁内拷贝而非引用，避免竞态与悬垂。
    std::string        pcapPath() const;
    const std::string& tsharkPath() const { return tsharkPath_; }

    // 当前后端引擎名：tshark（完整能力）或 native（内置引擎，无 tshark 时）。
    std::string engineName() const { return native_ ? "native" : "tshark"; }

    // 运行时切换 tshark 路径：更新自身并同步给 analyzer_/converter_，按需重估后端。
    void setTsharkPath(const std::string& path);

private:
    // 解析 pcapFilePath 入库到 dbFilePath：载入与停止抓包两条路径共用的收尾。
    bool analyzeAndStore(const std::string& pcapFilePath, const std::string& dbFilePath);

    std::string tsharkPath_;
    std::string dataDir_;
    std::string pcapsDir_;        // dataDir_/pcaps，按时间戳留存每次抓包/载入的 pcap 与 db
    std::string currentPcapPath_; // 最近一次载入/抓包对应的 pcap（供 hex / 导出复用）
    std::string currentDbPath_;   // 最近一次对应的 sqlite db
    std::string liveCapturePath_; // 本次实时抓包 tshark 直接写入的目标 pcap
    std::string liveDbPath_;      // 本次实时抓包停止后解析入库的 db

    PcapAnalyzer                 analyzer_;
    PdmlToJsonConverter          converter_;
    std::unique_ptr<SQLiteUtil>  db_;
    std::unique_ptr<LiveCapture> capture_;
    std::unique_ptr<NativeCapture> nativeCapture_; // 自研抓包（tshark 不可用时）
    std::unique_ptr<FlowMonitor> flow_;
    std::atomic<bool>            capturing_{false}; // 跨线程读写（UI 轮询 / 后台停止）安全

    // 后端选择：true = 自研引擎（无 tshark），false = tshark。
    // nativeAnalyzer_ 仅在 native_ 时使用；与 analyzer_ 同受 analyzerMutex_ 保护。
    bool                           native_ = false;
    std::unique_ptr<NativeAnalyzer> nativeAnalyzer_;

    // 实时抓包时反查每个包的归属进程；仅 macOS/Linux 生效，其他平台/离线回放恒为 no-op。
    std::unique_ptr<ProcessResolver> processResolver_;

    // 保护 packets_ 快照（原子交换的 shared_ptr，读写双方均持锁拷贝引用计数）
    mutable std::mutex                                                       mutex_;
    std::shared_ptr<const std::vector<std::shared_ptr<Packet>>>              packets_;
    // 保护 analyzer_ 内部状态：后台写入与 UI 线程读取互斥。锁序 analyzerMutex_ → mutex_，不得反序。
    mutable std::mutex analyzerMutex_;
};

#endif
