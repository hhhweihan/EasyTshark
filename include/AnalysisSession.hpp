#ifndef AnalysisSession_hpp
#define AnalysisSession_hpp

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "FlowMonitor.hpp"
#include "LiveCapture.hpp"
#include "PcapAnalyzer.hpp"
#include "PdmlToJsonConverter.hpp"
#include "tsharkDataType.hpp"
#include "utils.hpp"

// 一次“分析会话”的门面（Facade）：把 PcapAnalyzer / SQLiteUtil /
// PdmlToJsonConverter / LiveCapture / FlowMonitor 聚合到一处，对外只暴露
// 面向意图的接口（载入、取包、取 hex、查询、抓包、流量趋势）。
//
// 目的：让调用方（CLI 的 main、以及后续的 ImGui 前端）与解析/抓包/入库的
// 具体实现解耦——UI 只依赖这层稳定接口，不直接触碰 tshark 细节。这里的
// “前后端分离”是同进程内的“核心库 ↔ UI 层”边界，不是网络 C/S。
//
// 线程约定：packetCount / packetsSnapshot / flowTrendSnapshot 取的是
// 数据的拷贝快照，加锁保护，可从 UI 线程安全调用；载入/抓包等写操作应在
// 同一线程（或调用方自行串行化）发起。
class AnalysisSession
{
public:
    // tsharkPath 缺省用平台默认；dataDir 为会话工作目录（存放 capture.pcap / packets.db 等）。
    explicit AnalysisSession(const std::string& tsharkPath, const std::string& dataDir = "data");
    ~AnalysisSession();

    AnalysisSession(const AnalysisSession&)            = delete;
    AnalysisSession& operator=(const AnalysisSession&) = delete;

    // 载入并分析一个 pcap 文件：srcPath 必须非空，会按时间戳复制一份到
    // dataDir/pcaps/ 下（历史不覆盖），随后解析入库。srcPath 为空直接返回失败。
    bool loadPcap(const std::string& srcPath);

    // ---- 报文访问（读快照，线程安全）----
    size_t                               packetCount() const;
    std::vector<std::shared_ptr<Packet>> packetsSnapshot() const;

    // 取指定帧号的原始字节（十六进制视图用）
    bool getHex(uint32_t frameNumber, std::vector<unsigned char>& out);

    // 取指定帧号的协议分层树（详情面板逐层展开用）
    bool getDetailTree(uint32_t frameNumber, DetailNode& root);

    // 用 tshark 显示过滤表达式（-Y）筛选当前报文集，回填匹配的报文子集。
    // 匹配帧号由 tshark 求得，报文取自既有快照（保留正确 file_offset，hex 可用）。
    bool queryDisplayFilter(const std::string&                    displayFilter,
                            std::vector<std::shared_ptr<Packet>>& out);

    // 把当前载入/抓包的 pcap 另存到 destPath（工具栏“保存”用）。
    bool savePcapAs(const std::string& destPath);

    // 条件查询（参数化，防注入），结果为 JSON 字符串
    bool query(const std::map<std::string, std::string>& conditions, std::string& jsonOut);

    // 将当前 pcap 导出为详细的 PDML JSON（协议逐层展开），中间产物 XML 写到 xmlPath。
    bool exportDetailJson(const std::string& xmlPath, const std::string& jsonPath);

    // ---- 实时抓包 ----
    std::vector<AdapterInfo> listAdapters() const;
    // 开始实时抓包。onPacket 非空时，每抓到一个包就在**抓包线程**回调一次（供 UI 实时追加，
    // 调用方需自行加锁）；为空则仅落盘、停止后再统一解析。
    bool startLiveCapture(const std::string&           adapterName,
                          LiveCapture::PacketCallback onPacket = nullptr);
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

private:
    // 解析 pcapFilePath 并入库到 dbFilePath：载入与停止抓包两条路径共用的收尾。
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
    std::unique_ptr<FlowMonitor> flow_;
    bool                         capturing_ = false;

    // 保护 packets_ 的快照读写
    mutable std::mutex                   mutex_;
    std::vector<std::shared_ptr<Packet>> packets_;
};

#endif
