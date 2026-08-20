#include "AnalysisSession.hpp"

#include <cerrno>
#include <cstdio>
#include <fstream>
#include <set>
#include <sys/stat.h>

#if defined(_WIN32)
#include <direct.h> // _mkdir
#endif

#include "NativeAnalyzer.hpp"
#include "NativeCapture.hpp"
#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"

namespace
{
// 文件操作全部走程序内逻辑，不拼接 shell 命令，避免路径中的 shell 元字符注入。

// 创建单层目录，已存在也视为成功
bool ensureDir(const std::string& dir)
{
#if defined(_WIN32)
    // Windows 的 _mkdir 无权限位参数，仅接受路径。
    if (_mkdir(dir.c_str()) == 0)
    {
        return true;
    }
#else
    if (mkdir(dir.c_str(), 0755) == 0)
    {
        return true;
    }
#endif
    return errno == EEXIST;
}

// 递归创建 filePath 的父目录（类似 mkdir -p），最后一段视为文件名不创建。
bool ensureParentDir(const std::string& filePath)
{
    size_t slash = filePath.find_last_of("/\\");
    if (slash == std::string::npos || slash == 0)
        return true; // 无目录部分，或形如 "/name"（根下）——无需创建
    // 依次创建路径上每个中间前缀（跳过盘符根 "C:" 与空段）
    for (size_t i = 1; i < slash; ++i)
    {
        if (filePath[i] != '/' && filePath[i] != '\\')
            continue;
        std::string sub = filePath.substr(0, i);
        if (sub.empty() || (sub.size() == 2 && sub[1] == ':'))
            continue;
        if (!ensureDir(sub))
            return false;
    }
    std::string parent = filePath.substr(0, slash);
    if (parent.size() == 2 && parent[1] == ':')
        return true; // 形如 "C:foo" 的盘符相对路径，父目录即盘符根，无需创建
    return ensureDir(parent);
}

bool copyFile(const std::string& src, const std::string& dst)
{
    std::ifstream in(src, std::ios::binary);
    if (!in)
    {
        return false;
    }
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        return false;
    }
    char buf[8192];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
    {
        out.write(buf, in.gcount());
        if (!out)
        {
            return false;
        }
    }
    return true;
}
} // namespace

AnalysisSession::AnalysisSession(const std::string& tsharkPath, const std::string& dataDir)
    : tsharkPath_(tsharkPath),
      dataDir_(dataDir),
      pcapsDir_(dataDir + "/pcaps"),
      analyzer_(tsharkPath),
      converter_(tsharkPath),
      // 初始为空快照（非 null）：调用方无需检查空指针即可安全解引用。
      packets_(std::make_shared<const std::vector<std::shared_ptr<Packet>>>()),
      // 后端选择：tshark 不可用时降级到自研引擎（libpcap + 内置解析），否则优先用 tshark。
      native_(!TsharkCommand::tsharkAvailable(tsharkPath))
{
    if (native_)
    {
        LOG_F(INFO, "未检测到 tshark：启用自研引擎（离线解析/实时抓包/详情树/过滤子集）");
        nativeAnalyzer_.reset(new NativeAnalyzer());
    }
    if (!ensureDir(dataDir_))
    {
        LOG_F(WARNING, "创建数据目录失败: %s", dataDir_.c_str());
    }
    // pcap 与 db 按时间戳留存于此子目录，历史不覆盖。
    if (!ensureDir(pcapsDir_))
    {
        LOG_F(WARNING, "创建 pcap 目录失败: %s", pcapsDir_.c_str());
    }
}

// unique_ptr 成员的析构需要完整类型：即便无额外逻辑也在 .cpp 里落定义。
AnalysisSession::~AnalysisSession() = default;

void AnalysisSession::setTsharkPath(const std::string& path)
{
    // 切换后端必须持 analyzerMutex_：否则后台任务正用 nativeAnalyzer_ 时 reset() 会 use-after-free。
    // 锁序 analyzerMutex_ → mutex_，此处只取前者。
    std::lock_guard<std::mutex> alock(analyzerMutex_);
    tsharkPath_ = path;
    analyzer_.setTsharkPath(path);
    converter_.setTsharkPath(path);
    // 重新评估后端：新路径有效则回到 tshark，否则继续自研引擎。
    bool nowNative = !TsharkCommand::tsharkAvailable(path);
    if (native_ != nowNative)
    {
        native_ = nowNative;
        if (native_)
        {
            if (!nativeAnalyzer_)
                nativeAnalyzer_.reset(new NativeAnalyzer());
        }
        else
        {
            nativeAnalyzer_.reset(); // 不再需要：切回 tshark 引擎
        }
        LOG_F(INFO, "后端切换为 %s", native_ ? "自研引擎" : "tshark");
    }
    // capture_/flow_ 每次操作按 tsharkPath_ 新建，无需在此同步已存在实例。
}

bool AnalysisSession::loadPcap(const std::string& srcPath)
{
    if (srcPath.empty())
    {
        LOG_F(ERROR, "载入 pcap 需要指定源文件路径");
        return false;
    }

    // 按时间戳留一份到 pcaps 目录，历史不覆盖；db 与之一一对应。
    std::string ts       = CommonUtil::get_timestamp();
    std::string destPcap = pcapsDir_ + "/capture_" + ts + ".pcap";
    std::string destDb   = pcapsDir_ + "/packets_" + ts + ".db";

    if (srcPath != destPcap)
    {
        if (!copyFile(srcPath, destPcap))
        {
            LOG_F(ERROR, "复制 pcap 文件失败: %s -> %s", srcPath.c_str(), destPcap.c_str());
            return false;
        }
    }
    return analyzeAndStore(destPcap, destDb);
}

// 载入与停止抓包共用：解析 pcap → 建表入库 → 更新当前 pcap/db 指向与报文快照。
bool AnalysisSession::analyzeAndStore(const std::string& pcapFilePath,
                                      const std::string& dbFilePath)
{
    std::vector<std::shared_ptr<Packet>> packets;
    {
        // 解析期间锁住 analyzer_，避免 getHex/getDetailTree/queryDisplayFilter 读到半更新状态。
        std::lock_guard<std::mutex> alock(analyzerMutex_);
        bool ok = native_ ? nativeAnalyzer_->analyzeFile(pcapFilePath, packets)
                          : analyzer_.analysisFile(pcapFilePath, packets);
        if (!ok)
        {
            LOG_F(ERROR, "解析 pcap 文件失败: %s", pcapFilePath.c_str());
            return false;
        }
    }

    // SQLiteUtil 构造失败会抛异常，就地捕获转为返回值，避免上抛到 UI 线程。
    try
    {
        db_.reset(new SQLiteUtil(dbFilePath));
    }
    catch (const std::exception& e)
    {
        LOG_F(ERROR, "打开数据库失败: %s", e.what());
        return false;
    }

    if (!db_->createPacketTable())
    {
        LOG_F(ERROR, "创建数据表失败");
        return false;
    }
    if (!db_->insertPacket(packets))
    {
        LOG_F(WARNING, "导入数据包到数据库失败");
    }

    // 本函数跑在后台线程，路径成员与 packets_ 纳入 mutex_ 保护，供 UI 线程安全读取。
    // 快照是 shared_ptr 原子交换：旧快照被持有者保活，调用方无需担心悬垂。
    {
        std::lock_guard<std::mutex> lock(mutex_);
        currentPcapPath_ = pcapFilePath;
        currentDbPath_   = dbFilePath;
        packets_         = std::make_shared<const std::vector<std::shared_ptr<Packet>>>(
            std::move(packets));
    }
    return true;
}

size_t AnalysisSession::packetCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_ ? packets_->size() : 0;
}

std::string AnalysisSession::pcapPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentPcapPath_;
}

std::shared_ptr<const std::vector<std::shared_ptr<Packet>>>
AnalysisSession::packetsSnapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_; // 只拷贝引用计数，向量本体零拷贝；持有期间旧快照被保活
}

bool AnalysisSession::getHex(uint32_t frameNumber, std::vector<unsigned char>& out)
{
    std::lock_guard<std::mutex> alock(analyzerMutex_);
    return native_ ? nativeAnalyzer_->getPacketHexData(frameNumber, out)
                   : analyzer_.getPacketHexData(frameNumber, out);
}

bool AnalysisSession::getDetailTree(uint32_t frameNumber, DetailNode& root)
{
    std::lock_guard<std::mutex> alock(analyzerMutex_);
    return native_ ? nativeAnalyzer_->getPacketDetailTree(frameNumber, root)
                   : analyzer_.getPacketDetailTree(frameNumber, root);
}

bool AnalysisSession::queryDisplayFilter(const std::string&                    displayFilter,
                                         std::vector<std::shared_ptr<Packet>>& out,
                                         std::string* errorOut)
{
    out.clear();
    std::vector<uint32_t> frames;
    {
        // 与 analyzeAndStore 的解析互斥：读 analyzer_ 状态须等本轮载入完成。
        std::lock_guard<std::mutex> alock(analyzerMutex_);
        bool ok = native_ ? nativeAnalyzer_->getFramesByDisplayFilter(displayFilter, frames,
                                                                      errorOut)
                          : analyzer_.getFramesByDisplayFilter(displayFilter, frames, errorOut);
        if (!ok)
        {
            return false;
        }
    }
    // 从既有快照按帧号取报文，沿用快照里权威的 file_offset，过滤结果仍能正确取 hex。
    std::set<uint32_t> keep(frames.begin(), frames.end());
    std::shared_ptr<const std::vector<std::shared_ptr<Packet>>> snap;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snap = packets_;
    }
    if (!snap)
    {
        return false;
    }
    for (const std::shared_ptr<Packet>& p : *snap)
    {
        if (keep.count(static_cast<uint32_t>(p->frame_number)) > 0)
        {
            out.push_back(p);
        }
    }
    return true;
}

bool AnalysisSession::savePcapAs(const std::string& destPath)
{
    // 先在锁内取一份当前 pcap 路径快照，避免与后台 analyzeAndStore 的写入竞态。
    std::string srcPath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        srcPath = currentPcapPath_;
    }
    if (srcPath.empty())
    {
        LOG_F(ERROR, "当前没有可保存的 pcap（请先载入或抓包）");
        return false;
    }
    if (destPath.empty())
    {
        LOG_F(ERROR, "保存 pcap 需要指定目标路径");
        return false;
    }
    if (destPath == srcPath)
    {
        return true; // 目标即源，视为成功
    }
    // 允许用户指定尚不存在的多层目录（如 data/exports/foo.pcap），先补齐父目录再拷贝。
    if (!ensureParentDir(destPath))
    {
        LOG_F(ERROR, "创建保存目录失败: %s", destPath.c_str());
        return false;
    }
    if (!copyFile(srcPath, destPath))
    {
        LOG_F(ERROR, "保存 pcap 失败: %s -> %s", srcPath.c_str(), destPath.c_str());
        return false;
    }
    return true;
}

bool AnalysisSession::query(const std::map<std::string, std::string>& conditions,
                            std::string&                              jsonOut)
{
    if (!db_)
    {
        LOG_F(ERROR, "数据库未就绪，无法查询（请先载入 pcap）");
        return false;
    }
    return db_->queryPackets(conditions, jsonOut);
}

bool AnalysisSession::exportDetailJson(const std::string& xmlPath, const std::string& jsonPath)
{
    std::string srcPath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        srcPath = currentPcapPath_;
    }
    if (!converter_.convertPcapToXml(srcPath, xmlPath))
    {
        LOG_F(ERROR, "PCAP 转 XML 失败: %s", srcPath.c_str());
        return false;
    }
    if (!converter_.convertXmlToJson(xmlPath, jsonPath))
    {
        LOG_F(ERROR, "XML 转 JSON 失败: %s", xmlPath.c_str());
        return false;
    }
    return true;
}

bool AnalysisSession::exportPacketsCsv(const std::string& csvPath)
{
    if (csvPath.empty())
    {
        LOG_F(ERROR, "导出 CSV 需要指定目标路径");
        return false;
    }
    std::shared_ptr<const std::vector<std::shared_ptr<Packet>>> snap;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snap = packets_;
    }
    if (!snap || snap->empty())
    {
        LOG_F(ERROR, "当前没有可导出的报文（请先载入或抓包）");
        return false;
    }

    std::ofstream out(csvPath.c_str(), std::ios::trunc);
    if (!out)
    {
        LOG_F(ERROR, "打开 CSV 文件失败: %s", csvPath.c_str());
        return false;
    }

    // CSV 字段转义（内容来自不可信报文）：1) 公式注入防护——= + - @ Tab CR 开头前置单引号 '；
    // 2) RFC 4180 转义——含逗号/引号/换行时用双引号包裹，内部 " 翻倍成 ""。
    auto csvField = [](const std::string& v)
    {
        std::string s = v;
        if (!s.empty())
        {
            char c0 = s[0];
            if (c0 == '=' || c0 == '+' || c0 == '-' || c0 == '@' || c0 == '\t' || c0 == '\r')
                s.insert(s.begin(), '\'');
        }
        bool needQuote = s.find(',') != std::string::npos || s.find('"') != std::string::npos ||
                         s.find('\n') != std::string::npos || s.find('\r') != std::string::npos;
        if (!needQuote)
            return s;
        std::string out2;
        out2.reserve(s.size() + 2);
        out2.push_back('"');
        for (char c : s)
        {
            if (c == '"')
                out2 += "\"\""; // 内部引号翻倍（勿写成 """"，会被当空字面量吞掉）
            else
                out2.push_back(c);
        }
        out2.push_back('"');
        return out2;
    };

    out << "frame_number,time,src_mac,src_ip,src_location,src_port,dst_mac,dst_ip,"
           "dst_location,dst_port,protocol,len,info\n";
    char timeBuf[64];
    for (const std::shared_ptr<Packet>& p : *snap)
    {
        // time 是 epoch 浮点秒，转成可读时间戳（毫秒精度）
        std::snprintf(timeBuf, sizeof(timeBuf), "%.3f", p->time);
        out << p->frame_number << ',' << timeBuf << ','
            << csvField(p->src_mac) << ',' << csvField(p->src_ip) << ',' << csvField(p->src_location)
            << ',' << p->src_port << ',' << csvField(p->dst_mac) << ',' << csvField(p->dst_ip)
            << ',' << csvField(p->dst_location) << ',' << p->dst_port << ','
            << csvField(p->protocol) << ',' << p->len << ',' << csvField(p->info) << '\n';
        if (!out)
        {
            LOG_F(ERROR, "写 CSV 失败（磁盘满？）: %s", csvPath.c_str());
            return false;
        }
    }
    return true;
}

std::vector<AdapterInfo> AnalysisSession::listAdapters() const
{
    return native_ ? NativeCapture::listAdapters()
                   : TsharkCommand::listNetworkAdapters(tsharkPath_);
}

bool AnalysisSession::startLiveCapture(const std::string&           adapterName,
                                       LiveCapture::PacketCallback onPacket,
                                       int durationSeconds)
{
    if (capturing_)
    {
        LOG_F(WARNING, "已在抓包中，忽略重复的开始请求");
        return false;
    }
    // 按时间戳直接写入 pcaps 目录，历史不覆盖。
    std::string ts   = CommonUtil::get_timestamp();
    liveCapturePath_ = pcapsDir_ + "/capture_" + ts + ".pcap";
    liveDbPath_      = pcapsDir_ + "/packets_" + ts + ".db";

    if (native_)
    {
        // 自研抓包：libpcap 直接抓，无需 tshark 路径。
        nativeCapture_.reset(new NativeCapture());
        if (!nativeCapture_->startCapture(adapterName, std::move(onPacket), liveCapturePath_,
                                          durationSeconds))
        {
            nativeCapture_.reset();
            return false;
        }
    }
    else
    {
        capture_.reset(new LiveCapture(tsharkPath_));
        if (!capture_->startCapture(adapterName, std::move(onPacket), liveCapturePath_,
                                    durationSeconds))
        {
            capture_.reset();
            return false;
        }
    }
    capturing_ = true;
    return true;
}

bool AnalysisSession::stopLiveCapture()
{
    if (!capturing_)
    {
        return false;
    }
    if (native_)
    {
        if (!nativeCapture_)
            return false;
        nativeCapture_->stopCapture();
        nativeCapture_.reset();
        capturing_ = false;
    }
    else
    {
        if (!capture_)
            return false;
        capture_->stopCapture();
        capture_.reset();
        capturing_ = false;
    }

    // 抓包已直接写到 liveCapturePath_，无需搬运，直接解析入库。
    return analyzeAndStore(liveCapturePath_, liveDbPath_);
}

bool AnalysisSession::isCapturing() const
{
    return capturing_;
}

void AnalysisSession::startFlowMonitor()
{
    if (native_)
    {
        LOG_F(WARNING, "自研引擎暂不支持网卡流量趋势监控（tshark 专属功能），已忽略");
        return;
    }
    if (!flow_)
    {
        flow_.reset(new FlowMonitor(tsharkPath_));
    }
    flow_->startMonitorAdaptersFlowTrend();
}

void AnalysisSession::stopFlowMonitor()
{
    if (flow_)
    {
        flow_->stopMonitorAdaptersFlowTrend();
    }
}

void AnalysisSession::flowTrendSnapshot(std::map<std::string, std::map<long, long>>& out)
{
    out.clear();
    if (flow_)
    {
        flow_->getAdaptersFlowTrendData(out);
    }
}
