#include "AnalysisSession.hpp"

#include <cerrno>
#include <cstdio>
#include <fstream>
#include <set>
#include <sys/stat.h>

#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"

namespace
{
// 以下文件操作全部走程序内逻辑，不再拼接命令交给 /bin/sh 执行，
// 从根本上消除路径中的 shell 元字符（; | $() 等）被解释的注入风险。

// 创建单层目录，已存在也视为成功
bool ensureDir(const std::string& dir)
{
    if (mkdir(dir.c_str(), 0755) == 0)
    {
        return true;
    }
    return errno == EEXIST;
}

// 二进制方式复制文件，成功返回 true
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
      converter_(tsharkPath)
{
    if (!ensureDir(dataDir_))
    {
        LOG_F(WARNING, "创建数据目录失败: %s", dataDir_.c_str());
    }
    // 抓包/载入的 pcap 与 db 按时间戳留存于此子目录，历史全部保留、不覆盖。
    if (!ensureDir(pcapsDir_))
    {
        LOG_F(WARNING, "创建 pcap 目录失败: %s", pcapsDir_.c_str());
    }
}

// unique_ptr 成员的析构需要完整类型：即便无额外逻辑也在 .cpp 里落定义。
AnalysisSession::~AnalysisSession() = default;

bool AnalysisSession::loadPcap(const std::string& srcPath)
{
    if (srcPath.empty())
    {
        LOG_F(ERROR, "载入 pcap 需要指定源文件路径");
        return false;
    }

    // 每次载入按时间戳留一份到 pcaps 目录，历史不覆盖；db 与之一一对应。
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
    if (!analyzer_.analysisFile(pcapFilePath, packets))
    {
        LOG_F(ERROR, "解析 pcap 文件失败: %s", pcapFilePath.c_str());
        return false;
    }

    // 入库：SQLiteUtil 构造失败会抛异常，这里就地捕获转为返回值，避免上抛到 UI 线程。
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

    // analyzeAndStore 会在 UI 的后台线程（std::async）里执行，而 pcapPath()/savePcapAs
    // 在 UI 线程读 currentPcapPath_，故路径成员与 packets_ 一并纳入 mutex_ 保护，消除竞态。
    {
        std::lock_guard<std::mutex> lock(mutex_);
        currentPcapPath_ = pcapFilePath;
        currentDbPath_   = dbFilePath;
        packets_         = std::move(packets);
    }
    return true;
}

size_t AnalysisSession::packetCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_.size();
}

std::string AnalysisSession::pcapPath() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentPcapPath_;
}

std::vector<std::shared_ptr<Packet>> AnalysisSession::packetsSnapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_; // 拷贝 shared_ptr 向量，调用方拿到独立快照
}

bool AnalysisSession::getHex(uint32_t frameNumber, std::vector<unsigned char>& out)
{
    return analyzer_.getPacketHexData(frameNumber, out);
}

bool AnalysisSession::getDetailTree(uint32_t frameNumber, DetailNode& root)
{
    return analyzer_.getPacketDetailTree(frameNumber, root);
}

bool AnalysisSession::queryDisplayFilter(const std::string&                    displayFilter,
                                         std::vector<std::shared_ptr<Packet>>& out)
{
    out.clear();
    std::vector<uint32_t> frames;
    if (!analyzer_.getFramesByDisplayFilter(displayFilter, frames))
    {
        return false;
    }
    // 匹配帧号放进集合，再从既有快照按帧号取对应报文——快照里的 file_offset
    // 是权威值，这样过滤结果依然能正确取 hex，无需 tshark 重算偏移。
    std::set<uint32_t> keep(frames.begin(), frames.end());
    std::lock_guard<std::mutex> lock(mutex_);
    for (const std::shared_ptr<Packet>& p : packets_)
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

std::vector<AdapterInfo> AnalysisSession::listAdapters() const
{
    return TsharkCommand::listNetworkAdapters(tsharkPath_);
}

bool AnalysisSession::startLiveCapture(const std::string&           adapterName,
                                       LiveCapture::PacketCallback onPacket)
{
    if (capturing_)
    {
        LOG_F(WARNING, "已在抓包中，忽略重复的开始请求");
        return false;
    }
    // 本次抓包按时间戳直接写入 pcaps 目录（不再落到 cwd，也不清空历史）。
    std::string ts   = CommonUtil::get_timestamp();
    liveCapturePath_ = pcapsDir_ + "/capture_" + ts + ".pcap";
    liveDbPath_      = pcapsDir_ + "/packets_" + ts + ".db";

    capture_.reset(new LiveCapture(tsharkPath_));
    if (!capture_->startCapture(adapterName, std::move(onPacket), liveCapturePath_))
    {
        capture_.reset();
        return false;
    }
    capturing_ = true;
    return true;
}

bool AnalysisSession::stopLiveCapture()
{
    if (!capturing_ || !capture_)
    {
        return false;
    }
    capture_->stopCapture();
    capture_.reset();
    capturing_ = false;

    // tshark 已把报文直接写到 liveCapturePath_（带时间戳），无需搬运，直接解析入库。
    return analyzeAndStore(liveCapturePath_, liveDbPath_);
}

bool AnalysisSession::isCapturing() const
{
    return capturing_;
}

void AnalysisSession::startFlowMonitor()
{
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
