#include "PcapAnalyzer.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidxml/rapidxml.hpp"

#include "loguru/loguru.hpp"
#include "PacketParser.hpp"
#include "processUtil.hpp"
#include "tsharkCommand.hpp"
#include "utils.hpp"

namespace
{
// ---- pcapng 支持 ----
// 嗅探格式：pcapng 的 SHB 首 4 字节为 0x0A0D0D0A；经典 pcap 为 a1b2c3d4 等。读前 4 字节区分。
bool sniffIsPcapNg(const std::string& filePath)
{
    FILE* f = std::fopen(filePath.c_str(), "rb");
    if (!f)
        return false;
    unsigned char magic[4] = {0};
    size_t        n         = std::fread(magic, 1, 4, f);
    std::fclose(f);
    if (n < 4)
        return false;
    // 小端读 uint32：0x0A0D0D0A
    return magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A;
}

// 读小端 uint32（pcapng 块内字段；tshark 输出为小端，大端文件罕见，暂不支持）
uint32_t readLe32(const unsigned char* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// 预扫描 pcapng，返回各包 packet-data 在文件中的偏移（按帧号 0 基索引）。
// 块布局：Block Type(4) + Total Length(4) + 载荷 + Total Length(4)，长度含首尾。
std::vector<uint64_t> scanPcapNgPacketOffsets(const std::string& filePath)
{
    std::vector<uint64_t> offsets;
    FILE* f = std::fopen(filePath.c_str(), "rb");
    if (!f)
        return offsets;

    unsigned char hdr[8];
    while (std::fread(hdr, 1, 8, f) == 8)
    {
        uint32_t type = readLe32(hdr);
        uint32_t total = readLe32(hdr + 4);
        if (total < 12)
            break; // 损坏：块长不合法

        if (type == 0x00000006) // EPB：接口ID(4)+tsHigh(4)+tsLow(4)+capLen(4)+origLen(4)，数据在块内偏移 28
        {
            uint64_t blockStart = 0;
            // 块起始 = 当前位置 - 8（已读 8 字节头）
            long long cur = std::ftell(f);
            uint64_t blockStart64 = static_cast<uint64_t>(cur) - 8;
            offsets.push_back(blockStart64 + 28);
        }
        else if (type == 0x00000003) // SPB：origLen(4) 后即数据，数据在块内偏移 12
        {
            long long cur = std::ftell(f);
            uint64_t blockStart64 = static_cast<uint64_t>(cur) - 8;
            offsets.push_back(blockStart64 + 12);
        }
        // 其他块（IDB/NRB/自定义）跳过

        if (std::fseek(f, static_cast<long>(total) - 8, SEEK_CUR) != 0)
            break; // 前进到下一块（已读 8 字节头）
    }
    std::fclose(f);
    return offsets;
}

} // namespace

PcapAnalyzer::PcapAnalyzer(const std::string& tsharkPath, const std::string& ip2RegionDbPath)
    : tsharkPath(tsharkPath), ip2RegionDbPath(ip2RegionDbPath)
{
}

bool PcapAnalyzer::streamPackets(
    const std::string&                                         filePath,
    const std::function<void(const std::shared_ptr<Packet>&)>& onPacket)
{
    std::vector<std::string> tsharkArgs = {tsharkPath, "-r", filePath};
    std::vector<std::string> fieldArgs  = TsharkCommand::tsharkFieldArgs();
    tsharkArgs.insert(tsharkArgs.end(), fieldArgs.begin(), fieldArgs.end());

    ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
    FILE* pipe = ProcessUtil::PopenEx(tsharkArgs, &tsharkPid, "r");
    if (!pipe)
    {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    // IP地理位置数据库只需初始化一次，避免每个报文重复加载整个xdb文件
    bool ip2RegionReady = IP2RegionUtil::init(ip2RegionDbPath);
    if (!ip2RegionReady)
    {
        LOG_F(WARNING, "无法初始化IP2Region数据库，IP地理位置信息将不可用");
    }

    char buffer[4096];

    // pcapng 预扫描：tshark 输出帧序与文件内 EPB/SPB 顺序一致，按帧号索引到
    // packet-data 偏移（取 hex 用）。经典 pcap 则按 24 字节头 + 记录头累加。
    std::vector<uint64_t> ngOffsets;
    bool                  isPcapNg = sniffIsPcapNg(filePath);
    if (isPcapNg)
        ngOffsets = scanPcapNgPacketOffsets(filePath);

    // 当前报文在文件中的偏移，首包偏移即全局文件头 sizeof(PcapHeader) 字节；64 位累加避免大 pcap 溢出。
    uint64_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!PacketParser::parseLine(buffer, *packet))
        {
            // 解析失败会破坏后续偏移累加，无法安全继续，直接终止（不用 assert：release 会被去除）。
            LOG_F(ERROR, "解析 tshark 输出行失败，终止分析: %s", buffer);
            ProcessUtil::PcloseEx(pipe, tsharkPid);
            return false;
        }

        if (isPcapNg)
        {
            // 按帧号取预扫描偏移；越界时置 0，getPacketHexData 的越界检查会返回 false。
            size_t idx = static_cast<size_t>(packet->frame_number) - 1;
            packet->file_offset = (idx < ngOffsets.size()) ? ngOffsets[idx] : 0;
        }
        else
        {
            packet->file_offset = file_offset + sizeof(PacketHeader);
            file_offset         = file_offset + sizeof(PacketHeader) + packet->cap_len;
        }

        if (ip2RegionReady)
        {
            packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
            packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);
        }

        onPacket(packet);
    }
    ProcessUtil::PcloseEx(pipe, tsharkPid);
    return true;
}

bool PcapAnalyzer::analysisFile(const std::string& filePath)
{
    allPackets.clear();

    // 累积模式：每个包就地存入 allPackets，供 printAllPackets / getPacketHexData 复用。
    if (!streamPackets(filePath,
                       [this](const std::shared_ptr<Packet>& packet) { processPacket(packet); }))
    {
        return false;
    }

    currentFilePath = filePath;

    // 打开随机读取器一次供 getPacketHexData 复用；失败仅令取 hex 不可用，不影响解析结果。
    if (!fileReader.open(filePath))
    {
        LOG_F(WARNING, "无法打开报文文件用于十六进制读取: %s", filePath.c_str());
    }

    return true;
}

bool PcapAnalyzer::analysisFile(const std::string&                        filePath,
                                const std::function<void(const Packet&)>& onPacket)
{
    // 流式模式：逐包回调后即丢弃，不累积，常驻内存不随包数增长。
    return streamPackets(filePath, [&onPacket](const std::shared_ptr<Packet>& packet)
                         { onPacket(*packet); });
}

bool PcapAnalyzer::analysisFile(const std::string& filePath,
                                std::vector<std::shared_ptr<Packet>>& packets)
{
    allPackets.clear();

    if (!analysisFile(filePath))
    {
        return false;
    }

    packets.clear();
    packets.reserve(allPackets.size());
    for (const auto& packet : allPackets)
    {
        if (packet) // 跳过可能存在的空洞槽
        {
            packets.push_back(packet);
        }
    }

    return true;
}

void PcapAnalyzer::processPacket(const std::shared_ptr<Packet>& packet)
{
    // frame_number 从 1 起、稠密递增，用 (帧号-1) 作下标落入连续内存，省去 map 的哈希开销。
    if (packet->frame_number <= 0)
    {
        return; // 帧号异常（理论上不会出现），无法映射到下标，跳过
    }
    size_t idx = static_cast<size_t>(packet->frame_number) - 1;
    if (idx >= allPackets.size())
    {
        // 顺序到达等价 push_back，摊还 O(1)；偶发乱序留空槽也保证按帧号随机访问不越界。
        allPackets.resize(idx + 1);
    }
    allPackets[idx] = packet;
}

void PcapAnalyzer::printAllPackets()
{
    LOG_F(INFO, "Number of packets: %zu", allPackets.size());
    for (const auto& packet : allPackets)
    {
        if (!packet) // 跳过可能存在的空洞槽
        {
            continue;
        }
        rapidjson::Document                 pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", packet->time, allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator),
                         allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator),
                         allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator),
                         allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator),
                         allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        // 必须用 "%s" 承载：JSON 内容含 % 会被 loguru 当作格式串解析，直接传入是格式串注入。
        LOG_F(INFO, "%s", buffer.GetString());

        std::vector<unsigned char> buffer2(packet->cap_len);
        getPacketHexData(packet->frame_number, buffer2);
        std::stringstream hex_str;
        hex_str << "Packet Hex: ";
        for (unsigned char byte : buffer2)
            hex_str << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte)
                    << " ";
        LOG_F(INFO, "%s\n", hex_str.str().c_str());
    }
    LOG_F(INFO, "Number of packets: %zu", allPackets.size());
}

bool PcapAnalyzer::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& buffer)
{
    if (!fileReader.isOpen())
    {
        // 文件未成功打开（分析未跑或打开失败），无法读取原始字节
        LOG_F(ERROR, "报文文件未打开，无法读取十六进制数据: %s", currentFilePath.c_str());
        return false;
    }

    // 帧号从 1 起、按 (帧号-1) 定位到连续内存；越界或空洞槽都视为未找到
    if (frameNumber == 0 || frameNumber > allPackets.size() ||
        !allPackets[frameNumber - 1])
    {
        LOG_F(ERROR, "未找到帧号 %u 对应的报文", frameNumber);
        return false;
    }

    const std::shared_ptr<Packet>& packet  = allPackets[frameNumber - 1];
    uint32_t                       cap_len = packet->cap_len;
    // 一次打开、按偏移随机读：POSIX 下从 mmap 映射区直接切片，无重复 open/read
    if (!fileReader.readAt(packet->file_offset, cap_len, buffer))
    {
        LOG_F(ERROR, "读取帧号 %u 的报文数据失败（偏移 %llu，长度 %u）", frameNumber,
              static_cast<unsigned long long>(packet->file_offset), cap_len);
        return false;
    }
    return true;
}

namespace
{
// tshark 单包 PDML 输出通常不大，一次读完最省事。
std::string readPipeToString(FILE* pipe)
{
    std::string out;
    char        buf[8192];
    size_t      n;
    while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
    {
        out.append(buf, n);
    }
    return out;
}

// rapidxml 的 first_attribute 可能为 nullptr，需判空后再取值。
std::string attr(rapidxml::xml_node<>* node, const char* name)
{
    rapidxml::xml_attribute<>* a = node->first_attribute(name);
    return a ? std::string(a->value(), a->value_size()) : std::string();
}

// PDML 字段命名约定：label 用 showname 回退 name，value 用 show 回退 value。
DetailNode pdmlNodeToDetail(rapidxml::xml_node<>* node)
{
    DetailNode d;
    std::string showname = attr(node, "showname");
    d.label              = showname.empty() ? attr(node, "name") : showname;
    std::string show     = attr(node, "show");
    d.value              = show.empty() ? attr(node, "value") : show;

    for (rapidxml::xml_node<>* child = node->first_node("field"); child;
         child                       = child->next_sibling("field"))
    {
        d.children.push_back(pdmlNodeToDetail(child));
    }
    return d;
}
} // namespace

bool PcapAnalyzer::getPacketDetailTree(uint32_t frameNumber, DetailNode& root)
{
    if (currentFilePath.empty())
    {
        LOG_F(ERROR, "尚未分析任何文件，无法获取协议详情");
        return false;
    }

    // 只解析目标单包：-Y frame.number==N 精确定位，-T pdml 输出完整协议树。
    std::string              filter = "frame.number==" + std::to_string(frameNumber);
    std::vector<std::string> args   = {tsharkPath, "-r", currentFilePath, "-Y",
                                       filter,     "-T", "pdml"};

    ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
    FILE* pipe      = ProcessUtil::PopenEx(args, &tsharkPid, "r");
    if (!pipe)
    {
        LOG_F(ERROR, "运行 tshark 获取协议详情失败（帧 %u）", frameNumber);
        return false;
    }
    std::string xml = readPipeToString(pipe);
    ProcessUtil::PcloseEx(pipe, tsharkPid);

    if (xml.empty())
    {
        LOG_F(WARNING, "帧 %u 的 PDML 输出为空", frameNumber);
        return false;
    }

    try
    {
        // rapidxml 就地解析，需可写且持续存活的缓冲：复制一份并补 '\0' 结尾。
        std::vector<char> buffer(xml.begin(), xml.end());
        buffer.push_back('\0');

        rapidxml::xml_document<> doc;
        doc.parse<0>(buffer.data());

        rapidxml::xml_node<>* pdml = doc.first_node("pdml");
        if (!pdml)
            return false;
        rapidxml::xml_node<>* packet = pdml->first_node("packet");
        if (!packet)
            return false;

        root = DetailNode();
        root.label = "Frame " + std::to_string(frameNumber);
        for (rapidxml::xml_node<>* proto = packet->first_node("proto"); proto;
             proto                       = proto->next_sibling("proto"))
        {
            root.children.push_back(pdmlNodeToDetail(proto));
        }
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_F(ERROR, "解析 PDML 失败（帧 %u）: %s", frameNumber, e.what());
        return false;
    }
}

bool PcapAnalyzer::getFramesByDisplayFilter(const std::string&     displayFilter,
                                            std::vector<uint32_t>& frameNumbers,
                                            std::string* errorOut)
{
    frameNumbers.clear();
    if (errorOut)
        errorOut->clear();
    if (currentFilePath.empty())
    {
        LOG_F(ERROR, "尚未分析任何文件，无法执行显示过滤");
        if (errorOut)
            *errorOut = "尚未分析任何文件";
        return false;
    }
    if (displayFilter.empty())
    {
        if (errorOut)
            *errorOut = "过滤表达式为空";
        return false; // 空过滤：交由调用方走“不过滤”路径
    }

    // 只取匹配帧号：-Y 过滤 + -T fields -e frame.number；mergeStderr 把 tshark 错误合并进管道以透传。
    std::vector<std::string> args = {tsharkPath,    "-r", currentFilePath,
                                     "-Y",          displayFilter,
                                     "-T",          "fields",
                                     "-e",          "frame.number"};

    ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
    FILE* pipe = ProcessUtil::PopenEx(args, &tsharkPid, "r", /*mergeStderr=*/true);
    if (!pipe)
    {
        LOG_F(ERROR, "运行 tshark 执行显示过滤失败: %s", displayFilter.c_str());
        if (errorOut)
            *errorOut = "无法启动 tshark 执行过滤";
        return false;
    }

    char   buffer[256];
    bool   sawError = false; // stderr 合并后，错误行以 "tshark:" 等前缀出现
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::string line(buffer);
        size_t      begin = line.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos)
            continue;
        // 合法帧号是纯数字；非数字开头的行视为 tshark 错误/警告，记首行原文供 UI 展示。
        if (line[begin] < '0' || line[begin] > '9')
        {
            if (errorOut && errorOut->empty())
            {
                size_t e = line.find_last_not_of("\r\n");
                *errorOut = line.substr(begin, e - begin + 1);
            }
            sawError = true;
            continue;
        }
        try
        {
            frameNumbers.push_back(static_cast<uint32_t>(std::stoul(line.substr(begin))));
        }
        catch (const std::exception&)
        {
            continue;
        }
    }
    ProcessUtil::PcloseEx(pipe, tsharkPid);

    // 没有任何帧号且捕获到错误行：视为过滤失败（表达式非法等），返回 false 并带错误。
    if (sawError && frameNumbers.empty())
    {
        if (errorOut && errorOut->empty())
            *errorOut = "过滤表达式无效（tshark 拒绝执行）";
        LOG_F(WARNING, "显示过滤失败（tshark 报错）: %s", displayFilter.c_str());
        return false;
    }
    return true;
}
