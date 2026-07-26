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

PcapAnalyzer::PcapAnalyzer(const std::string& tsharkPath, const std::string& ip2RegionDbPath)
    : tsharkPath(tsharkPath), ip2RegionDbPath(ip2RegionDbPath)
{
}

bool PcapAnalyzer::streamPackets(
    const std::string&                                         filePath,
    const std::function<void(const std::shared_ptr<Packet>&)>& onPacket)
{
    // 命令 = {tshark, -r, 文件} + 共享字段列表
    std::vector<std::string> tsharkArgs = {tsharkPath, "-r", filePath};
    std::vector<std::string> fieldArgs  = TsharkCommand::tsharkFieldArgs();
    tsharkArgs.insert(tsharkArgs.end(), fieldArgs.begin(), fieldArgs.end());

    pid_t tsharkPid = -1;
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

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节。
    // 用 64 位累加，避免超过 4GB 的大 pcap 偏移溢出。
    uint64_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!PacketParser::parseLine(buffer, *packet))
        {
            // 解析失败会破坏后续报文的文件偏移累加，无法安全继续，直接终止本次分析。
            // 不用 assert：release 构建下 assert 会被去除，等于漏掉这条错误路径。
            LOG_F(ERROR, "解析 tshark 输出行失败，终止分析: %s", buffer);
            ProcessUtil::PcloseEx(pipe, tsharkPid);
            return false;
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
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

    // 打开随机读取器一次，供后续 getPacketHexData 复用；失败不影响解析结果本身，
    // 仅令取 hex 数据不可用（getPacketHexData 会因未打开而返回 false）。
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

    // 调用原有的analysisFile方法
    if (!analysisFile(filePath))
    {
        return false;
    }

    // 将allPackets中的数据复制到packets中
    packets.clear();
    packets.reserve(allPackets.size());
    for (const auto& pair : allPackets)
    {
        packets.push_back(pair.second);
    }

    return true;
}

void PcapAnalyzer::processPacket(const std::shared_ptr<Packet>& packet)
{
    // 将分析的数据包插入保存起来
    allPackets.insert(std::make_pair(packet->frame_number, packet));
}

void PcapAnalyzer::printAllPackets()
{
    LOG_F(INFO, "Number of packets: %zu", allPackets.size());
    for (const auto& pair : allPackets)
    {
        std::shared_ptr<Packet> packet = pair.second;
        // 构建JSON对象
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

        // 序列化为 JSON 字符串
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

    auto it = allPackets.find(frameNumber);
    if (it == allPackets.end())
    {
        LOG_F(ERROR, "未找到帧号 %u 对应的报文", frameNumber);
        return false;
    }

    const std::shared_ptr<Packet>& packet  = it->second;
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
// 把管道里的全部字节读进字符串（tshark 单包 PDML 输出通常不大，一次读完最省事）。
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

// 取属性值，取不到返回空串（rapidxml 的 first_attribute 可能为 nullptr）。
std::string attr(rapidxml::xml_node<>* node, const char* name)
{
    rapidxml::xml_attribute<>* a = node->first_attribute(name);
    return a ? std::string(a->value(), a->value_size()) : std::string();
}

// 把一个 PDML 的 <proto>/<field> 节点递归转成 DetailNode：
// label 优先用 showname（人类可读），回退到 name；value 优先 show，回退 value。
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

    pid_t tsharkPid = -1;
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
                                            std::vector<uint32_t>& frameNumbers)
{
    frameNumbers.clear();
    if (currentFilePath.empty())
    {
        LOG_F(ERROR, "尚未分析任何文件，无法执行显示过滤");
        return false;
    }
    if (displayFilter.empty())
    {
        return false; // 空过滤：交由调用方走“不过滤”路径
    }

    // 只取匹配帧号：-Y 过滤 + -T fields -e frame.number，逐行一个编号。
    std::vector<std::string> args = {tsharkPath,    "-r", currentFilePath,
                                     "-Y",          displayFilter,
                                     "-T",          "fields",
                                     "-e",          "frame.number"};

    pid_t tsharkPid = -1;
    FILE* pipe      = ProcessUtil::PopenEx(args, &tsharkPid, "r");
    if (!pipe)
    {
        LOG_F(ERROR, "运行 tshark 执行显示过滤失败: %s", displayFilter.c_str());
        return false;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        // 每行一个帧号，可能带前后空白；空行跳过，非法行忽略不中断。
        try
        {
            std::string line(buffer);
            size_t      begin = line.find_first_not_of(" \t\r\n");
            if (begin == std::string::npos)
                continue;
            frameNumbers.push_back(static_cast<uint32_t>(std::stoul(line.substr(begin))));
        }
        catch (const std::exception&)
        {
            continue;
        }
    }
    ProcessUtil::PcloseEx(pipe, tsharkPid);
    return true;
}
