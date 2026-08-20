#include "NativeAnalyzer.hpp"

#include <cstdio>
#include <cstring>
#include <functional>

#include "NativePacketParser.hpp"
#include "loguru/loguru.hpp"

namespace
{
uint32_t rdLe32(const unsigned char* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint16_t rdLe16(const unsigned char* p)
{
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
uint32_t rdBe32(const unsigned char* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// 经典 pcap 小端 magic
bool isPcapLe(const unsigned char* p)
{
    return p[0] == 0xd4 && p[1] == 0xc3 && p[2] == 0xb2 && p[3] == 0xa1;
}
// pcap 大端 magic
bool isPcapBe(const unsigned char* p)
{
    return p[0] == 0xa1 && p[1] == 0xb2 && p[2] == 0xc3 && p[3] == 0xd4;
}
// 纳秒精度经典 pcap magic（0xa1b23c4d）：布局同微秒版，仅时间戳小数字段单位为纳秒。
bool isPcapLeNano(const unsigned char* p)
{
    return p[0] == 0x4d && p[1] == 0x3c && p[2] == 0xb2 && p[3] == 0xa1;
}
bool isPcapBeNano(const unsigned char* p)
{
    return p[0] == 0xa1 && p[1] == 0xb2 && p[2] == 0x3c && p[3] == 0x4d;
}
// pcapng：SHB 块类型（小端 0x0A0D0D0A）
bool isPcapNg(const unsigned char* p)
{
    return p[0] == 0x0a && p[1] == 0x0d && p[2] == 0x0d && p[3] == 0x0a;
}

// 只保留能正确解析的链路类型；未知类型按 Ethernet 兜底。
// 0=NULL/Loopback，1=Ethernet，113=Linux SLL，276=Linux SLL2。
uint32_t normalizeLinkType(uint32_t lt)
{
    if (lt == 0 || lt == 1 || lt == 113 || lt == 276)
        return lt;
    return 1;
}

// pcapng if_tsresol（选项码 9，1 字节）→「每秒 tick 数」除数。
// 高位(0x80)置位：分辨率 = 2^-(v&0x7f) 秒 → 除数 = 2^(v&0x7f)；
// 否则：分辨率 = 10^-v 秒 → 除数 = 10^v。缺省 v=6（微秒）→ 除数 1e6。
double tsResolDivisor(uint8_t v)
{
    if (v & 0x80)
    {
        double d = 1.0;
        for (uint8_t i = 0; i < (v & 0x7f); ++i)
            d *= 2.0;
        return d;
    }
    double d = 1.0;
    for (uint8_t i = 0; i < v; ++i)
        d *= 10.0;
    return d;
}

// 解析 pcapng IDB 块：取 LinkType 与 if_tsresol。blk 指向块首（含 8 字节块头）。
// IDB 体：LinkType(2) Reserved(2) SnapLen(4)，随后是 TLV 选项（if_tsresol 码=9）。
void parseIdb(const unsigned char* blk, uint32_t total, uint32_t& linkType, double& tsDivisor)
{
    linkType  = 1;
    tsDivisor = 1e6; // 默认微秒
    if (total < 20)
        return;
    linkType = rdLe16(blk + 8);
    // 选项从块内偏移 16 开始，扫到块尾长度字段（total-4）之前
    uint32_t off = 16;
    uint32_t end = total - 4;
    while (off + 4 <= end)
    {
        uint16_t code = rdLe16(blk + off);
        uint16_t olen = rdLe16(blk + off + 2);
        if (code == 0) // opt_endofopt
            break;
        if (code == 9 && olen >= 1 && off + 4 + olen <= total) // if_tsresol
        {
            tsDivisor = tsResolDivisor(blk[off + 4]);
        }
        // 选项值按 4 字节对齐
        off += 4 + ((olen + 3u) & ~3u);
    }
}

// 经典 pcap 记录遍历（24 字节全局头 + 16 字节记录头 + 数据）。LE/BE/微秒/纳秒四种组合仅字节序与
// 时间戳单位不同，故用读取函子 rd32（rdLe32/rdBe32）与除数 tsDiv（1e6/1e9）参数化，共用一份循环。
void parseClassicPcap(PcapFileReader& reader, uint64_t fileSize,
                      uint32_t (*rd32)(const unsigned char*), double tsDiv, int linkType,
                      std::vector<std::shared_ptr<Packet>>& packets)
{
    uint64_t pos   = 24;
    int      frame = 1;
    for (;;)
    {
        if (pos + 16 > fileSize)
            break; // 文件尾
        const unsigned char* rh = reader.viewAt(pos, 16);
        if (!rh)
            break;
        uint32_t tsSec   = rd32(rh);
        uint32_t tsFrac  = rd32(rh + 4);
        uint32_t caplen  = rd32(rh + 8);
        uint32_t origlen = rd32(rh + 12);
        uint64_t dataOff = pos + 16;
        // 零拷贝借出帧字节，直接在映射区上解析（rh 的标量已全部取出，安全被覆盖）
        const unsigned char* data = reader.viewAt(dataOff, caplen);
        if (!data)
        {
            LOG_F(ERROR, "NativeAnalyzer: 记录 %d 数据越界", frame);
            break;
        }
        Packet p;
        p.frame_number = frame;
        p.time         = static_cast<double>(tsSec) + static_cast<double>(tsFrac) / tsDiv;
        p.cap_len      = caplen;
        p.len          = origlen ? origlen : caplen;
        p.file_offset  = dataOff;
        NativePacketParser::parseFrame(data, caplen, p, linkType);

        packets.push_back(std::make_shared<Packet>(std::move(p)));
        pos += 16 + static_cast<uint64_t>(caplen);
        ++frame;
    }
}
} // namespace

bool NativeAnalyzer::analyzeFile(const std::string& filePath,
                                 std::vector<std::shared_ptr<Packet>>& out)
{
    packets_.clear();
    analyzed_  = false;
    linkType_  = 1;

    if (!reader_.open(filePath))
    {
        LOG_F(ERROR, "NativeAnalyzer: 打开文件失败 %s", filePath.c_str());
        return false;
    }
    currentPath_ = filePath;

    const uint64_t fileSize = reader_.size();
    // 预留容量：按平均帧 ~64 字节保守估计包数，减少 push_back 扩容（估偏只影响扩容次数）。
    packets_.reserve(static_cast<size_t>(fileSize / 64) + 16);

    // 读文件头判断格式（一次性，非热点，但同样走零拷贝 viewAt）
    const unsigned char* head = reader_.viewAt(0, 4);
    if (!head)
    {
        LOG_F(ERROR, "NativeAnalyzer: 文件过小 %s", filePath.c_str());
        return false;
    }

    if (isPcapLe(head) || isPcapLeNano(head))
    {
        // 经典小端 pcap：24 字节全局头 + 16 字节记录头。微秒版除数 1e6，纳秒版 1e9。
        const unsigned char* gh = reader_.viewAt(0, 24);
        if (!gh)
            return false;
        // 链路类型：全局头偏移 20 的 network 字段
        uint32_t linkType = normalizeLinkType(rdLe32(gh + 20));
        linkType_         = static_cast<int>(linkType);
        double tsDiv      = isPcapLeNano(head) ? 1e9 : 1e6;
        parseClassicPcap(reader_, fileSize, &rdLe32, tsDiv, static_cast<int>(linkType), packets_);
    }
    else if (isPcapBe(head) || isPcapBeNano(head))
    {
        // 经典大端 pcap：同布局，字段大端。
        const unsigned char* gh = reader_.viewAt(0, 24);
        if (!gh)
            return false;
        uint32_t linkType = normalizeLinkType(rdBe32(gh + 20));
        linkType_         = static_cast<int>(linkType);
        double tsDiv      = isPcapBeNano(head) ? 1e9 : 1e6;
        parseClassicPcap(reader_, fileSize, &rdBe32, tsDiv, static_cast<int>(linkType), packets_);
    }
    else if (isPcapNg(head))
    {
        // pcapng：SHB + IDB + EPB/SPB 块。块布局：Type(4) + TotalLen(4) + 载荷 + TotalLen(4)。
        // 逐接口记录 LinkType 与时间戳分辨率（IDB 的 if_tsresol），EPB 按 interface_id 选用。
        std::vector<uint32_t> ifLink;    // 各接口链路类型
        std::vector<double>   ifTsDiv;   // 各接口时间戳除数（tick/秒）
        uint64_t              pos = 0;
        int                   frame = 1;
        for (;;)
        {
            if (pos + 8 > fileSize)
                break;
            const unsigned char* hdr = reader_.viewAt(pos, 8);
            if (!hdr)
                break;
            uint32_t type  = rdLe32(hdr);
            uint32_t total = rdLe32(hdr + 4);
            if (total < 12 || total > 64 * 1024 * 1024 || pos + total > fileSize)
                break; // 损坏保护
            if (type == 0x00000001) // IDB
            {
                const unsigned char* blk = reader_.viewAt(pos, total);
                uint32_t lt = 1;
                double   div = 1e6;
                if (blk)
                    parseIdb(blk, total, lt, div);
                ifLink.push_back(normalizeLinkType(lt));
                ifTsDiv.push_back(div);
                if (ifLink.size() == 1)
                    linkType_ = static_cast<int>(ifLink[0]); // 详情树用首个接口的链路类型
            }
            else if (type == 0x00000006) // EPB：interface(4) tsHigh(4) tsLow(4) capLen(4) origLen(4) data
            {
                const unsigned char* body = reader_.viewAt(pos + 8, 20);
                if (!body)
                    break;
                uint32_t ifId    = rdLe32(body);
                uint32_t tsHigh  = rdLe32(body + 4);
                uint32_t tsLow   = rdLe32(body + 8);
                uint32_t capLen  = rdLe32(body + 12);
                uint32_t origLen = rdLe32(body + 16);
                // capLen 取自文件字段，须按块长夹紧（块头 8 + body 20 + 尾长 4 = 32）；否则伪造的 capLen 会越读后续块字节。
                if (total >= 32 && capLen > total - 32)
                    capLen = total - 32;
                uint64_t dataOff = pos + 28;
                const unsigned char* data = reader_.viewAt(dataOff, capLen);
                if (!data)
                    break;
                double div = (ifId < ifTsDiv.size()) ? ifTsDiv[ifId] : 1e6;
                int    lt  = (ifId < ifLink.size()) ? static_cast<int>(ifLink[ifId]) : linkType_;
                double ts  = static_cast<double>((static_cast<uint64_t>(tsHigh) << 32) | tsLow) /
                            div;
                Packet p;
                p.frame_number = frame;
                p.time         = ts;
                p.cap_len      = capLen;
                p.len          = origLen ? origLen : capLen;
                p.file_offset  = dataOff;
                NativePacketParser::parseFrame(data, capLen, p, lt);
                packets_.push_back(std::make_shared<Packet>(std::move(p)));
                ++frame;
            }
            else if (type == 0x00000003) // SPB：origLen(4) + data（无时间戳，约定用接口 0）
            {
                const unsigned char* body = reader_.viewAt(pos + 8, 4);
                if (!body)
                    break;
                uint32_t origLen = rdLe32(body);
                uint64_t dataOff = pos + 12;
                uint32_t capLen  = (total >= 16) ? (total - 16) : origLen;
                if (capLen > origLen)
                    capLen = origLen;
                const unsigned char* data = reader_.viewAt(dataOff, capLen);
                if (!data)
                    break;
                int lt = ifLink.empty() ? linkType_ : static_cast<int>(ifLink[0]);
                Packet p;
                p.frame_number = frame;
                p.time         = 0.0;
                p.cap_len      = capLen;
                p.len          = origLen;
                p.file_offset  = dataOff;
                NativePacketParser::parseFrame(data, capLen, p, lt);
                packets_.push_back(std::make_shared<Packet>(std::move(p)));
                ++frame;
            }
            // 其他块（SHB/NRB/自定义）跳过
            pos += total;
        }
    }
    else
    {
        LOG_F(ERROR, "NativeAnalyzer: 无法识别的文件格式 %s", filePath.c_str());
        return false;
    }

    analyzed_ = true;
    out = packets_; // 共享同一批 shared_ptr（浅拷贝指针，不复制 Packet）
    LOG_F(INFO, "NativeAnalyzer: %s 共解析 %zu 包", filePath.c_str(), packets_.size());
    return true;
}

bool NativeAnalyzer::getPacketHexData(uint32_t frameNumber,
                                      std::vector<unsigned char>& out) const
{
    if (!analyzed_ || frameNumber == 0 || frameNumber > packets_.size())
        return false;
    const Packet& p = *packets_[frameNumber - 1];
    return reader_.readAt(p.file_offset, p.cap_len, out);
}

bool NativeAnalyzer::getPacketDetailTree(uint32_t frameNumber, DetailNode& root) const
{
    if (!analyzed_ || frameNumber == 0 || frameNumber > packets_.size())
        return false;
    const Packet& p = *packets_[frameNumber - 1];
    // 零拷贝借出原始帧字节；用分析时确定的链路类型，保证 SLL/NULL 等非以太网帧也能正确重解析。
    const unsigned char* raw = reader_.viewAt(p.file_offset, p.cap_len);
    if (!raw)
        return false;
    return NativePacketParser::buildDetailTree(raw, p.cap_len, linkType_, frameNumber, root);
}

bool NativeAnalyzer::getFramesByDisplayFilter(const std::string& expr,
                                              std::vector<uint32_t>& frames,
                                              std::string* err) const
{
    frames.clear();
    if (!analyzed_)
    {
        if (err)
            *err = "尚未分析任何文件";
        return false;
    }
    // 编译一次：把表达式解析成可复用谓词，避免对每个包重新词法/语法分析。
    std::string                        localErr;
    std::function<bool(const Packet&)> pred =
        NativePacketParser::compileDisplayFilter(expr, err ? err : &localErr);
    if (!pred)
        return false; // 表达式非法（原因已写入 err）
    for (const auto& p : packets_)
    {
        if (pred(*p))
            frames.push_back(static_cast<uint32_t>(p->frame_number));
    }
    return true;
}
