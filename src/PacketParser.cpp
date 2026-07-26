#include "PacketParser.hpp"

#include <cstdlib>

namespace PacketParser
{
namespace
{
// 在 [p, end) 区间上按十进制整数解析：要求至少消费一个数字，否则视为失败
// （与原先 std::stoi 对空串 / 非数字抛异常 → 返回 false 的语义一致）。
// 数字字段后面必然跟着 '\t' 或字符串结尾（c_str 以 '\0' 收尾），strtol 天然在
// 分隔符处停下，无需先把字段拷成独立的、以 '\0' 结尾的字符串。
bool parseLongField(const char* p, const char* end, long& out)
{
    if (p >= end)
    {
        return false; // 空字段
    }
    char* stop = nullptr;
    long  v    = std::strtol(p, &stop, 10);
    if (stop == p)
    {
        return false; // 没有消费任何数字：非法
    }
    out = v;
    return true;
}

// 同上，浮点版本（frame.time_epoch）。
bool parseDoubleField(const char* p, const char* end, double& out)
{
    if (p >= end)
    {
        return false;
    }
    char*  stop = nullptr;
    double v    = std::strtod(p, &stop);
    if (stop == p)
    {
        return false;
    }
    out = v;
    return true;
}
} // namespace

bool parseLine(const std::string& rawLine, Packet& packet)
{
    // 直接在 rawLine 上按有效长度切分，避免为了去掉末尾 '\n' 而整行复制一份
    size_t lineLen = rawLine.size();
    if (lineLen > 0 && rawLine[lineLen - 1] == '\n')
    {
        --lineLen;
    }

    // 只记录每个字段的 [start,end) 边界，而不是一上来就为 16 个字段各分配一个 std::string。
    // 数字字段（0-3、10-13）只需就地解析、用完即弃，避免“分配一个字符串马上又丢掉”的浪费；
    // 只有真正要存进 Packet 的文本字段（4-9、14、15）才在最后 substr 出来。
    struct Span
    {
        size_t start;
        size_t end;
    };
    Span   spans[16];
    int    fieldCount = 0;
    size_t start      = 0;
    while (fieldCount < 16)
    {
        size_t end = rawLine.find('\t', start);
        if (end == std::string::npos || end >= lineLen)
        {
            // 最后一个字段：吃到有效行尾（末尾 '\n' 已被 lineLen 排除在外）
            spans[fieldCount++] = {start, lineLen};
            break;
        }
        spans[fieldCount++] = {start, end};
        start               = end + 1;
    }

    // 字段下标与 TsharkCommand::tsharkFieldArgs() 一一对应：
    //  0: frame.number      1: frame.time_epoch   2: frame.len        3: frame.cap_len
    //  4: eth.src           5: eth.dst            6: ip.src           7: ipv6.src
    //  8: ip.dst            9: ipv6.dst          10: tcp.srcport     11: udp.srcport
    // 12: tcp.dstport      13: udp.dstport       14: _ws.col.Protocol 15: _ws.col.Info
    if (fieldCount < 16)
    {
        return false;
    }

    const char* base    = rawLine.c_str();
    auto        spanPtr = [&](int i) { return base + spans[i].start; };
    auto        spanEnd = [&](int i) { return base + spans[i].end; };
    auto        isEmpty = [&](int i) { return spans[i].start >= spans[i].end; };
    auto        substr  = [&](int i)
    { return rawLine.substr(spans[i].start, spans[i].end - spans[i].start); };

    // 数字字段就地解析：任意一个必填数字字段非法（空/非数字）即判定整行解析失败，
    // 绝不让异常沿 streamPackets → analysisFile → std::async 的 future 冒泡到 UI 线程。
    long tmp = 0;
    if (!parseLongField(spanPtr(0), spanEnd(0), tmp))
    {
        return false;
    }
    packet.frame_number = static_cast<int>(tmp);
    if (!parseDoubleField(spanPtr(1), spanEnd(1), packet.time))
    {
        return false;
    }
    if (!parseLongField(spanPtr(2), spanEnd(2), tmp))
    {
        return false;
    }
    packet.len = static_cast<uint32_t>(tmp);
    if (!parseLongField(spanPtr(3), spanEnd(3), tmp))
    {
        return false;
    }
    packet.cap_len = static_cast<uint32_t>(tmp);

    // 端口：tcp.* 非空取之，否则取 udp.*；两者皆空则保持默认 0。
    if (!isEmpty(10) || !isEmpty(11))
    {
        int idx = !isEmpty(10) ? 10 : 11;
        if (!parseLongField(spanPtr(idx), spanEnd(idx), tmp))
        {
            return false;
        }
        packet.src_port = static_cast<uint16_t>(tmp);
    }
    if (!isEmpty(12) || !isEmpty(13))
    {
        int idx = !isEmpty(12) ? 12 : 13;
        if (!parseLongField(spanPtr(idx), spanEnd(idx), tmp))
        {
            return false;
        }
        packet.dst_port = static_cast<uint16_t>(tmp);
    }

    // 文本字段才真正 substr 出来存入 Packet（临时串直接移动赋值，无额外拷贝）
    packet.src_mac = substr(4);
    packet.dst_mac = substr(5);
    // IPv4 为空时回退到 IPv6 字段
    packet.src_ip = !isEmpty(6) ? substr(6) : substr(7);
    packet.dst_ip = !isEmpty(8) ? substr(8) : substr(9);
    // 传输层：tcp.* 字段非空即 TCP，否则 udp.* 非空即 UDP，都空则留空。
    // 仅供会话视图区分，不影响 src_port/dst_port（二者已合并取值）。
    if (!isEmpty(10) || !isEmpty(12))
    {
        packet.transport = "TCP";
    }
    else if (!isEmpty(11) || !isEmpty(13))
    {
        packet.transport = "UDP";
    }
    packet.protocol = substr(14);
    packet.info     = substr(15);
    return true;
}
} // namespace PacketParser
