#include "PacketParser.hpp"

#include <vector>

namespace PacketParser
{
bool parseLine(const std::string& rawLine, Packet& packet)
{
    // 直接在 rawLine 上按有效长度切分，避免为了去掉末尾 '\n' 而整行复制一份
    size_t lineLen = rawLine.size();
    if (lineLen > 0 && rawLine[lineLen - 1] == '\n')
    {
        --lineLen;
    }

    std::vector<std::string> fields;
    fields.reserve(16); // 预期 16 个字段，预留容量避免 push_back 过程中反复扩容

    // 自己实现字符串拆分（限定在有效长度内，末尾 '\n' 不会混入最后一个字段）
    size_t start = 0, end;
    while (start <= lineLen && (end = rawLine.find('\t', start)) != std::string::npos &&
           end < lineLen)
    {
        fields.push_back(rawLine.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(rawLine.substr(start, lineLen - start));

    // 字段下标与 TsharkCommand::tsharkFieldArgs() 一一对应：
    //  0: frame.number      1: frame.time_epoch   2: frame.len        3: frame.cap_len
    //  4: eth.src           5: eth.dst            6: ip.src           7: ipv6.src
    //  8: ip.dst            9: ipv6.dst          10: tcp.srcport     11: udp.srcport
    // 12: tcp.dstport      13: udp.dstport       14: _ws.col.Protocol 15: _ws.col.Info
    if (fields.size() < 16)
    {
        return false;
    }

    // 数字字段用 stoi/stod 解析：遇到截断行或异常输出（非数字）会抛异常。
    // 这里就地捕获转成“解析失败”返回 false，绝不让异常沿 streamPackets →
    // analysisFile → std::async 的 future 冒泡到 UI 线程，导致 std::terminate。
    try
    {
        packet.frame_number = std::stoi(fields[0]);
        packet.time         = std::stod(fields[1]);
        packet.len          = std::stoi(fields[2]);
        packet.cap_len      = std::stoi(fields[3]);
        if (!fields[10].empty() || !fields[11].empty())
        {
            packet.src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }
        if (!fields[12].empty() || !fields[13].empty())
        {
            packet.dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
    }
    catch (const std::exception&)
    {
        return false;
    }

    // 用 std::move 把字段的内部缓冲直接转移给 Packet，避免再拷贝一份字符串
    packet.src_mac = std::move(fields[4]);
    packet.dst_mac = std::move(fields[5]);
    // IPv4 为空时回退到 IPv6 字段；先判空再 move，move 后原字段即失效
    packet.src_ip = std::move(fields[6].empty() ? fields[7] : fields[6]);
    packet.dst_ip = std::move(fields[8].empty() ? fields[9] : fields[8]);
    // 传输层：tcp.* 字段非空即 TCP，否则 udp.* 非空即 UDP，都空则留空。
    // 仅供会话视图区分，不影响 src_port/dst_port（二者已合并取值）。
    if (!fields[10].empty() || !fields[12].empty())
    {
        packet.transport = "TCP";
    }
    else if (!fields[11].empty() || !fields[13].empty())
    {
        packet.transport = "UDP";
    }
    packet.protocol = std::move(fields[14]);
    packet.info     = std::move(fields[15]);
    return true;
}
} // namespace PacketParser
