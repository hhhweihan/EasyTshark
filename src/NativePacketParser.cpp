#include "NativePacketParser.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <functional>

namespace NativePacketParser
{
namespace
{
// ---- 字节序工具（网络序 = 大端）----
uint16_t rd16(const unsigned char* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t rd32(const unsigned char* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

std::string macToStr(const unsigned char* p)
{
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3],
                  p[4], p[5]);
    return std::string(buf);
}

std::string ipv4ToStr(const unsigned char* p)
{
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return std::string(buf);
}

std::string ipv6ToStr(const unsigned char* p)
{
    char buf[40];
    int  pos = 0;
    for (int i = 0; i < 8; ++i)
    {
        pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%02x%02x", p[i * 2], p[i * 2 + 1]);
        if (i < 7)
            buf[pos++] = ':';
    }
    return std::string(buf);
}

// TCP flags → "[SYN, ACK]" 写入定长栈缓冲（无 flag 写空串），省去每包临时 std::string。
void tcpFlagsToBuf(char* out, size_t n, unsigned char flags)
{
    static const struct
    {
        unsigned char bit;
        const char*   name;
    } kFlags[] = {
        {0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"},
    };
    if (n == 0)
        return;
    size_t pos   = 0;
    bool   first = true;
    for (const auto& f : kFlags)
    {
        if (!(flags & f.bit))
            continue;
        const char* sep = first ? "[" : ", ";
        pos += static_cast<size_t>(std::snprintf(out + pos, pos < n ? n - pos : 0, "%s%s", sep,
                                                  f.name));
        first = false;
    }
    if (first) // 一个 flag 都没有
    {
        out[0] = '\0';
        return;
    }
    if (pos < n - 1)
    {
        out[pos++] = ']';
        out[pos]   = '\0';
    }
    else
        out[n - 1] = '\0';
}

// ---- 上层服务识别（据端口）----
const char* serviceForPort(uint16_t port, bool udp)
{
    if (udp)
    {
        if (port == 53) return "DNS";
        if (port == 123) return "NTP";
        if (port == 67 || port == 68) return "DHCP";
        if (port == 137 || port == 138) return "NetBIOS";
        if (port == 5353) return "MDNS";
        if (port == 1900) return "SSDP";
        if (port == 443) return "QUIC";
    }
    else
    {
        if (port == 80 || port == 8080) return "HTTP";
        if (port == 443 || port == 8443) return "TLS";
        if (port == 22) return "SSH";
        if (port == 53) return "TCP-DNS";
        if (port == 21) return "FTP";
        if (port == 25 || port == 587) return "SMTP";
        if (port == 110) return "POP";
        if (port == 143 || port == 993) return "IMAP";
        if (port == 3306) return "MySQL";
        if (port == 6379) return "Redis";
        if (port == 27017) return "MongoDB";
    }
    return nullptr;
}

// ---- DNS 辅助 ----
// 解析 DNS 名字（标签序列；遇压缩指针 0xC0 停止并返回消费字节数）
std::string dnsNameAt(const unsigned char* p, uint32_t avail, uint32_t& consumed)
{
    std::string name;
    uint32_t    pos = 0;
    while (pos < avail)
    {
        uint8_t len = p[pos];
        if (len == 0)
        {
            ++pos;
            break;
        }
        if ((len & 0xC0) == 0xC0)
        {
            pos += 2; // 压缩指针：不跟随
            break;
        }
        ++pos;
        if (pos + len > avail)
            break;
        if (!name.empty())
            name += '.';
        for (uint32_t i = 0; i < len; ++i)
            name += static_cast<char>(p[pos + i]);
        pos += len;
    }
    consumed = pos;
    return name;
}

const char* dnsTypeName(uint16_t t)
{
    switch (t)
    {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 255: return "ANY";
    default: return "?";
    }
}

// 提取 DNS 报文第 0 个 question 的 name 与 qtype（消费 name 后的偏移回填）
std::string dnsFirstQuestion(const unsigned char* payload, uint32_t len, uint16_t& qtype)
{
    qtype = 0;
    if (len < 12)
        return std::string();
    uint16_t qd = rd16(payload + 4);
    if (qd == 0)
        return std::string();
    uint32_t off = 12;
    uint32_t consumed = 0;
    std::string name = dnsNameAt(payload + 12, len - 12, consumed);
    off += consumed;
    if (off + 4 <= len)
        qtype = rd16(payload + off);
    return name;
}

// DNS 响应：摘要前几个回答记录（type + rdata）
std::string dnsAnswerSummary(const unsigned char* payload, uint32_t len)
{
    std::string out;
    if (len < 12)
        return out;
    uint16_t qd    = rd16(payload + 4);
    uint16_t an    = rd16(payload + 6);
    uint16_t anMax = an > 3 ? 3 : an; // 只摘要前 3 个，避免超长
    if (an == 0)
        return out;
    uint32_t off = 12;
    // 跳过 questions
    for (uint16_t i = 0; i < qd; ++i)
    {
        if (off >= len)
            return out;
        uint32_t consumed = 0;
        dnsNameAt(payload + off, len - off, consumed);
        off += consumed + 4; // qtype + qclass
    }
    // 解析 answers
    for (uint16_t i = 0; i < an && i < anMax; ++i)
    {
        if (off + 10 > len)
            break;
        uint32_t consumed = 0;
        dnsNameAt(payload + off, len - off, consumed);
        off += consumed;
        if (off + 10 > len)
            break;
        uint16_t type    = rd16(payload + off);
        uint16_t rdlen   = rd16(payload + off + 8);
        const unsigned char* rdata = payload + off + 10;
        if (off + 10 + rdlen > len)
            break;
        char buf[96];
        if (type == 1 && rdlen == 4) // A
        {
            std::snprintf(buf, sizeof(buf), "%s %s", dnsTypeName(type),
                          ipv4ToStr(rdata).c_str());
        }
        else if (type == 28 && rdlen == 16) // AAAA
        {
            std::snprintf(buf, sizeof(buf), "%s %s", dnsTypeName(type), ipv6ToStr(rdata).c_str());
        }
        else if ((type == 12 || type == 5 || type == 2) && rdlen > 0) // PTR/CNAME/NS
        {
            uint32_t c = 0;
            std::string n = dnsNameAt(rdata, rdlen, c);
            std::snprintf(buf, sizeof(buf), "%s %s", dnsTypeName(type), n.c_str());
        }
        else if (type == 16 && rdlen > 0) // TXT
        {
            std::string txt(reinterpret_cast<const char*>(rdata + 1),
                            static_cast<size_t>(rdlen > 1 ? rdlen - 1 : 0));
            if (txt.size() > 24)
                txt.resize(24);
            std::snprintf(buf, sizeof(buf), "TXT \"%s\"", txt.c_str());
        }
        else
        {
            std::snprintf(buf, sizeof(buf), "%s", dnsTypeName(type));
        }
        if (!out.empty())
            out += ", ";
        out += buf;
        off += 10 + rdlen;
    }
    return out;
}

// DNS 报文 → info 摘要（查询 + 响应回答）
std::string dnsInfo(const unsigned char* payload, uint32_t len, ProtocolDetail& detail)
{
    if (len < 12)
        return std::string();
    uint16_t id     = rd16(payload);
    uint16_t flags  = rd16(payload + 2);
    bool     resp   = (flags & 0x8000) != 0;
    uint16_t qtype  = 0;
    std::string name = dnsFirstQuestion(payload, len, qtype);
    std::string answers = dnsAnswerSummary(payload, len);
    detail.dnsAnswers = answers;

    char buf[256];
    if (resp)
    {
        if (!answers.empty())
            std::snprintf(buf, sizeof(buf), "Standard query response 0x%04x, %s", id,
                          answers.c_str());
        else
            std::snprintf(buf, sizeof(buf), "Standard query response 0x%04x", id);
    }
    else if (!name.empty())
        std::snprintf(buf, sizeof(buf), "Standard query 0x%04x %s %s", id, dnsTypeName(qtype),
                      name.c_str());
    else
        std::snprintf(buf, sizeof(buf), "Standard query 0x%04x", id);
    return std::string(buf);
}

// ---- HTTP ----
void parseHttp(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    // 只解析首行 + Host 头（TCP 载荷可能跨包，取首个完整 \r\n 行）
    detail.http = true;
    const unsigned char* lineEnd = static_cast<const unsigned char*>(
        std::memchr(payload, '\n', len));
    uint32_t lineLen = lineEnd ? static_cast<uint32_t>(lineEnd - payload) : len;
    std::string firstLine(reinterpret_cast<const char*>(payload),
                          static_cast<size_t>(lineLen > 0 && payload[lineLen - 1] == '\r'
                                                  ? lineLen - 1
                                                  : lineLen));
    // 行首三 token（响应 "HTTP/1.1 200 OK" / 请求 "GET /x HTTP/1.1"）；手动切分省去 istringstream 开销。
    std::string tok1, tok2, tok3;
    {
        std::string* toks[3] = {&tok1, &tok2, &tok3};
        size_t       i = 0, n = firstLine.size(), t = 0;
        while (t < 3)
        {
            while (i < n && (firstLine[i] == ' ' || firstLine[i] == '\t'))
                ++i;
            if (i >= n)
                break;
            size_t s = i;
            while (i < n && firstLine[i] != ' ' && firstLine[i] != '\t')
                ++i;
            toks[t++]->assign(firstLine, s, i - s);
        }
    }
    if (tok1.compare(0, 5, "HTTP/") == 0) // 响应行：HTTP/x.y CODE REASON
    {
        detail.httpVersion = tok1;
        detail.httpStatus  = tok2;
        detail.httpReason  = tok3;
        char buf[128];
        std::snprintf(buf, sizeof(buf), "%s %s %s", tok1.c_str(), tok2.c_str(), tok3.c_str());
        packet.info = buf;
    }
    else if (tok2.compare(0, 1, "/") == 0 || tok2.compare(0, 1, "?") == 0)
    {
        detail.httpMethod  = tok1;
        detail.httpUri     = tok2;
        detail.httpVersion = tok3;
        // 找 Host 头（前几行内）
        const unsigned char* p = payload;
        const unsigned char* end = payload + len;
        for (int i = 0; i < 20 && p < end; ++i)
        {
            const unsigned char* nl = static_cast<const unsigned char*>(
                std::memchr(p, '\n', static_cast<size_t>(end - p)));
            if (!nl)
                break;
            size_t hlen = static_cast<size_t>(nl - p);
            if (hlen > 2 && std::strncmp(reinterpret_cast<const char*>(p), "Host:", 5) == 0)
            {
                std::string host(reinterpret_cast<const char*>(p + 5), hlen - 5);
                size_t s = host.find_first_not_of(" \t\r");
                if (s != std::string::npos)
                    detail.httpHost = host.substr(s);
                break;
            }
            p = nl + 1;
        }
        char buf[256];
        if (!detail.httpHost.empty())
            std::snprintf(buf, sizeof(buf), "%s %s %s Host: %s", tok1.c_str(), tok2.c_str(),
                          tok3.c_str(), detail.httpHost.c_str());
        else
            std::snprintf(buf, sizeof(buf), "%s %s %s", tok1.c_str(), tok2.c_str(),
                          tok3.c_str());
        packet.info = buf;
    }
}

// ---- TLS ----
// TLS record: type(1) version(2) len(2) payload
void parseTls(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (len < 5)
        return;
    detail.tls = true;
    unsigned char rtype = payload[0];
    uint16_t      ver   = rd16(payload + 1);
    uint16_t      rlen  = rd16(payload + 3);
    const char*   version = nullptr;
    if (ver == 0x0301) version = "TLS 1.0";
    else if (ver == 0x0302) version = "TLS 1.1";
    else if (ver == 0x0303) version = "TLS 1.2";
    else if (ver == 0x0304) version = "TLS 1.3";
    if (version)
        detail.tlsVersion = version;

    if (rtype == 0x16) // Handshake
    {
        if (len < 6)
            return;
        unsigned char hsType = payload[5];
        const char*   hsName = nullptr;
        switch (hsType)
        {
        case 1: hsName = "Client Hello"; break;
        case 2: hsName = "Server Hello"; break;
        case 4: hsName = "New Session Ticket"; break;
        case 11: hsName = "Certificate"; break;
        case 13: hsName = "Certificate Request"; break;
        case 14: hsName = "Server Hello Done"; break;
        case 15: hsName = "Certificate Verify"; break;
        case 16: hsName = "Client Key Exchange"; break;
        case 20: hsName = "Finished"; break;
        default: hsName = "Handshake"; break;
        }
        detail.tlsType = hsName;
        // ClientHello（type 1）里提取 SNI
            if (hsType == 1 && len >= 12)
            {
                // body: version(2) random(32) sidLen(1)+sid cipherLen(2)+ciphers compLen(1)+comp extLen(2)+ext
                uint32_t off = 5 + 4 + 2 + 32; // record 5 + hs 4 + version 2 + random 32 = 43
                if (off < len)
                {
                    uint8_t sidLen = payload[off++];
                    off += sidLen;
                    if (off + 2 <= len)
                    {
                        uint16_t csLen = rd16(payload + off);
                        off += 2 + csLen;
                    }
                    if (off < len)
                    {
                        uint8_t compLen = payload[off++];
                        off += compLen;
                    }
                    if (off + 2 <= len)
                    {
                        uint16_t extTotal = rd16(payload + off);
                        off += 2;
                        uint32_t extEnd = off + extTotal;
                        if (extEnd > len)
                            extEnd = len;
                        while (off + 4 <= extEnd)
                        {
                            uint16_t extType = rd16(payload + off);
                            uint16_t extLen  = rd16(payload + off + 2);
                            if (extType == 0 && extLen >= 5 && off + 4 + extLen <= extEnd)
                            {
                                // SNI 扩展布局：listLen(2) nameType(1) nameLen(2) name；extLen = 2 + listLen
                                uint16_t listLen = rd16(payload + off + 4);
                                if (listLen >= 3 && 2 + listLen <= extLen)
                                {
                                    uint16_t nameLen = rd16(payload + off + 4 + 3);
                                    if (nameLen > 0 && 2 + 3 + nameLen <= extLen)
                                    {
                                        detail.tlsSni =
                                            std::string(reinterpret_cast<const char*>(payload +
                                                                                      off + 4 +
                                                                                      3 + 2),
                                                        nameLen);
                                    }
                                }
                                break;
                            }
                            off += 4 + extLen;
                        }
                    }
                }
            }
        }
    else if (rtype == 0x17)
    {
        detail.tlsType = "Application Data";
    }
    else if (rtype == 0x15)
    {
        detail.tlsType = "Alert";
    }
    else if (rtype == 0x14)
    {
        detail.tlsType = "Change Cipher Spec";
    }
    char buf[128];
    if (!detail.tlsSni.empty())
        std::snprintf(buf, sizeof(buf), "%s, %s, SNI=%s", detail.tlsType.c_str(),
                      version ? version : "TLS", detail.tlsSni.c_str());
    else
        std::snprintf(buf, sizeof(buf), "%s, %s", detail.tlsType.c_str(),
                      version ? version : "TLS");
    packet.info = buf;
}

// ---- DHCP ----
void parseDhcp(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (len < 240)
        return;
    detail.dhcp = true;
    uint8_t op = payload[0]; // 1=request 2=reply
    // magic cookie 0x63825363 在偏移 236
    if (payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 ||
        payload[239] != 0x63)
        return;
    const char* type = "?";
    uint32_t    off  = 240;
    uint32_t    end  = len - 1; // 末尾 0xff 是 end option
    while (off < end)
    {
        uint8_t opt = payload[off];
        if (opt == 255)
            break;
        if (opt == 0) // pad
        {
            ++off;
            continue;
        }
        if (off + 1 >= len)
            break;
        uint8_t olen = payload[off + 1];
        if (opt == 53 && olen == 1 && off + 2 < len)
        {
            switch (payload[off + 2])
            {
            case 1: type = "Discover"; break;
            case 2: type = "Offer"; break;
            case 3: type = "Request"; break;
            case 4: type = "Decline"; break;
            case 5: type = "ACK"; break;
            case 6: type = "NAK"; break;
            case 7: type = "Release"; break;
            case 8: type = "Inform"; break;
            }
            break;
        }
        off += 2 + olen;
    }
    detail.dhcpType = type;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "DHCP %s, %s, XID=0x%08x", type,
                  op == 2 ? "Reply" : "Request",
                  rd32(payload + 4));
    packet.info = buf;
}

// ---- NTP ----
void parseNtp(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (len < 4)
        return;
    detail.ntp      = true;
    uint8_t  b0     = payload[0];
    unsigned vn     = (b0 >> 3) & 0x07;
    unsigned mode   = b0 & 0x07;
    const char* modeName = "?";
    switch (mode)
    {
    case 3: modeName = "client"; break;
    case 4: modeName = "server"; break;
    case 6: modeName = "control"; break;
    default: break;
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "NTP v%u, %s", vn, modeName);
    detail.ntpDesc = buf;
    packet.info    = buf;
}

// ---- TCP/UDP ----
void parseTcp(const unsigned char* data, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (len < 4)
        return;
    packet.src_port = rd16(data);
    packet.dst_port = rd16(data + 2);
    packet.transport = "TCP";
    const char* svc = serviceForPort(packet.src_port, false);
    if (!svc)
        svc = serviceForPort(packet.dst_port, false);
    if (svc && std::strcmp(svc, "TCP-DNS") != 0)
        packet.protocol = svc;
    else
        packet.protocol = "TCP";
    unsigned char flags = (len >= 14) ? data[13] : 0;
    uint32_t      seq = (len >= 8) ? rd32(data + 4) : 0;
    uint32_t      ack = (len >= 12) ? rd32(data + 8) : 0;
    uint16_t      win = (len >= 16) ? rd16(data + 14) : 0;
    uint32_t      tcpLen = (len >= 12) ? ((data[12] >> 4) * 4) : 20;
    uint32_t      appLen = (len > tcpLen) ? (len - tcpLen) : 0;

    // 应用层解析（载荷非空且是已识别服务）
    const unsigned char* app = data + tcpLen;
    if (appLen > 0 && packet.protocol == "HTTP")
        parseHttp(app, appLen, packet, detail);
    else if (appLen > 0 && packet.protocol == "TLS")
        parseTls(app, appLen, packet, detail);

    if (detail.http || detail.tls)
        return; // 应用层已填 info

    char flagsBuf[40];
    tcpFlagsToBuf(flagsBuf, sizeof(flagsBuf), flags);
    char buf[160];
    std::snprintf(buf, sizeof(buf), "%u \xe2\x86\x92 %u %s Seq=%u Ack=%u Win=%u Len=%u",
                  packet.src_port, packet.dst_port, flagsBuf, seq, ack, win, appLen);
    packet.info = buf;
}

void parseUdp(const unsigned char* data, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (len < 8)
        return;
    packet.src_port  = rd16(data);
    packet.dst_port  = rd16(data + 2);
    uint16_t udpLen  = rd16(data + 4);
    packet.transport = "UDP";
    const char* svc = serviceForPort(packet.src_port, true);
    if (!svc)
        svc = serviceForPort(packet.dst_port, true);
    if (svc)
        packet.protocol = svc;
    else
        packet.protocol = "UDP";

    uint32_t appLen = (udpLen >= 8 && udpLen <= len) ? (udpLen - 8) : (len - 8);
    const unsigned char* app = data + 8;

    if (packet.protocol == "DNS" && appLen > 0)
    {
        packet.info = dnsInfo(app, appLen, detail);
        if (packet.info.empty())
        {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "%u \xe2\x86\x92 %u Len=%u", packet.src_port,
                          packet.dst_port, appLen);
            packet.info = buf;
        }
        return;
    }
    if (packet.protocol == "DHCP" && appLen > 0)
    {
        parseDhcp(app, appLen, packet, detail);
        return;
    }
    if (packet.protocol == "NTP" && appLen > 0)
    {
        parseNtp(app, appLen, packet, detail);
        return;
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%u \xe2\x86\x92 %u Len=%u", packet.src_port, packet.dst_port,
                  appLen);
    packet.info = buf;
}

void parseIcmp(const unsigned char* data, uint32_t len, Packet& packet, bool v6,
               ProtocolDetail& detail)
{
    if (len < 4)
        return;
    packet.protocol = v6 ? "ICMPv6" : "ICMP";
    uint8_t type = data[0];
    uint8_t code = data[1];
    const char* desc = nullptr;
    if (!v6)
    {
        switch (type)
        {
        case 0: desc = "Echo (ping) reply"; break;
        case 3: desc = "Destination unreachable"; break;
        case 5: desc = "Redirect"; break;
        case 8: desc = "Echo (ping) request"; break;
        case 9: desc = "Router advertisement"; break;
        case 10: desc = "Router solicitation"; break;
        case 11: desc = "Time-to-live exceeded"; break;
        case 13: desc = "Timestamp request"; break;
        case 14: desc = "Timestamp reply"; break;
        default: break;
        }
    }
    else
    {
        switch (type)
        {
        case 1: desc = "Destination unreachable"; break;
        case 2: desc = "Packet too big"; break;
        case 3: desc = "Time exceeded"; break;
        case 128: desc = "Echo (ping) request"; break;
        case 129: desc = "Echo (ping) reply"; break;
        case 133: desc = "Router solicitation"; break;
        case 134: desc = "Router advertisement"; break;
        case 135: desc = "Neighbor solicitation"; break;
        case 136: desc = "Neighbor advertisement"; break;
        case 137: desc = "Redirect"; break;
        default: break;
        }
    }
    char buf[80];
    if (desc)
        std::snprintf(buf, sizeof(buf), "%s (type=%u, code=%u)", desc, type, code);
    else
        std::snprintf(buf, sizeof(buf), "Type %u, code %u", type, code);
    packet.info = buf;
}

void parseArp(const unsigned char* data, uint32_t len, Packet& packet)
{
    if (len < 28)
        return;
    uint16_t htype = rd16(data);
    uint16_t ptype = rd16(data + 2);
    uint16_t op    = rd16(data + 6);
    packet.protocol = "ARP";
    if (htype != 1 || ptype != 0x0800)
        return;
    if (op == 1)
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Who has %s? Tell %s", ipv4ToStr(data + 24).c_str(),
                      ipv4ToStr(data + 14).c_str());
        packet.info = buf;
    }
    else if (op == 2)
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s is at %s", ipv4ToStr(data + 14).c_str(),
                      macToStr(data + 8).c_str());
        packet.info = buf;
    }
}

// 解析 IPv4（含分片信息）
bool parseIpv4(const unsigned char* data, uint32_t len, Packet& packet, uint8_t& proto,
               const unsigned char*& payload, uint32_t& payloadLen, ProtocolDetail& detail)
{
    if (len < 20)
        return false;
    uint8_t  ihl = (data[0] & 0x0F) * 4;
    uint16_t total = rd16(data + 2);
    if (ihl < 20 || ihl > len)
        return false;
    proto     = data[9];
    packet.src_ip = ipv4ToStr(data + 12);
    packet.dst_ip = ipv4ToStr(data + 16);
    // 分片：flags(2 字节) 的 MF=0x2000，offset 低 13 位
    uint16_t fragField = rd16(data + 6);
    detail.fragMore    = (fragField & 0x2000) != 0;
    detail.fragOffset  = static_cast<uint16_t>((fragField & 0x1FFF) * 8);
    detail.ipFragmented = (fragField & 0x1FFF) != 0 || detail.fragMore;
    uint32_t plen = (total >= ihl && total <= len) ? (total - ihl) : (len - ihl);
    payload    = data + ihl;
    payloadLen = plen;
    return true;
}

bool parseIpv6(const unsigned char* data, uint32_t len, Packet& packet, uint8_t& proto,
               const unsigned char*& payload, uint32_t& payloadLen)
{
    if (len < 40)
        return false;
    uint16_t plen = rd16(data + 4);
    proto     = data[6];
    packet.src_ip = ipv6ToStr(data + 8);
    packet.dst_ip = ipv6ToStr(data + 24);
    uint32_t off = 40;
    uint32_t avail = (plen + 40 <= len) ? plen : (len - 40);
    int guard = 0;
    while ((proto == 0 || proto == 43 || proto == 44 || proto == 51 || proto == 60) &&
           guard++ < 8)
    {
        if (off + 2 > len)
            break;
        uint8_t next  = data[off];
        uint8_t hlen8 = data[off + 1];
        if (proto == 44)
        {
            if (off + 8 > len)
                break;
            off += 8;
        }
        else if (proto == 51)
        {
            off += (hlen8 + 2) * 4;
        }
        else
        {
            off += (hlen8 + 1) * 8;
        }
        proto = next;
        if (off > len)
            break;
    }
    if (off > avail + 40 || off > len)
    {
        payload    = nullptr;
        payloadLen = 0;
        return true;
    }
    payload    = data + off;
    payloadLen = avail + 40 - off;
    if (payloadLen > len - off)
        payloadLen = len - off;
    return true;
}

// 以太网帧解析
bool parseEthernet(const unsigned char* data, uint32_t len, Packet& packet,
                   const unsigned char*& payload, uint32_t& payloadLen, uint16_t& ethertype)
{
    if (len < 14)
        return false;
    packet.dst_mac = macToStr(data);
    packet.src_mac = macToStr(data + 6);
    uint32_t off = 14;
    ethertype     = rd16(data + 12);
    int guard = 0;
    while ((ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100) && guard++ < 4)
    {
        if (off + 4 > len)
            return false;
        off += 4;
        ethertype = rd16(data + off - 2);
    }
    if (off > len)
        return false;
    payload    = data + off;
    payloadLen = len - off;
    return true;
}

// 按 EtherType 分派到网络层/上层解析。Ethernet 与 Linux SLL/SLL2 剥掉各自的
// 链路头后，携带的 EtherType 语义一致，故共用这段分派逻辑。
bool dispatchByEtherType(uint16_t ethertype, const unsigned char* payload, uint32_t payloadLen,
                         Packet& packet, ProtocolDetail& detail)
{
    if (ethertype == 0x0806)
    {
        parseArp(payload, payloadLen, packet);
        return true;
    }
    if (ethertype == 0x0800)
    {
        uint8_t proto = 0;
        if (!parseIpv4(payload, payloadLen, packet, proto, payload, payloadLen, detail))
            return false;
        if (proto == 6)
            parseTcp(payload, payloadLen, packet, detail);
        else if (proto == 17)
            parseUdp(payload, payloadLen, packet, detail);
        else if (proto == 1)
            parseIcmp(payload, payloadLen, packet, false, detail);
        else if (proto == 2)
        {
            packet.protocol = "IGMP";
            packet.info     = "IGMP";
        }
        else
        {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "IP-%u", proto);
            packet.protocol = buf;
        }
        return true;
    }
    if (ethertype == 0x86DD)
    {
        uint8_t proto = 0;
        if (!parseIpv6(payload, payloadLen, packet, proto, payload, payloadLen))
            return false;
        if (proto == 6)
            parseTcp(payload, payloadLen, packet, detail);
        else if (proto == 17)
            parseUdp(payload, payloadLen, packet, detail);
        else if (proto == 58)
            parseIcmp(payload, payloadLen, packet, true, detail);
        else if (proto == 59)
            return true;
        else
        {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "IPv6-%u", proto);
            packet.protocol = buf;
        }
        return true;
    }
    if (ethertype == 0x88CC)
    {
        packet.protocol = "LLDP";
        packet.info     = "Link Layer Discovery Protocol";
        return true;
    }
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%04x", ethertype);
    packet.protocol = buf;
    packet.info     = "Unknown ethertype " + std::string(buf);
    return true;
}

// Linux "cooked" 捕获（tcpdump -i any）：
//   SLL  (linktype 113)：pkttype(2) arphrd(2) lladdrlen(2) lladdr(8) protocol(2) → 头长 16
//   SLL2 (linktype 276)：protocol(2) reserved(2) ifindex(4) arphrd(2) pkttype(1) lladdrlen(1)
//                        lladdr(8) → 头长 20，protocol 在最前
bool parseSll(const unsigned char* data, uint32_t len, bool v2, Packet& packet,
              ProtocolDetail& detail)
{
    uint32_t hdr = v2 ? 20 : 16;
    if (len < hdr)
        return false;
    uint16_t ethertype = v2 ? rd16(data) : rd16(data + 14);
    return dispatchByEtherType(ethertype, data + hdr, len - hdr, packet, detail);
}

// 主解析：填充 Packet + ProtocolDetail
bool parseFrameCtx(const unsigned char* data, uint32_t len, int linkType, Packet& packet,
                   ProtocolDetail& detail)
{
    if (!data || len < 14)
        return false;

    // NULL/Loopback 链路（BSD lo 接口）
    if (linkType == 0 ||
        (linkType < 0 && len >= 4 &&
         ((data[0] == 2 && data[1] == 0 && data[2] == 0 && data[3] == 0) ||
          (data[0] == 30 && data[1] == 0 && data[2] == 0 && data[3] == 0) ||
          (data[0] == 24 && data[1] == 0 && data[2] == 0 && data[3] == 0))))
    {
        uint32_t family = static_cast<uint32_t>(data[0]) |
                          (static_cast<uint32_t>(data[1]) << 8) |
                          (static_cast<uint32_t>(data[2]) << 16) |
                          (static_cast<uint32_t>(data[3]) << 24);
        const unsigned char* payload    = data + 4;
        uint32_t             payloadLen = len - 4;
        if (family == 2)
        {
            uint8_t proto = 0;
            if (!parseIpv4(payload, payloadLen, packet, proto, payload, payloadLen, detail))
                return false;
            if (proto == 6)
                parseTcp(payload, payloadLen, packet, detail);
            else if (proto == 17)
                parseUdp(payload, payloadLen, packet, detail);
            else if (proto == 1)
                parseIcmp(payload, payloadLen, packet, false, detail);
            else
            {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "IP-%u", proto);
                packet.protocol = buf;
            }
            return true;
        }
        if (family == 30 || family == 24)
        {
            uint8_t proto = 0;
            if (!parseIpv6(payload, payloadLen, packet, proto, payload, payloadLen))
                return false;
            if (proto == 6)
                parseTcp(payload, payloadLen, packet, detail);
            else if (proto == 17)
                parseUdp(payload, payloadLen, packet, detail);
            else if (proto == 58)
                parseIcmp(payload, payloadLen, packet, true, detail);
            else
            {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "IPv6-%u", proto);
                packet.protocol = buf;
            }
            return true;
        }
    }

    // Linux SLL / SLL2（tcpdump -i any 抓包的链路层）
    if (linkType == 113)
        return parseSll(data, len, false, packet, detail);
    if (linkType == 276)
        return parseSll(data, len, true, packet, detail);

    // 默认 Ethernet II（含 VLAN/QinQ 剥离）
    const unsigned char* payload    = nullptr;
    uint32_t             payloadLen = 0;
    uint16_t             ethertype  = 0;
    if (!parseEthernet(data, len, packet, payload, payloadLen, ethertype))
        return false;
    return dispatchByEtherType(ethertype, payload, payloadLen, packet, detail);
}
} // namespace

bool available()
{
    return true;
}

bool parseFrame(const unsigned char* data, uint32_t len, Packet& packet, int linkType)
{
    ProtocolDetail detail;
    return parseFrameCtx(data, len, linkType, packet, detail);
}

// ---- 完整协议树 ----
namespace
{
void addChild(DetailNode& parent, const std::string& label, const std::string& value)
{
    DetailNode n;
    n.label = label;
    n.value = value;
    parent.children.push_back(n);
}

void addLeaf(const std::string& label, const std::string& value, DetailNode& root)
{
    addChild(root, label, value);
}
} // namespace

bool buildDetailTree(const unsigned char* data, uint32_t len, int linkType, uint32_t frameNumber,
                     DetailNode& root)
{
    Packet p;
    ProtocolDetail detail;
    if (!parseFrameCtx(data, len, linkType, p, detail))
        return false;
    p.frame_number = frameNumber;

    root.label = "Frame " + std::to_string(frameNumber);
    char buf[128];

    // Ethernet II / Null/Loopback
    DetailNode eth;
    if (!p.src_mac.empty())
    {
        eth.label = "Ethernet II";
        addChild(eth, "Destination", p.dst_mac);
        addChild(eth, "Source", p.src_mac);
        bool v6addr = p.src_ip.find(':') != std::string::npos;
        addChild(eth, "Type", p.protocol + " (0x" + (v6addr ? "86dd" : "0800") + ")");
    }
    else
    {
        eth.label = "Null/Loopback";
        addChild(eth, "Family", p.src_ip.find(':') != std::string::npos ? "IPv6" : "IPv4");
    }
    root.children.push_back(eth);

    // IP 层
    if (!p.src_ip.empty())
    {
        bool v6 = p.src_ip.find(':') != std::string::npos;
        DetailNode ip;
        ip.label = v6 ? "Internet Protocol Version 6" : "Internet Protocol Version 4";
        addChild(ip, "Source", p.src_ip);
        addChild(ip, "Destination", p.dst_ip);
        addChild(ip, "Protocol", p.protocol);
        if (detail.ipFragmented)
        {
            std::snprintf(buf, sizeof(buf), "%s (offset=%u)",
                          detail.fragMore ? "More fragments" : "Last fragment",
                          detail.fragOffset);
            addChild(ip, "Fragment", buf);
        }
        root.children.push_back(ip);
    }

    // 传输层
    if (p.transport == "TCP" || p.transport == "UDP")
    {
        DetailNode tr;
        tr.label = (p.transport == "TCP") ? "Transmission Control Protocol"
                                          : "User Datagram Protocol";
        char pbuf[16];
        std::snprintf(pbuf, sizeof(pbuf), "%u", p.src_port);
        addChild(tr, "Source Port", pbuf);
        std::snprintf(pbuf, sizeof(pbuf), "%u", p.dst_port);
        addChild(tr, "Destination Port", pbuf);
        addChild(tr, "Info", p.info);
        root.children.push_back(tr);
    }
    else if (p.protocol == "ICMP" || p.protocol == "ICMPv6")
    {
        DetailNode ic;
        ic.label = (p.protocol == "ICMPv6") ? "Internet Control Message Protocol v6"
                                            : "Internet Control Message Protocol";
        addChild(ic, "Info", p.info);
        root.children.push_back(ic);
    }
    else if (p.protocol == "ARP")
    {
        DetailNode ar;
        ar.label = "Address Resolution Protocol";
        addChild(ar, "Info", p.info);
        root.children.push_back(ar);
    }

    // 应用层分层
    if (detail.http)
    {
        DetailNode hp;
        hp.label = "Hypertext Transfer Protocol";
        if (!detail.httpMethod.empty())
            addChild(hp, "Method", detail.httpMethod);
        if (!detail.httpUri.empty())
            addChild(hp, "URI", detail.httpUri);
        if (!detail.httpVersion.empty())
            addChild(hp, "Version", detail.httpVersion);
        if (!detail.httpStatus.empty())
            addChild(hp, "Status Code", detail.httpStatus + " " + detail.httpReason);
        if (!detail.httpHost.empty())
            addChild(hp, "Host", detail.httpHost);
        root.children.push_back(hp);
    }
    else if (detail.tls)
    {
        DetailNode tl;
        tl.label = "Transport Layer Security";
        addChild(tl, "Handshake", detail.tlsType);
        if (!detail.tlsVersion.empty())
            addChild(tl, "Version", detail.tlsVersion);
        if (!detail.tlsSni.empty())
            addChild(tl, "Server Name Indication", detail.tlsSni);
        root.children.push_back(tl);
    }
    else if (p.protocol == "DNS")
    {
        DetailNode dn;
        dn.label = "Domain Name System";
        addChild(dn, "Info", p.info);
        if (!detail.dnsAnswers.empty())
            addChild(dn, "Answers", detail.dnsAnswers);
        root.children.push_back(dn);
    }
    else if (detail.dhcp)
    {
        DetailNode dh;
        dh.label = "Dynamic Host Configuration Protocol";
        addChild(dh, "Message Type", detail.dhcpType);
        addChild(dh, "Info", p.info);
        root.children.push_back(dh);
    }
    else if (detail.ntp)
    {
        DetailNode nt;
        nt.label = "Network Time Protocol";
        addChild(nt, "Info", detail.ntpDesc);
        root.children.push_back(nt);
    }

    return true;
}

// ---- 显示过滤子集 ----
// 编译一次为 std::function 闭包求值树（Pred）：语法/字段校验在编译期完成，求值期只做比较，N 个报文只解析一次。
// 文法（优先级 ! > && > ||，支持括号）：
//   or     := and ("||" and)*
//   and    := unary ("&&" unary)*
//   unary  := "!" unary | "(" or ")" | primary
//   primary:= FIELD (("=="|"!=") VALUE)?      // 带值=比较；裸字段=存在性
namespace
{
typedef std::function<bool(const Packet&)> Pred;

class Compiler
{
public:
    Compiler(const std::string& s, std::string* e) : src(s), err(e), pos(0) {}

    // 成功返回可复用谓词；语法/字段非法返回空 Pred 并置 *err。
    Pred compile()
    {
        skipSpace();
        Pred p = parseOr();
        if (!p)
            return Pred();
        skipSpace();
        if (pos != src.size())
        {
            setErr("unexpected trailing text");
            return Pred();
        }
        return p;
    }

private:
    const std::string& src;
    std::string*       err;
    size_t             pos;

    void setErr(const std::string& m)
    {
        if (err && err->empty())
            *err = "过滤表达式错误：" + m;
    }

    void skipSpace()
    {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t'))
            ++pos;
    }

    bool peek(const char* tok) { return src.compare(pos, std::strlen(tok), tok) == 0; }

    Pred parseOr()
    {
        Pred left = parseAnd();
        if (!left)
            return Pred();
        for (;;)
        {
            skipSpace();
            if (!peek("||"))
                break;
            pos += 2;
            Pred right = parseAnd();
            if (!right)
                return Pred();
            Pred l = left, r = right; // 捕获两个子谓词，合成新的短路 OR
            left = [l, r](const Packet& p) { return l(p) || r(p); };
        }
        return left;
    }

    Pred parseAnd()
    {
        Pred left = parseUnary();
        if (!left)
            return Pred();
        for (;;)
        {
            skipSpace();
            if (!peek("&&"))
                break;
            pos += 2;
            Pred right = parseUnary();
            if (!right)
                return Pred();
            Pred l = left, r = right;
            left = [l, r](const Packet& p) { return l(p) && r(p); };
        }
        return left;
    }

    Pred parseUnary()
    {
        skipSpace();
        if (peek("!") && !peek("!=")) // 逻辑非（勿把 "!=" 当成非）
        {
            pos += 1;
            Pred inner = parseUnary();
            if (!inner)
                return Pred();
            Pred i = inner;
            return [i](const Packet& p) { return !i(p); };
        }
        if (peek("("))
        {
            pos += 1;
            Pred r = parseOr();
            if (!r)
                return Pred();
            skipSpace();
            if (pos < src.size() && src[pos] == ')')
                ++pos;
            return r;
        }
        return parsePrimary();
    }

    Pred parsePrimary()
    {
        skipSpace();
        size_t start = pos;
        while (pos < src.size() && (std::isalnum(static_cast<unsigned char>(src[pos])) ||
                                    src[pos] == '.' || src[pos] == '_' || src[pos] == '-'))
            ++pos;
        std::string field = src.substr(start, pos - start);
        if (field.empty())
        {
            setErr("missing field");
            return Pred();
        }
        skipSpace();
        if (pos >= src.size() || (!peek("==") && !peek("!=")))
            return makeExists(field);
        bool negate = peek("!=");
        pos += 2;
        skipSpace();
        size_t vstart = pos;
        while (pos < src.size() && src[pos] != ' ' && src[pos] != '\t' && src[pos] != ')' &&
               src[pos] != '&' && src[pos] != '|')
            ++pos;
        return makeCompare(field, src.substr(vstart, pos - vstart), negate);
    }

    // FIELD ==/!= VALUE：按字段编译成比较闭包（tcp/udp 端口含传输层类型校验）。未知字段→报错返回空。
    Pred makeCompare(const std::string& field, const std::string& value, bool negate)
    {
        Pred eq;
        if (field == "frame.number")
        {
            long v = std::strtol(value.c_str(), nullptr, 10);
            eq = [v](const Packet& p) { return static_cast<long>(p.frame_number) == v; };
        }
        else if (field == "eth.addr")
            eq = [value](const Packet& p) { return p.src_mac == value || p.dst_mac == value; };
        else if (field == "eth.src")
            eq = [value](const Packet& p) { return p.src_mac == value; };
        else if (field == "eth.dst")
            eq = [value](const Packet& p) { return p.dst_mac == value; };
        else if (field == "ip.addr" || field == "ipv6.addr")
            eq = [value](const Packet& p) { return p.src_ip == value || p.dst_ip == value; };
        else if (field == "ip.src" || field == "ipv6.src")
            eq = [value](const Packet& p) { return p.src_ip == value; };
        else if (field == "ip.dst" || field == "ipv6.dst")
            eq = [value](const Packet& p) { return p.dst_ip == value; };
        else if (field == "tcp.port" || field == "udp.port")
        {
            std::string tp = (field.compare(0, 3, "tcp") == 0) ? "TCP" : "UDP";
            long        v  = std::strtol(value.c_str(), nullptr, 10);
            eq             = [tp, v](const Packet& p) {
                return p.transport == tp && (p.src_port == v || p.dst_port == v);
            };
        }
        else if (field == "tcp.srcport" || field == "udp.srcport")
        {
            std::string tp = (field.compare(0, 3, "tcp") == 0) ? "TCP" : "UDP";
            long        v  = std::strtol(value.c_str(), nullptr, 10);
            eq = [tp, v](const Packet& p) { return p.transport == tp && p.src_port == v; };
        }
        else if (field == "tcp.dstport" || field == "udp.dstport")
        {
            std::string tp = (field.compare(0, 3, "tcp") == 0) ? "TCP" : "UDP";
            long        v  = std::strtol(value.c_str(), nullptr, 10);
            eq = [tp, v](const Packet& p) { return p.transport == tp && p.dst_port == v; };
        }
        else
        {
            setErr("unsupported field '" + field + "'");
            return Pred();
        }
        if (negate)
        {
            Pred inner = eq;
            return [inner](const Packet& p) { return !inner(p); };
        }
        return eq;
    }

    // 裸字段：协议/传输层存在性判断。未知字段→报错返回空。
    Pred makeExists(const std::string& f)
    {
        if (f == "tcp") return [](const Packet& p) { return p.transport == "TCP"; };
        if (f == "udp") return [](const Packet& p) { return p.transport == "UDP"; };
        if (f == "arp") return [](const Packet& p) { return p.protocol == "ARP"; };
        if (f == "icmp") return [](const Packet& p) { return p.protocol == "ICMP"; };
        if (f == "icmpv6") return [](const Packet& p) { return p.protocol == "ICMPv6"; };
        if (f == "dns") return [](const Packet& p) { return p.protocol == "DNS"; };
        if (f == "http") return [](const Packet& p) { return p.protocol == "HTTP"; };
        if (f == "tls" || f == "ssl") return [](const Packet& p) { return p.protocol == "TLS"; };
        if (f == "ssh") return [](const Packet& p) { return p.protocol == "SSH"; };
        if (f == "dhcp") return [](const Packet& p) { return p.protocol == "DHCP"; };
        if (f == "ntp") return [](const Packet& p) { return p.protocol == "NTP"; };
        if (f == "ip") return [](const Packet& p) { return !p.src_ip.empty(); };
        if (f == "ipv6")
            return [](const Packet& p) { return p.src_ip.find(':') != std::string::npos; };
        setErr("unsupported field '" + f + "'");
        return Pred();
    }
};
} // namespace

std::function<bool(const Packet&)> compileDisplayFilter(const std::string& expr, std::string* err)
{
    if (err)
        err->clear();
    if (expr.empty())
    {
        if (err)
            *err = "过滤表达式为空";
        return Pred();
    }
    Compiler c(expr, err);
    return c.compile();
}

bool matchDisplayFilter(const std::string& expr, const Packet& packet, std::string* err)
{
    // 单包 API：编译后立即求值一次（大批量求值请用 compileDisplayFilter 复用谓词）。
    std::function<bool(const Packet&)> pred = compileDisplayFilter(expr, err);
    if (!pred)
        return false;
    return pred(packet);
}
} // namespace NativePacketParser
