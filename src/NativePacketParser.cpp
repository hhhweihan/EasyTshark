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
uint32_t rdLe32(const unsigned char* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// 小写十六进制（1/2 字节 → "10" / "8001"）
std::string hex2(uint8_t b)
{
    static const char* digits = "0123456789abcdef";
    char buf[3];
    buf[0] = digits[b >> 4];
    buf[1] = digits[b & 0x0F];
    buf[2] = '\0';
    return std::string(buf);
}

std::string macToStr(const unsigned char* p)
{
    static const char* d = "0123456789abcdef";
    char buf[18];
    int  o = 0;
    for (int i = 0; i < 6; ++i)
    {
        if (i)
            buf[o++] = ':';
        buf[o++] = d[p[i] >> 4];
        buf[o++] = d[p[i] & 0x0F];
    }
    return std::string(buf, static_cast<size_t>(o));
}

std::string ipv4ToStr(const unsigned char* p)
{
    char buf[16];
    int  o = 0;
    for (int i = 0; i < 4; ++i)
    {
        if (i)
            buf[o++] = '.';
        unsigned v = p[i];
        if (v >= 100)
        {
            buf[o++] = static_cast<char>('0' + v / 100);
            v %= 100;
            buf[o++] = static_cast<char>('0' + v / 10);
            buf[o++] = static_cast<char>('0' + v % 10);
        }
        else if (v >= 10)
        {
            buf[o++] = static_cast<char>('0' + v / 10);
            buf[o++] = static_cast<char>('0' + v % 10);
        }
        else
            buf[o++] = static_cast<char>('0' + v);
    }
    return std::string(buf, static_cast<size_t>(o));
}

std::string ipv6ToStr(const unsigned char* p)
{
    static const char* d = "0123456789abcdef";
    char                buf[40];
    int                 o = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (i)
            buf[o++] = ':';
        uint16_t g = rd16(p + i * 2);
        buf[o++]   = d[(g >> 12) & 0xF];
        buf[o++]   = d[(g >> 8) & 0xF];
        buf[o++]   = d[(g >> 4) & 0xF];
        buf[o++]   = d[g & 0xF];
    }
    return std::string(buf, static_cast<size_t>(o));
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
    if (first)
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
        if (port == 13400) return "DoIP"; // ISO 13400-2 车辆发现（UDP）
        if (port == 443) return "QUIC";
    }
    else
    {
        if (port == 80 || port == 8080) return "HTTP";
        if (port == 443 || port == 8443) return "TLS";
        if (port == 13400) return "DoIP"; // ISO 13400-2 诊断 over IP（Tester→ECU）
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
// 解析 DNS 名字（标签序列；遇压缩指针 0xC0xx（RFC 1035 §4.1.4）跟随跳转，在整份报文 base 内查找目标标签）。
// offset：名字在 base 内的起始偏移；consumed：本次调用（含跟随的指针）在「起始位置」处占用的字节数
// （只统计第一段——即指针本身 2 字节，或未遇指针前的标签序列——不含跳转目标处的字节，供上层推进偏移量用）。
// 只允许向后跳（ptr < 当前访问过的最小偏移）并限制跳转次数，防止构造恶意报文时形成死循环。
std::string dnsNameAt(const unsigned char* base, uint32_t totalLen, uint32_t offset,
                      uint32_t& consumed)
{
    std::string name;
    uint32_t    pos          = offset;
    uint32_t    firstConsumed = 0;
    bool        gotFirst     = false;
    int         jumps        = 0;
    for (;;)
    {
        if (pos >= totalLen)
            break;
        uint8_t len = base[pos];
        if (len == 0)
        {
            if (!gotFirst)
            {
                firstConsumed = pos + 1 - offset;
                gotFirst      = true;
            }
            break;
        }
        if ((len & 0xC0) == 0xC0)
        {
            if (pos + 1 >= totalLen || ++jumps > 32)
                break;
            uint32_t ptr = (static_cast<uint32_t>(len & 0x3F) << 8) | base[pos + 1];
            if (!gotFirst)
            {
                firstConsumed = pos + 2 - offset;
                gotFirst      = true;
            }
            if (ptr >= pos)
                break; // 只允许向后跳（严格小于指针自身位置），防止自引用/循环；配合跳转次数上限兜底
            pos = ptr;
            continue;
        }
        ++pos;
        if (pos + len > totalLen)
            break;
        if (!name.empty())
            name += '.';
        for (uint32_t i = 0; i < len; ++i)
            name += static_cast<char>(base[pos + i]);
        pos += len;
    }
    consumed = gotFirst ? firstConsumed : (pos - offset);
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
    std::string name = dnsNameAt(payload, len, off, consumed);
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
    for (uint16_t i = 0; i < qd; ++i)
    {
        if (off >= len)
            return out;
        uint32_t consumed = 0;
        dnsNameAt(payload, len, off, consumed);
        off += consumed + 4; // qtype + qclass
    }
    for (uint16_t i = 0; i < an && i < anMax; ++i)
    {
        if (off + 10 > len)
            break;
        uint32_t consumed = 0;
        dnsNameAt(payload, len, off, consumed);
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
            // 传入整份报文 base + rdata 的绝对偏移（而非局部切片），使压缩指针能跟随到报文其它位置。
            uint32_t c = 0;
            std::string n = dnsNameAt(payload, len, off + 10, c);
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

    const char* recordType = "Unknown"; // 保证 detail.tls 为真时 tlsType 全程非空
    if (rtype == 0x16) // Handshake
    {
        if (len < 6)
            return;
        unsigned char hsType = payload[5];
        const char*   hsName = "Handshake";
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
        default: break;
        }
        recordType = hsName;
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
        recordType = "Application Data";
    }
    else if (rtype == 0x15)
    {
        recordType = "Alert";
    }
    else if (rtype == 0x14)
    {
        recordType = "Change Cipher Spec";
    }
    detail.tlsType = recordType;
    char buf[128];
    if (!detail.tlsSni.empty())
        std::snprintf(buf, sizeof(buf), "%s, %s, SNI=%s", recordType, version ? version : "TLS",
                      detail.tlsSni.c_str());
    else
        std::snprintf(buf, sizeof(buf), "%s, %s", recordType, version ? version : "TLS");
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

// ---- SSH（RFC 4253 §4.2）----
// 版本交换阶段以明文单行 banner 开始："SSH-protoversion-softwareversion[ comments]\r\n"（上限 255 字节）。
// 交换完成后转入二进制协议且通常加密，本引擎不解密，只识别这条 banner 行。
void parseSsh(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    detail.ssh = true;
    if (len >= 4 && std::memcmp(payload, "SSH-", 4) == 0)
    {
        uint32_t scanLen = len > 255 ? 255 : len;
        const unsigned char* nl = static_cast<const unsigned char*>(
            std::memchr(payload, '\n', scanLen));
        uint32_t lineLen = nl ? static_cast<uint32_t>(nl - payload) : scanLen;
        if (lineLen > 0 && payload[lineLen - 1] == '\r')
            --lineLen;
        detail.sshVersion.assign(reinterpret_cast<const char*>(payload), lineLen);
        packet.info = "Protocol: " + detail.sshVersion;
        return;
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), "Encrypted Packet (len=%u)", len);
    packet.info = buf;
}

// ---- DoIP（ISO 13400-2）/ UDS（ISO 14229-1）/ CAN ----
const char* doipPayloadTypeName(uint16_t t)
{
    switch (t)
    {
    case 0x0000: return "Generic DoIP header negative acknowledge";
    case 0x0001: return "Vehicle identification request";
    case 0x0002: return "Vehicle identification request with EID";
    case 0x0003: return "Vehicle identification request with VIN";
    case 0x0004: return "Vehicle identification response";
    case 0x0005: return "Routing activation request";
    case 0x0006: return "Routing activation response";
    case 0x0007: return "Alive check request";
    case 0x0008: return "Alive check response";
    case 0x4001: return "DoIP entity status request";
    case 0x4002: return "DoIP entity status response";
    case 0x4003: return "Diagnostic power mode information request";
    case 0x4004: return "Diagnostic power mode information response";
    case 0x8001: return "Diagnostic message";
    case 0x8002: return "Diagnostic message positive acknowledgement";
    case 0x8003: return "Diagnostic message negative acknowledgement";
    case 0x8004: return "Diagnostic message (ISO 13400-2:2016)";
    default: return "Unknown";
    }
}

const char* udsServiceName(uint8_t sid)
{
    switch (sid)
    {
    case 0x10: return "DiagnosticSessionControl";
    case 0x11: return "ECUReset";
    case 0x14: return "ClearDiagnosticInformation";
    case 0x19: return "ReadDTCInformation";
    case 0x22: return "ReadDataByIdentifier";
    case 0x23: return "ReadMemoryByAddress";
    case 0x24: return "ReadScalingDataByIdentifier";
    case 0x27: return "SecurityAccess";
    case 0x28: return "CommunicationControl";
    case 0x29: return "Authentication";
    case 0x2A: return "ReadDataByPeriodicIdentifier";
    case 0x2C: return "DynamicallyDefineDataIdentifier";
    case 0x2E: return "WriteDataByIdentifier";
    case 0x2F: return "InputOutputControlByIdentifier";
    case 0x31: return "RoutineControl";
    case 0x34: return "RequestDownload";
    case 0x35: return "RequestUpload";
    case 0x36: return "TransferData";
    case 0x37: return "RequestTransferExit";
    case 0x38: return "RequestFileTransfer";
    case 0x3D: return "WriteMemoryByAddress";
    case 0x3E: return "TesterPresent";
    case 0x83: return "AccessTimingParameter";
    case 0x84: return "SecuredDataTransmission";
    case 0x85: return "ControlDTCSetting";
    case 0x86: return "ResponseOnEvent";
    case 0x87: return "LinkControl";
    default: return "Unknown";
    }
}

const char* udsNrcName(uint8_t nrc)
{
    switch (nrc)
    {
    case 0x00: return "No error";
    case 0x10: return "General reject";
    case 0x11: return "Service not supported";
    case 0x12: return "Sub-function not supported";
    case 0x13: return "Incorrect message length or invalid format";
    case 0x14: return "Response too long";
    case 0x21: return "Busy repeat request";
    case 0x22: return "Conditions not correct";
    case 0x24: return "Request sequence error";
    case 0x25: return "No response from subnet component";
    case 0x26: return "Failure prevents execution of requested action";
    case 0x31: return "Request out of range";
    case 0x33: return "Security access denied";
    case 0x34: return "Authentication failed";
    case 0x35: return "Invalid key";
    case 0x36: return "Exceeded number of attempts";
    case 0x37: return "Required time delay not expired";
    case 0x70: return "Upload/download not accepted";
    case 0x71: return "Transfer data suspended";
    case 0x72: return "General programming failure";
    case 0x73: return "Wrong block sequence counter";
    case 0x78: return "Request correctly received - response pending";
    case 0x7E: return "Sub-function not supported in active session";
    case 0x7F: return "Service not supported in active session";
    case 0x81: return "Voltage too high";
    case 0x82: return "Voltage too low";
    default: return "Unknown";
    }
}

// UDS（ISO 14229-1）负载：首字节 SID。请求 SID 0x10~0x87；正响应 = SID+0x40；
// 负响应 SID=0x7F（后随原 SID 与 NRC）。
void parseUds(const unsigned char* p, uint32_t len, ProtocolDetail& detail)
{
    if (!p || len < 1)
        return;
    uint8_t sid = p[0];
    detail.uds  = true;
    char    buf[96];
    if (sid == 0x7F)
    {
        detail.udsResponse = true;
        if (len >= 2)
        {
            std::snprintf(buf, sizeof(buf), "Negative response: %s (0x%02x)", udsServiceName(p[1]),
                          p[1]);
            detail.udsService = buf;
        }
        else
            detail.udsService = "Negative response";
        if (len >= 3)
        {
            std::snprintf(buf, sizeof(buf), "%s (0x%02x)", udsNrcName(p[2]), p[2]);
            detail.udsNrc = buf;
        }
        return;
    }
    if ((sid & 0x40) != 0)
    {
        detail.udsResponse = true;
        uint8_t reqSid      = static_cast<uint8_t>(sid & 0xBF);
        std::snprintf(buf, sizeof(buf), "Positive response: %s (0x%02x)", udsServiceName(reqSid),
                      reqSid);
        detail.udsService = buf;
        return;
    }
    std::snprintf(buf, sizeof(buf), "%s (0x%02x)", udsServiceName(sid), sid);
    detail.udsService = buf;
}

// 已知 UDS 服务 SID（请求/正响应/负响应），用于判定 CAN 数据区是否为 UDS 负载（降低误报）。
bool isKnownUdsSid(uint8_t b)
{
    if (b == 0x7F)
        return true;
    if ((b & 0x40) != 0)
        b = static_cast<uint8_t>(b & 0xBF); // 正响应：回退到请求 SID
    switch (b)
    {
    case 0x10: case 0x11: case 0x14: case 0x19: case 0x22: case 0x23: case 0x24:
    case 0x27: case 0x28: case 0x29: case 0x2A: case 0x2C: case 0x2E: case 0x2F:
    case 0x31: case 0x34: case 0x35: case 0x36: case 0x37: case 0x38: case 0x3D:
    case 0x3E: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        return true;
    default: return false;
    }
}

// DoIP（ISO 13400-2）帧头：ver(1) invVer(1) payloadType(2) payloadLen(4)，网络字节序。
// 诊断消息（0x8001/0x8004）负载 = 源地址(2) + 目标地址(2) + UDS。
void parseDoip(const unsigned char* payload, uint32_t len, Packet& packet, ProtocolDetail& detail)
{
    if (!payload || len < 8)
        return;
    uint8_t  ver    = payload[0];
    uint8_t  invVer = payload[1];
    uint16_t type   = rd16(payload + 2);
    uint32_t plen   = rd32(payload + 4);
    if (ver + invVer != 0xFF) // 版本 + 反码校验（0x02+0xFD / 0x03+0xFC）
        return;
    detail.doip      = true;
    detail.doipType  = type;
    detail.doipVersion = (ver == 0x02) ? "ISO 13400-2:2012"
                         : (ver == 0x03) ? "ISO 13400-2:2016"
                                         : "v" + std::to_string(ver);
    if (plen > len - 8)
        plen = len - 8;
    const unsigned char* body = payload + 8;

    if (type == 0x8001 || type == 0x8004) // 诊断消息（源/目标地址 + UDS）
    {
        uint32_t udsOff = (plen >= 4) ? 4 : 0;
        if (plen > udsOff)
            parseUds(body + udsOff, plen - udsOff, detail);
    }
    else if (type == 0x8002 && plen >= 1) // 诊断消息 ACK：ackCode(1) + ...
    {
        detail.doipDesc = (body[0] == 0x00) ? "Diagnostic message ACK (positive)"
                                            : "Diagnostic message ACK (negative)";
    }

    char buf[200];
    const char* name = doipPayloadTypeName(type);
    if (detail.uds)
    {
        if (detail.udsNrc.empty())
            std::snprintf(buf, sizeof(buf), "%s, %s", name, detail.udsService.c_str());
        else
            std::snprintf(buf, sizeof(buf), "%s, %s, NRC %s", name, detail.udsService.c_str(),
                          detail.udsNrc.c_str());
    }
    else
        std::snprintf(buf, sizeof(buf), "%s (type=0x%04x, len=%u)", name, type, plen);
    packet.info     = buf;
    packet.protocol = detail.uds ? "UDS" : "DoIP";
    packet.is_doip  = true;
}

std::string canDataHex(const unsigned char* d, uint32_t n)
{
    std::string s;
    uint32_t show = n > 8 ? 8 : n;
    for (uint32_t i = 0; i < show; ++i)
    {
        if (i)
            s += ' ';
        s += hex2(d[i]);
    }
    if (n > show)
        s += " ...";
    return s;
}

// 提取 CAN/CAN FD 帧的 ID 与数据区（不含 ISO-TP/UDS 语义），parseCan 与 feedCanFrame 共用。链路布局：
//   DLT 227（SocketCAN）：8 字节头 can_id(4, LE) + flags/len(4) + data（偏移 8 起）。
//   DLT 228（原始 CAN）：4 字节 can_id(LE，高 3 位 EFF/RTR/ERR) + 数据（经典 ≤8）。
//   DLT 229（原始 CAN FD）：同 228，数据可达 64 字节。
// can_id 高 3 位标志：0x80000000=EFF（扩展帧） 0x40000000=RTR 0x20000000=ERR。
bool extractCanPayload(const unsigned char* data, uint32_t len, int linkType, uint32_t& canId,
                       bool& extended, const unsigned char*& dptr, uint32_t& dlen)
{
    if (!data || len < 4)
        return false;
    if (linkType == 227)
    {
        if (len < 8)
            return false;
        uint32_t raw = rdLe32(data);
        canId        = raw & 0x1FFFFFFF;
        extended     = (raw & 0x80000000) != 0;
        dptr = data + 8;
        dlen = len - 8;
    }
    else // DLT 228 / 229
    {
        uint32_t raw = rdLe32(data);
        canId        = raw & 0x1FFFFFFF;
        extended     = (raw & 0x80000000) != 0;
        uint32_t maxD = (linkType == 229) ? 64 : 8;
        dptr = data + 4;
        dlen = len - 4;
        if (dlen > maxD)
            dlen = maxD;
    }
    return true;
}

// CAN 帧解析（含 ISO-TP 单帧/多帧解包后识别 UDS 负载）。
// isoTp：非空时用于 FF/CF/FC 跨帧重组；为空时仍能识别帧类型，但不会累积/完成多帧重组。
void parseCan(const unsigned char* data, uint32_t len, int linkType, Packet& packet,
              ProtocolDetail& detail, IsoTpReassembler* isoTp)
{
    uint32_t canId = 0;
    bool     extended = false;
    const unsigned char* dptr = nullptr;
    uint32_t              dlen = 0;
    if (!extractCanPayload(data, len, linkType, canId, extended, dptr, dlen))
        return;
    detail.can          = true;
    detail.canId        = canId;
    detail.canExtended  = extended;
    packet.can_id       = canId;

    uint32_t    dlc  = dlen;
    const char* kind = "CAN";
    if (linkType == 227)
    {
        unsigned char flags = data[4];
        bool          isFd  = (flags & 0x80) != 0; // CANFD_FDF
        dlc = isFd ? data[5] : (flags & 0x0F);
        if (dlc > dlen)
            dlc = dlen;
        if (isFd)
        {
            bool brs = (flags & 0x01) != 0, esi = (flags & 0x02) != 0;
            kind = (brs && esi) ? "CAN FD BRS ESI" : brs ? "CAN FD BRS" : esi ? "CAN FD ESI"
                                                                              : "CAN FD";
        }
    }
    else if (linkType == 229)
        kind = "CAN FD";
    detail.canKind = kind;

    // ISO-TP（ISO 15765-2）与直接 UDS 的判定天然存在歧义：ISO-TP 的 PCI 字节（FF=0x1x/CF=0x2x/
    // FC=0x3x）与 UDS SID 空间（几乎覆盖 0x10~0x3E）完全重叠，单看首字节无法可靠区分。这里沿用
    // 既有的「长度前缀」启发式——先按 SF 语义尝试解出一个已知 SID；命中则认定是不走 ISO-TP 封装、
    // 直接携带 UDS 的帧（覆盖原 ParsesRawCan/ParsesUdsOverCanSingleFrame 两类用例，逻辑不变）。
    // 只有这个启发式没命中时，才按 PCI 高 4 位识别 FF/CF/FC 做跨帧重组——保证像 FF 的 0x10 这种
    // 「PCI 字节恰好等于某个 SID」的合法 ISO-TP 帧不会被误判为直接 UDS。
    uint8_t pci = (dlen >= 1) ? static_cast<uint8_t>(dptr[0] & 0xF0) : 0xFFu;
    uint32_t udsOff = 0, udsLen = dlen;
    if (dlen >= 2 && (dptr[0] & 0x0F) <= dlen - 1)
    {
        udsOff = 1;
        udsLen = dptr[0] & 0x0F;
    }
    if (udsLen >= 1 && isKnownUdsSid(dptr[udsOff]))
    {
        parseUds(dptr + udsOff, udsLen, detail);
    }
    else if (pci == 0x10 || pci == 0x20 || pci == 0x30) // FF/CF/FC：跨帧重组
    {
        detail.isoTpFrame = true;
        IsoTpReassembler local; // 无重组器时的兜底：仅无状态识别帧类型，不会误报 completed
        IsoTpReassembler::Result r = isoTp ? isoTp->feed(canId, dptr, dlen)
                                            : local.feed(canId, dptr, dlen);
        detail.isoTpKind = (pci == 0x10) ? "First Frame"
                          : (pci == 0x20) ? "Consecutive Frame"
                                          : "Flow Control";
        detail.isoTpSeq      = (pci == 0x20) ? static_cast<uint16_t>(dptr[0] & 0x0F) : 0;
        detail.isoTpTotalLen = r.totalLen;
        if (r.completed && !r.payload.empty() && isKnownUdsSid(r.payload[0]))
            parseUds(r.payload.data(), static_cast<uint32_t>(r.payload.size()), detail);
    }

    char buf[160];
    if (detail.uds)
    {
        std::snprintf(buf, sizeof(buf), "%s 0x%03x, %s", detail.canKind, detail.canId,
                      detail.udsService.c_str());
        packet.protocol = "UDS";
    }
    else if (detail.isoTpFrame)
    {
        if (pci == 0x10)
            std::snprintf(buf, sizeof(buf), "%s 0x%03x ISO-TP First Frame, Len=%u",
                          detail.canKind, detail.canId, detail.isoTpTotalLen);
        else if (pci == 0x20)
            std::snprintf(buf, sizeof(buf), "%s 0x%03x ISO-TP Consecutive Frame, Seq=%u",
                          detail.canKind, detail.canId, detail.isoTpSeq);
        else
            std::snprintf(buf, sizeof(buf), "%s 0x%03x ISO-TP Flow Control", detail.canKind,
                          detail.canId);
        packet.protocol = detail.canKind;
    }
    else
    {
        if (detail.canExtended)
            std::snprintf(buf, sizeof(buf), "%s 0x%08x DLC=%u %s", detail.canKind, detail.canId,
                          dlc, canDataHex(dptr, dlen).c_str());
        else
            std::snprintf(buf, sizeof(buf), "%s 0x%03x DLC=%u %s", detail.canKind, detail.canId,
                          dlc, canDataHex(dptr, dlen).c_str());
        packet.protocol = detail.canKind;
    }
    packet.info = buf;
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

    const unsigned char* app = data + tcpLen;
    if (appLen > 0 && packet.protocol == "HTTP")
        parseHttp(app, appLen, packet, detail);
    else if (appLen > 0 && packet.protocol == "TLS")
        parseTls(app, appLen, packet, detail);
    else if (appLen > 0 && packet.protocol == "DoIP")
        parseDoip(app, appLen, packet, detail);
    else if (appLen > 0 && packet.protocol == "SSH")
        parseSsh(app, appLen, packet, detail);

    if (detail.http || detail.tls || detail.doip || detail.ssh)
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
    if (packet.protocol == "DoIP" && appLen > 0)
    {
        parseDoip(app, appLen, packet, detail);
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
               const unsigned char*& payload, uint32_t& payloadLen, ProtocolDetail& detail)
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
        if (proto == 44) // Fragment Header：next(1) reserved(1) fragOffset+flags(2) id(4)
        {
            if (off + 8 > len)
                break;
            uint16_t fragField = rd16(data + off + 2);
            detail.fragMore     = (fragField & 0x0001) != 0;
            detail.fragOffset   = static_cast<uint16_t>((fragField & 0xFFF8));
            detail.ipFragmented = detail.fragOffset != 0 || detail.fragMore;
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
        if (!parseIpv6(payload, payloadLen, packet, proto, payload, payloadLen, detail))
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

bool parseFrameCtx(const unsigned char* data, uint32_t len, int linkType, Packet& packet,
                   ProtocolDetail& detail, IsoTpReassembler* isoTp)
{
    if (!data || len < 4)
        return false;

    // CAN 链路（SocketCAN 227 / 原始 CAN 228 / CAN FD 229）：帧长可小于以太网最小 14 字节，提前分派
    if (linkType == 227 || linkType == 228 || linkType == 229)
    {
        parseCan(data, len, linkType, packet, detail, isoTp);
        return true;
    }

    if (len < 14)
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
            if (!parseIpv6(payload, payloadLen, packet, proto, payload, payloadLen, detail))
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

IsoTpReassembler::Result IsoTpReassembler::feed(uint32_t canId, const unsigned char* data,
                                                uint32_t len)
{
    Result r;
    if (!data || len < 1)
        return r;
    uint8_t pci = static_cast<uint8_t>(data[0] & 0xF0);
    if (pci == 0x10) // First Frame：低 4 位 + 下一字节 = 12 位总长度
    {
        if (len < 2)
            return r;
        r.kind     = kFirstFrame;
        r.totalLen = static_cast<uint16_t>(((data[0] & 0x0F) << 8) | data[1]);
        Session& s = sessions_[canId]; // 新首帧覆盖同 ID 上未完成的旧会话
        s          = Session();
        s.expectedLen = r.totalLen;
        uint32_t avail = len - 2;
        uint32_t take  = avail < s.expectedLen ? avail : s.expectedLen;
        s.buf.assign(data + 2, data + 2 + take);
        s.nextSeq = 1;
    }
    else if (pci == 0x20) // Consecutive Frame
    {
        r.kind = kConsecutive;
        r.seq  = data[0] & 0x0F;
        auto it = sessions_.find(canId);
        if (it == sessions_.end())
            return r; // 没有对应的首帧：孤立 CF，忽略（不崩溃）
        Session& s = it->second;
        uint32_t remain = s.expectedLen > s.buf.size()
                              ? s.expectedLen - static_cast<uint32_t>(s.buf.size())
                              : 0;
        uint32_t avail = len - 1;
        uint32_t take  = avail < remain ? avail : remain;
        s.buf.insert(s.buf.end(), data + 1, data + 1 + take);
        s.nextSeq = static_cast<uint8_t>((s.nextSeq + 1) & 0x0F);
        if (s.buf.size() >= s.expectedLen)
        {
            r.completed = true;
            r.payload   = s.buf;
            sessions_.erase(it);
        }
    }
    else if (pci == 0x30)
    {
        r.kind = kFlowControl; // 流控帧不携带负载，不进入会话状态
    }
    return r;
}

void feedCanFrame(const unsigned char* data, uint32_t len, int linkType, IsoTpReassembler& isoTp)
{
    uint32_t canId = 0;
    bool     extended = false;
    const unsigned char* dptr = nullptr;
    uint32_t              dlen = 0;
    if (!extractCanPayload(data, len, linkType, canId, extended, dptr, dlen))
        return;
    if (dlen >= 1)
        isoTp.feed(canId, dptr, dlen); // 仅预热重组状态；SF/FC 对重组器天然 no-op
}

bool parseFrame(const unsigned char* data, uint32_t len, Packet& packet, int linkType,
                IsoTpReassembler* isoTp)
{
    ProtocolDetail detail;
    return parseFrameCtx(data, len, linkType, packet, detail, isoTp);
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
                     DetailNode& root, IsoTpReassembler* isoTp)
{
    Packet p;
    ProtocolDetail detail;
    if (!parseFrameCtx(data, len, linkType, p, detail, isoTp))
        return false;
    p.frame_number = frameNumber;

    root.label = "Frame " + std::to_string(frameNumber);
    char buf[128];

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

    // CAN 层（SocketCAN / 原始 CAN / CAN FD 链路帧）
    if (detail.can)
    {
        DetailNode cn;
        cn.label = "Controller Area Network";
        char cbuf[32];
        if (detail.canExtended)
            std::snprintf(cbuf, sizeof(cbuf), "0x%08x", detail.canId);
        else
            std::snprintf(cbuf, sizeof(cbuf), "0x%03x", detail.canId);
        addChild(cn, "ID", cbuf);
        addChild(cn, "Kind", detail.canKind);
        if (detail.isoTpFrame && !detail.uds)
        {
            addChild(cn, "ISO-TP", detail.isoTpKind);
            if (detail.isoTpKind[0] == 'F') // First Frame
                addChild(cn, "Declared Length", std::to_string(detail.isoTpTotalLen));
            else if (detail.isoTpKind[0] == 'C') // Consecutive Frame
                addChild(cn, "Sequence", std::to_string(detail.isoTpSeq));
        }
        addChild(cn, "Info", p.info);
        root.children.push_back(cn);
    }
    else if (p.transport == "TCP" || p.transport == "UDP")
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
    if (detail.doip)
    {
        DetailNode dp;
        dp.label = "Diagnostic over IP";
        addChild(dp, "Version", detail.doipVersion);
        std::snprintf(buf, sizeof(buf), "%s (0x%04x)",
                      detail.doipDesc ? detail.doipDesc : doipPayloadTypeName(detail.doipType),
                      detail.doipType);
        addChild(dp, "Payload Type", buf);
        if (detail.uds)
        {
            DetailNode ud;
            ud.label = "Unified Diagnostic Services";
            addChild(ud, "Service", detail.udsService);
            if (!detail.udsNrc.empty())
                addChild(ud, "Negative Response Code", detail.udsNrc);
            dp.children.push_back(ud);
        }
        root.children.push_back(dp);
    }
    else if (detail.uds) // CAN 负载上的 UDS（ISO-TP 单帧）
    {
        DetailNode ud;
        ud.label = "Unified Diagnostic Services";
        addChild(ud, "Service", detail.udsService);
        if (!detail.udsNrc.empty())
            addChild(ud, "Negative Response Code", detail.udsNrc);
        root.children.push_back(ud);
    }
    else if (detail.http)
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
        if (detail.tlsVersion)
            addChild(tl, "Version", detail.tlsVersion);
        if (!detail.tlsSni.empty())
            addChild(tl, "Server Name Indication", detail.tlsSni);
        root.children.push_back(tl);
    }
    else if (detail.ssh)
    {
        DetailNode sh;
        sh.label = "SSH Protocol";
        if (!detail.sshVersion.empty())
            addChild(sh, "Protocol", detail.sshVersion);
        else
            addChild(sh, "Info", p.info);
        root.children.push_back(sh);
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
        addChild(dh, "Message Type", detail.dhcpType ? detail.dhcpType : "?");
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
        else if (field == "can.id") // 支持 0x 前缀十六进制或十进制
        {
            unsigned long v = std::strtoul(value.c_str(), nullptr, 0);
            eq = [v](const Packet& p) { return p.can_id != 0 && p.can_id == v; };
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
        if (f == "doip") return [](const Packet& p) { return p.is_doip; };
        if (f == "uds") return [](const Packet& p) { return p.protocol == "UDS"; };
        if (f == "can")
            // 匹配 CAN / CAN FD / CAN FD BRS 等（canKind 前缀均为 "CAN"）
            return [](const Packet& p) { return p.protocol.compare(0, 3, "CAN") == 0; };
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
