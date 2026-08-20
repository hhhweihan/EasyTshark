#ifndef NativePacketParser_hpp
#define NativePacketParser_hpp

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "tsharkDataType.hpp"

// 自研协议解析引擎：原始帧字节 → 与 tshark -T fields 对齐的 Packet。供无 tshark 环境兜底。
// 覆盖 Ethernet(VLAN/QinQ) / ARP / IPv4 / IPv6 / ICMP / ICMPv6(ND) / TCP / UDP，
// 应用层 DNS / HTTP / TLS(SNI) / DHCP / NTP / SSH 等；只覆盖展示所需字段，不做完整协议语义。
namespace NativePacketParser
{
// 应用层协议详情（供完整协议树与增强 info 使用）。
struct ProtocolDetail
{
    // HTTP
    bool        http = false;
    std::string httpMethod;  // GET/POST/...
    std::string httpUri;     // /path?query
    std::string httpVersion; // HTTP/1.1
    std::string httpStatus;  // "200"
    std::string httpReason;  // "OK"
    std::string httpHost;    // Host header
    // TLS
    bool        tls = false;
    std::string tlsType;    // "Client Hello" / "Server Hello" / "Certificate" ...
    std::string tlsVersion; // "TLS 1.2" ...
    std::string tlsSni;     // SNI 扩展里的服务器名
    // DNS 响应回答摘要（"A 93.184.216.34, AAAA 2606:... "）
    std::string dnsAnswers;
    // DHCP
    bool        dhcp = false;
    std::string dhcpType; // Discover / Offer / Request / Ack ...
    // NTP
    bool        ntp = false;
    std::string ntpDesc;
    // IP 分片
    bool     ipFragmented = false;
    uint16_t fragOffset   = 0;
    bool     fragMore     = false;
};

// 解析一个原始帧，填充 packet。成功返回 true；帧太短/格式异常返回 false（不抛异常、不崩溃）。
// linkType：0 = NULL/Loopback（BSD lo，前 4 字节地址族），1 = Ethernet，-1 = 自动检测。
bool parseFrame(const unsigned char* data, uint32_t len, Packet& packet, int linkType = -1);

// 完整协议树：从原始帧重建（含应用层分层：HTTP/TLS/DNS/DHCP 子层、IP 分片标记）。
// root 需预先为 DetailNode()（调用方负责）。
bool buildDetailTree(const unsigned char* data, uint32_t len, int linkType, uint32_t frameNumber,
                     DetailNode& root);

// 判断显示过滤表达式是否命中一个报文（自研子集）。
// 支持的字段：
//   frame.number（整数）
//   eth.addr / eth.src / eth.dst（MAC）
//   ip.addr / ip.src / ip.dst / ipv6.addr / ipv6.src / ipv6.dst（IP）
//   tcp.port / tcp.srcport / tcp.dstport / udp.port / udp.srcport / udp.dstport（整数）
//   协议存在性：tcp udp arp icmp icmpv6 dns http tls ssl ssh dhcp ntp（无操作数）
// 操作符：== !=   逻辑：&& || !   支持括号。
// 返回 true 表示表达式合法且命中；expr 非法时置 *err 并返回 false。
bool matchDisplayFilter(const std::string& expr, const Packet& packet,
                        std::string* err = nullptr);

// 把显示过滤表达式「编译一次」为可复用谓词，用于对大量报文反复求值（避免每包重新解析）。
// 表达式非法时置 *err 并返回空 function（转 bool 为 false）。
std::function<bool(const Packet&)> compileDisplayFilter(const std::string& expr,
                                                        std::string* err = nullptr);

// 判断当前是否在无 tshark 环境下也能解析（恒 true——本引擎不依赖外部程序）。
bool available();
} // namespace NativePacketParser

#endif
