#ifndef NativePacketParser_hpp
#define NativePacketParser_hpp

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "tsharkDataType.hpp"

// 自研协议解析引擎：原始帧字节 → 与 tshark -T fields 对齐的 Packet。供无 tshark 环境兜底。
// 覆盖 Ethernet(VLAN/QinQ) / ARP / IPv4 / IPv6(含分片) / ICMP / ICMPv6(ND) / TCP / UDP，
// 应用层 DNS(含压缩指针) / HTTP / TLS(SNI) / DHCP / NTP / SSH(版本交换 banner)，
// 以及汽车诊断 DoIP / UDS / CAN(CAN FD，含 ISO-TP 多帧重组)
// （SocketCAN DLT 227 / 原始 CAN 228 / CAN FD 229 链路）；只覆盖展示所需字段，不做完整协议语义。
namespace NativePacketParser
{
// ISO-TP（ISO 15765-2）跨 CAN 帧重组器：按 can_id 维护挂起会话，把 First Frame + Consecutive Frame
// 序列还原成完整负载（通常是较长的 UDS 报文）。Flow Control 帧不携带负载，不进入会话状态。
// 单帧（SF）不经过此类：parseCan 对 SF 直接原地解析，无需跨帧状态。
class IsoTpReassembler
{
public:
    enum Kind { kNone, kFirstFrame, kConsecutive, kFlowControl };
    struct Result
    {
        Kind     kind      = kNone;
        bool     completed = false; // 本帧是否恰好补满一条完整负载
        uint16_t seq       = 0;     // Consecutive Frame 的序号（低 4 位）
        uint16_t totalLen  = 0;     // First Frame 声明的总长度
        std::vector<unsigned char> payload; // completed 时：重组后的完整负载
    };
    // data/len：该 CAN 帧的数据区（含 ISO-TP PCI 字节）。非 FF/CF/FC 返回 kind=kNone，不改变状态。
    Result feed(uint32_t canId, const unsigned char* data, uint32_t len);

private:
    struct Session
    {
        uint32_t                   expectedLen = 0;
        std::vector<unsigned char> buf;
        uint8_t                    nextSeq = 1;
    };
    std::unordered_map<uint32_t, Session> sessions_;
};

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
    const char* tlsType = nullptr;    // "Client Hello" / "Server Hello" / "Application Data" ...
    const char* tlsVersion = nullptr; // "TLS 1.2" ...（未识别的版本号时为空）
    std::string tlsSni;     // SNI 扩展里的服务器名
    // DNS 响应回答摘要（"A 93.184.216.34, AAAA 2606:... "）
    std::string dnsAnswers;
    // SSH（RFC 4253，仅明文版本交换阶段）
    bool        ssh = false;
    std::string sshVersion; // 版本交换 banner，如 "SSH-2.0-OpenSSH_8.9"
    // DHCP
    bool        dhcp = false;
    const char* dhcpType = nullptr; // Discover / Offer / Request / Ack ...（magic cookie 校验失败时为空）
    // NTP
    bool        ntp = false;
    std::string ntpDesc;
    // DoIP（ISO 13400-2，TCP/UDP 13400 端口）
    bool        doip = false;
    std::string doipVersion;      // 协议版本描述（"ISO 13400-2:2012" 等）
    uint16_t    doipType = 0;     // 负载类型码（0x0001 Vehicle identification request ...）
    const char* doipDesc = nullptr; // 负载类型补充描述（如 ACK 的正/负；仅部分类型有）
    // UDS（ISO 14229-1，DoIP 诊断消息负载或 CAN 报文负载）
    bool        uds = false;
    std::string udsService;   // 服务名 + SID（如 "DiagnosticSessionControl (0x10)"）
    bool        udsResponse = false; // 是否响应帧（正响应 0x40+SID 或负响应 0x7F）
    std::string udsNrc;       // 负响应码名称（0x7F 时，如 "Service not supported"）
    // CAN（SocketCAN DLT 227 / 原始 CAN 228 / CAN FD 229）
    bool        can = false;
    const char* canKind = nullptr; // "CAN" / "CAN FD"（含 BRS/ESI 附加标记）；detail.can 为真时必非空
    uint32_t    canId = 0;    // 去掉 EFF/RTR/ERR 标志后的 CAN ID
    bool        canExtended = false; // 29 位扩展帧（EFF）
    // ISO-TP 多帧（FF/CF/FC；SF 走既有 uds 字段，不设置这组字段）
    bool        isoTpFrame = false;
    const char* isoTpKind = nullptr; // "First Frame" / "Consecutive Frame" / "Flow Control"
    uint16_t    isoTpSeq = 0;        // Consecutive Frame 的序号
    uint16_t    isoTpTotalLen = 0;   // First Frame 声明的总长度
    // IP 分片（IPv4 与 IPv6 Fragment Header 共用）
    bool     ipFragmented = false;
    uint16_t fragOffset   = 0;
    bool     fragMore     = false;
};

// 解析一个原始帧，填充 packet。成功返回 true；帧太短/格式异常返回 false（不抛异常、不崩溃）。
// linkType：0 = NULL/Loopback（BSD lo，前 4 字节地址族），1 = Ethernet，-1 = 自动检测。
// isoTp：非空时用于跨帧累积 ISO-TP 状态（CAN 链路多帧场景），调用方负责在同一序列的帧之间共享同一实例。
bool parseFrame(const unsigned char* data, uint32_t len, Packet& packet, int linkType = -1,
                IsoTpReassembler* isoTp = nullptr);

// 完整协议树：从原始帧重建（含应用层分层：HTTP/TLS/DNS/DHCP/DoIP/UDS/SSH 子层、CAN 层、IP 分片标记）。
// root 需预先为 DetailNode()（调用方负责）。isoTp 语义同 parseFrame。
bool buildDetailTree(const unsigned char* data, uint32_t len, int linkType, uint32_t frameNumber,
                     DetailNode& root, IsoTpReassembler* isoTp = nullptr);

// 仅把一帧 CAN/CAN FD 原始帧喂给重组器（不生成 Packet/DetailNode）。
// 用于按需重建详情树前，重放同一 CAN 链路上先前的帧以预热跨帧状态。
void feedCanFrame(const unsigned char* data, uint32_t len, int linkType, IsoTpReassembler& isoTp);

// 判断显示过滤表达式是否命中一个报文（自研子集）。
// 支持的字段：
//   frame.number（整数）
//   eth.addr / eth.src / eth.dst（MAC）
//   ip.addr / ip.src / ip.dst / ipv6.addr / ipv6.src / ipv6.dst（IP）
//   tcp.port / tcp.srcport / tcp.dstport / udp.port / udp.srcport / udp.dstport（整数）
//   can.id（整数，支持 0x 前缀十六进制）
//   协议存在性：tcp udp arp icmp icmpv6 dns http tls ssl ssh dhcp ntp doip uds can（无操作数）
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
