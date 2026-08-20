#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "NativeAnalyzer.hpp"
#include "NativeCapture.hpp"
#include "NativePacketParser.hpp"

// 自研引擎（无 tshark 兜底）单元测试：全部用构造的字节流验证，
// 不依赖 tshark、不依赖真实网卡，可在任何环境运行。

namespace
{
// ---- 字节拼装工具 ----
void pushByte(std::vector<unsigned char>& v, unsigned char b) { v.push_back(b); }
void pushBE16(std::vector<unsigned char>& v, uint16_t x)
{
    v.push_back(static_cast<unsigned char>(x >> 8));
    v.push_back(static_cast<unsigned char>(x & 0xff));
}
void pushBE32(std::vector<unsigned char>& v, uint32_t x)
{
    v.push_back(static_cast<unsigned char>(x >> 24));
    v.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
    v.push_back(static_cast<unsigned char>(x & 0xff));
}
void pushBytes(std::vector<unsigned char>& v, const std::vector<unsigned char>& src)
{
    v.insert(v.end(), src.begin(), src.end());
}
void pushHex(std::vector<unsigned char>& v, const char* hex)
{
    while (*hex)
    {
        auto nib = [](char c) -> unsigned char {
            return (c >= '0' && c <= '9') ? static_cast<unsigned char>(c - '0')
                                          : static_cast<unsigned char>(c - 'a' + 10);
        };
        v.push_back(static_cast<unsigned char>((nib(hex[0]) << 4) | nib(hex[1])));
        hex += 2;
    }
}

// Ethernet 头：dst(6) src(6) type(2)
std::vector<unsigned char> ethHeader(uint16_t ethertype)
{
    std::vector<unsigned char> v;
    pushHex(v, "00112233445566778899aabb");
    pushBE16(v, ethertype);
    return v;
}

// IPv4 头（ihl=5）：src/dst + protocol
std::vector<unsigned char> ipv4Header(const char* src, const char* dst, uint8_t proto,
                                      uint16_t totalLen)
{
    std::vector<unsigned char> v;
    pushByte(v, 0x45);
    pushByte(v, 0x00);
    pushBE16(v, totalLen);
    pushBE16(v, 0x0000); // id
    pushBE16(v, 0x4000); // flags + frag
    pushByte(v, 64);     // ttl
    pushByte(v, proto);
    pushBE16(v, 0x0000); // checksum（不校验）
    unsigned a, b, c, d;
    std::sscanf(src, "%u.%u.%u.%u", &a, &b, &c, &d);
    pushByte(v, static_cast<unsigned char>(a));
    pushByte(v, static_cast<unsigned char>(b));
    pushByte(v, static_cast<unsigned char>(c));
    pushByte(v, static_cast<unsigned char>(d));
    std::sscanf(dst, "%u.%u.%u.%u", &a, &b, &c, &d);
    pushByte(v, static_cast<unsigned char>(a));
    pushByte(v, static_cast<unsigned char>(b));
    pushByte(v, static_cast<unsigned char>(c));
    pushByte(v, static_cast<unsigned char>(d));
    return v;
}

// TCP 头（offset=5）：src/dst port + flags
std::vector<unsigned char> tcpHeader(uint16_t srcPort, uint16_t dstPort, unsigned char flags)
{
    std::vector<unsigned char> v;
    pushBE16(v, srcPort);
    pushBE16(v, dstPort);
    pushBE32(v, 1);     // seq
    pushBE32(v, 0);     // ack
    pushByte(v, 0x50);  // offset 5
    pushByte(v, flags);
    pushBE16(v, 64240); // win
    pushBE16(v, 0);     // checksum
    pushBE16(v, 0);     // urgent pointer（凑满 20 字节标准头）
    return v;
}

// UDP 头
std::vector<unsigned char> udpHeader(uint16_t srcPort, uint16_t dstPort, uint16_t len)
{
    std::vector<unsigned char> v;
    pushBE16(v, srcPort);
    pushBE16(v, dstPort);
    pushBE16(v, len);
    pushBE16(v, 0);
    return v;
}

// 完整 TCP SYN 帧：192.168.1.10:12345 → 93.184.216.34:80
std::vector<unsigned char> tcpSynFrame()
{
    auto eth = ethHeader(0x0800);
    auto ip  = ipv4Header("192.168.1.10", "93.184.216.34", 6, 40);
    auto tcp = tcpHeader(12345, 80, 0x02);
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, tcp);
    return frame;
}

// 完整 DNS 查询帧：192.168.1.10:53000 → 8.8.8.8:53 查询 example.com A
std::vector<unsigned char> dnsQueryFrame()
{
    auto eth = ethHeader(0x0800);
    // DNS payload：id=0x1234 flags=0x0100 qd=1；name "example.com"；qtype A(1) qclass IN(1)
    std::vector<unsigned char> dns;
    pushBE16(dns, 0x1234);
    pushBE16(dns, 0x0100);
    pushBE16(dns, 1); // QDCOUNT
    pushBE16(dns, 0); // ANCOUNT
    pushBE16(dns, 0);
    pushBE16(dns, 0);
    pushByte(dns, 7);
    pushHex(dns, "6578616d706c65"); // "example"
    pushByte(dns, 3);
    pushHex(dns, "636f6d"); // "com"
    pushByte(dns, 0);
    pushBE16(dns, 1); // qtype A
    pushBE16(dns, 1); // qclass IN
    uint16_t udpLen = static_cast<uint16_t>(8 + dns.size());
    auto     udp    = udpHeader(53000, 53, udpLen);
    auto     ip     = ipv4Header("192.168.1.10", "8.8.8.8", 17, static_cast<uint16_t>(20 + udpLen));
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, udp);
    pushBytes(frame, dns);
    return frame;
}

// ARP 请求帧
std::vector<unsigned char> arpFrame()
{
    std::vector<unsigned char> frame = ethHeader(0x0806);
    pushBE16(frame, 1);    // htype ethernet
    pushBE16(frame, 0x0800);
    pushByte(frame, 6);
    pushByte(frame, 4);
    pushBE16(frame, 1); // request
    pushHex(frame, "001122334455"); // sha
    pushHex(frame, "c0a80101");     // spa 192.168.1.1
    pushHex(frame, "000000000000"); // tha
    pushHex(frame, "c0a80164");     // tpa 192.168.1.100
    return frame;
}

// VLAN 标签的 IPv4 帧
std::vector<unsigned char> vlanFrame()
{
    auto frame = ethHeader(0x8100);
    pushBE16(frame, 0x0064); // TCI（VID=100）
    pushBE16(frame, 0x0800); // 内层 ethertype
    auto ip = ipv4Header("10.0.0.1", "10.0.0.2", 6, 40);
    pushBytes(frame, ip);
    pushBytes(frame, tcpHeader(1000, 2000, 0x10));
    return frame;
}

// IPv6 + TCP 帧
std::vector<unsigned char> ipv6Frame()
{
    std::vector<unsigned char> frame = ethHeader(0x86dd);
    // 固定头：version/tc/flow=0x60000000, payload len=20, next=6, hop=64
    pushBE32(frame, 0x60000000);
    pushBE16(frame, 20);
    pushByte(frame, 6);
    pushByte(frame, 64);
    // src fe80::1, dst fe80::2
    pushHex(frame, "fe800000000000000000000000000001");
    pushHex(frame, "fe800000000000000000000000000002");
    pushBytes(frame, tcpHeader(443, 5555, 0x12)); // SYN+ACK
    return frame;
}

// 小端写 uint32（pcap 记录头用）
void pushLe32(std::vector<unsigned char>& v, uint32_t x)
{
    v.push_back(static_cast<unsigned char>(x & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 24) & 0xff));
}
void pushLe16(std::vector<unsigned char>& v, uint16_t x)
{
    v.push_back(static_cast<unsigned char>(x & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
}

// 经典 pcap 文件（小端）：2 包
std::vector<unsigned char> makePcapFile(const std::vector<unsigned char>& f1,
                                        const std::vector<unsigned char>& f2)
{
    std::vector<unsigned char> v;
    pushLe32(v, 0xa1b2c3d4); // magic
    pushLe16(v, 2);
    pushLe16(v, 4);
    pushLe32(v, 0); // thiszone
    pushLe32(v, 0); // sigfigs
    pushLe32(v, 65535);
    pushLe32(v, 1); // LINKTYPE_ETHERNET
    // record 1
    pushLe32(v, 1); // ts_sec
    pushLe32(v, 500000);
    pushLe32(v, static_cast<uint32_t>(f1.size()));
    pushLe32(v, static_cast<uint32_t>(f1.size()));
    pushBytes(v, f1);
    // record 2
    pushLe32(v, 1);
    pushLe32(v, 600000);
    pushLe32(v, static_cast<uint32_t>(f2.size()));
    pushLe32(v, static_cast<uint32_t>(f2.size()));
    pushBytes(v, f2);
    return v;
}

// 指定链路类型的单包 pcap（小端），供 CAN 等非以太网链路测试
std::vector<unsigned char> makePcapFileLinkType(uint32_t linkType,
                                                const std::vector<unsigned char>& f1)
{
    std::vector<unsigned char> v;
    pushLe32(v, 0xa1b2c3d4);
    pushLe16(v, 2);
    pushLe16(v, 4);
    pushLe32(v, 0);
    pushLe32(v, 0);
    pushLe32(v, 65535);
    pushLe32(v, linkType);
    pushLe32(v, 1); // ts_sec
    pushLe32(v, 0);
    pushLe32(v, static_cast<uint32_t>(f1.size()));
    pushLe32(v, static_cast<uint32_t>(f1.size()));
    pushBytes(v, f1);
    return v;
}

// ---- 汽车协议帧构造 ----
// DoIP 帧：Ethernet/IPv4/TCP(13400) + DoIP 头（ISO 13400-2:2012）+ 负载
std::vector<unsigned char> doipTcpFrame(uint16_t payloadType,
                                        const std::vector<unsigned char>& body)
{
    std::vector<unsigned char> doip;
    pushByte(doip, 0x02); // version
    pushByte(doip, 0xFD); // inverse version
    pushBE16(doip, payloadType);
    pushBE32(doip, static_cast<uint32_t>(body.size()));
    pushBytes(doip, body);
    uint16_t tcpLen = static_cast<uint16_t>(20 + doip.size());
    auto     eth    = ethHeader(0x0800);
    auto     ip     = ipv4Header("192.168.1.10", "192.168.1.20", 6,
                                 static_cast<uint16_t>(20 + tcpLen));
    auto tcp = tcpHeader(49152, 13400, 0x18); // PSH+ACK
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, tcp);
    pushBytes(frame, doip);
    return frame;
}

// SocketCAN（DLT 227）经典帧：can_id(LE) + DLC + 数据（数据区从偏移 8 起）
std::vector<unsigned char> canSocketcanFrame(uint32_t canId, uint8_t dlc,
                                             const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> v;
    pushLe32(v, canId);
    pushByte(v, dlc);
    pushByte(v, 0); // pad
    pushByte(v, 0); // res0
    pushByte(v, 0); // len8_dlc
    pushBytes(v, data);
    return v;
}

// SocketCAN（DLT 227）CAN FD 帧：can_id(LE) + flags + len + 数据
std::vector<unsigned char> canFdSocketcanFrame(uint32_t canId, uint8_t flags, uint8_t len,
                                               const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> v;
    pushLe32(v, canId);
    pushByte(v, flags);
    pushByte(v, len);
    pushByte(v, 0); // res0
    pushByte(v, 0); // res1
    pushBytes(v, data);
    return v;
}

// 原始 CAN（DLT 228/229）：can_id(LE，高 3 位 EFF/RTR/ERR 标志) + 数据
std::vector<unsigned char> rawCanFrame(uint32_t canId, const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> v;
    pushLe32(v, canId);
    pushBytes(v, data);
    return v;
}
} // namespace

// ---- NativePacketParser ----
TEST(NativeParserTest, ParsesTcpSyn)
{
    auto frame = tcpSynFrame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.src_mac, "66:77:88:99:aa:bb");
    EXPECT_EQ(p.dst_mac, "00:11:22:33:44:55");
    EXPECT_EQ(p.src_ip, "192.168.1.10");
    EXPECT_EQ(p.dst_ip, "93.184.216.34");
    EXPECT_EQ(p.src_port, 12345);
    EXPECT_EQ(p.dst_port, 80);
    EXPECT_EQ(p.transport, "TCP");
    EXPECT_EQ(p.protocol, "HTTP"); // 80 端口识别
    EXPECT_NE(p.info.find("12345"), std::string::npos);
    EXPECT_NE(p.info.find("[SYN]"), std::string::npos);
}

TEST(NativeParserTest, ParsesDnsQuery)
{
    auto frame = dnsQueryFrame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.dst_port, 53);
    EXPECT_NE(p.info.find("example.com"), std::string::npos);
    EXPECT_NE(p.info.find("0x1234"), std::string::npos);
}

TEST(NativeParserTest, ParsesArp)
{
    auto frame = arpFrame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "ARP");
    EXPECT_NE(p.info.find("192.168.1.100"), std::string::npos);
}

TEST(NativeParserTest, ParsesVlan)
{
    auto frame = vlanFrame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.src_ip, "10.0.0.1");
    EXPECT_EQ(p.src_port, 1000);
    EXPECT_EQ(p.transport, "TCP");
}

TEST(NativeParserTest, ParsesIpv6)
{
    auto frame = ipv6Frame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_NE(p.src_ip.find("fe80"), std::string::npos);
    EXPECT_EQ(p.src_port, 443);
    EXPECT_EQ(p.transport, "TCP");
}

TEST(NativeParserTest, RejectsTruncatedFrame)
{
    auto frame = tcpSynFrame();
    Packet p;
    // 只给 5 字节：不足以太网头
    EXPECT_FALSE(NativePacketParser::parseFrame(frame.data(), 5, p));
}


TEST(NativeParserTest, ParsesNullLoopbackFrame)
{
    // BSD lo 接口：4 字节小端地址族（AF_INET=2）+ IPv4/TCP
    std::vector<unsigned char> frame;
    pushByte(frame, 0x02); pushByte(frame, 0); pushByte(frame, 0); pushByte(frame, 0);
    pushBytes(frame, ipv4Header("127.0.0.1", "127.0.0.1", 6, 40));
    pushBytes(frame, tcpHeader(5000, 80, 0x02));
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.src_ip, "127.0.0.1");
    EXPECT_EQ(p.dst_port, 80);
    EXPECT_EQ(p.transport, "TCP");
    EXPECT_EQ(p.protocol, "HTTP");
    // 无以太网头：MAC 应为空
    EXPECT_TRUE(p.src_mac.empty());
    // 显式 linkType=0（NULL）也应解析
    Packet p2;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p2, 0));
    EXPECT_EQ(p2.src_ip, "127.0.0.1");
}

TEST(NativeParserTest, BuildsDetailTree)
{
    auto frame = tcpSynFrame();
    DetailNode root;
    ASSERT_TRUE(NativePacketParser::buildDetailTree(frame.data(),
                                                    static_cast<uint32_t>(frame.size()), 1, 7,
                                                    root));
    EXPECT_EQ(root.label, "Frame 7");
    ASSERT_GE(root.children.size(), 3u); // Ethernet + IP + TCP
    EXPECT_EQ(root.children[0].label, "Ethernet II");
    EXPECT_EQ(root.children[1].label, "Internet Protocol Version 4");
    EXPECT_EQ(root.children[2].label, "Transmission Control Protocol");
}

TEST(NativeParserTest, DisplayFilterBasics)
{
    auto tcpFrame = tcpSynFrame();
    auto dnsFrame = dnsQueryFrame();
    auto arp      = arpFrame();
    Packet tcpP, dnsP, arpP;
    NativePacketParser::parseFrame(tcpFrame.data(), static_cast<uint32_t>(tcpFrame.size()), tcpP);
    NativePacketParser::parseFrame(dnsFrame.data(), static_cast<uint32_t>(dnsFrame.size()), dnsP);
    NativePacketParser::parseFrame(arp.data(), static_cast<uint32_t>(arp.size()), arpP);

    std::string err;
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("ip.src==192.168.1.10", tcpP, &err));
    EXPECT_TRUE(err.empty());
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("tcp.port==80", tcpP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("tcp.port==12345", tcpP, &err));
    EXPECT_FALSE(NativePacketParser::matchDisplayFilter("tcp.port==99", tcpP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("dns", dnsP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("ip.addr==8.8.8.8 && dns", dnsP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("!tcp", arpP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("arp", arpP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("arp || tcp", arpP, &err));
    EXPECT_FALSE(NativePacketParser::matchDisplayFilter("frame.number==5", tcpP, &err));

    // 非法字段：报错且返回 false
    std::string badErr;
    EXPECT_FALSE(NativePacketParser::matchDisplayFilter("no.such.field==1", tcpP, &badErr));
    EXPECT_FALSE(badErr.empty());
}

// ---- 汽车协议：DoIP / UDS / CAN ----
TEST(NativeParserTest, ParsesDoipUdsRequest)
{
    // 诊断消息（0x8001）：源地址(2) + 目标地址(2) + UDS（DiagnosticSessionControl 请求）
    std::vector<unsigned char> body;
    pushBE16(body, 0x0E80); // 源逻辑地址
    pushBE16(body, 0x0001); // 目标逻辑地址
    pushByte(body, 0x10);   // SID DiagnosticSessionControl
    pushByte(body, 0x03);   // 子功能 extendedDiagnosticSession
    auto frame = doipTcpFrame(0x8001, body);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "UDS");
    EXPECT_EQ(p.dst_port, 13400);
    EXPECT_NE(p.info.find("DiagnosticSessionControl"), std::string::npos);
    EXPECT_NE(p.info.find("0x10"), std::string::npos);
}

TEST(NativeParserTest, ParsesDoipRoutingActivation)
{
    // 路由激活请求（0x0005），无 UDS 负载
    std::vector<unsigned char> body;
    pushByte(body, 0x0E);
    pushByte(body, 0x80);
    pushByte(body, 0x00); // 激活类型
    pushByte(body, 0x00);
    pushByte(body, 0x00); // 保留
    pushByte(body, 0x00);
    pushByte(body, 0x00); // 保留
    pushByte(body, 0x00);
    auto frame = doipTcpFrame(0x0005, body);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DoIP");
    EXPECT_NE(p.info.find("Routing activation request"), std::string::npos);
    EXPECT_NE(p.info.find("0x0005"), std::string::npos);
}

TEST(NativeParserTest, ParsesDoipUdsNegativeResponse)
{
    // UDS 负响应：7F <SID> <NRC>
    std::vector<unsigned char> body;
    pushBE16(body, 0x0E80);
    pushBE16(body, 0x0001);
    pushByte(body, 0x7F); // 负响应
    pushByte(body, 0x10); // 原服务
    pushByte(body, 0x31); // NRC RequestOutOfRange
    auto frame = doipTcpFrame(0x8001, body);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "UDS");
    EXPECT_NE(p.info.find("Negative response"), std::string::npos);
    EXPECT_NE(p.info.find("Request out of range"), std::string::npos);
}

TEST(NativeParserTest, ParsesCanSocketcan)
{
    std::vector<unsigned char> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto frame = canSocketcanFrame(0x123, 0x08, data);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 227));
    EXPECT_EQ(p.protocol, "CAN");
    EXPECT_EQ(p.can_id, 0x123u);
    EXPECT_NE(p.info.find("0x123"), std::string::npos);
    EXPECT_NE(p.info.find("DLC=8"), std::string::npos);
    EXPECT_NE(p.info.find("01 02 03 04"), std::string::npos);
}

TEST(NativeParserTest, ParsesCanFdSocketcan)
{
    std::vector<unsigned char> data(64, 0xAA);
    auto frame = canFdSocketcanFrame(0x1FED, 0x80, 64, data); // FDF=0x80 → CAN FD
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 227));
    EXPECT_EQ(p.protocol, "CAN FD");
    EXPECT_EQ(p.can_id, 0x1FEDu);
    EXPECT_NE(p.info.find("CAN FD"), std::string::npos);
}

TEST(NativeParserTest, ParsesUdsOverCanSingleFrame)
{
    // CAN 0x123 上的 ISO-TP 单帧：PCI=0x02（长度 2），UDS = 3E 00（TesterPresent）
    std::vector<unsigned char> data;
    pushHex(data, "023e000000000000");
    auto frame = canSocketcanFrame(0x123, 0x08, data);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 227));
    EXPECT_EQ(p.protocol, "UDS");
    EXPECT_EQ(p.can_id, 0x123u);
    EXPECT_NE(p.info.find("TesterPresent"), std::string::npos);
}

TEST(NativeParserTest, ParsesRawCan)
{
    // 数据区不以已知 UDS SID 开头 → 按普通 CAN 帧解析
    std::vector<unsigned char> data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    auto frame = rawCanFrame(0x456, data);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 228));
    EXPECT_EQ(p.protocol, "CAN");
    EXPECT_EQ(p.can_id, 0x456u);
    EXPECT_NE(p.info.find("0x456"), std::string::npos);
    // 29 位扩展帧（EFF 标志）
    auto ext = rawCanFrame(0x80000000 | 0x1FED123, data);
    Packet pe;
    ASSERT_TRUE(NativePacketParser::parseFrame(ext.data(), static_cast<uint32_t>(ext.size()), pe,
                                               228));
    EXPECT_EQ(pe.can_id, 0x1FED123u);
    EXPECT_NE(pe.info.find("0x01fed123"), std::string::npos);
    // 原始 CAN 上携带 UDS（数据区以已知 SID 0x3E 开头）
    std::vector<unsigned char> udsData = {0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto uframe = rawCanFrame(0x7E0, udsData);
    Packet pu;
    ASSERT_TRUE(NativePacketParser::parseFrame(uframe.data(),
                                               static_cast<uint32_t>(uframe.size()), pu, 228));
    EXPECT_EQ(pu.protocol, "UDS");
    EXPECT_NE(pu.info.find("TesterPresent"), std::string::npos);
}

TEST(NativeParserTest, AutomotiveDisplayFilters)
{
    std::vector<unsigned char> body;
    pushBE16(body, 0x0E80);
    pushBE16(body, 0x0001);
    pushByte(body, 0x3E); // TesterPresent
    pushByte(body, 0x00);
    auto doip = doipTcpFrame(0x8001, body);
    std::vector<unsigned char> canData = {0, 0, 0, 0, 0, 0, 0, 0};
    auto can  = canSocketcanFrame(0x123, 8, canData);
    Packet doipP, canP;
    ASSERT_TRUE(NativePacketParser::parseFrame(doip.data(), static_cast<uint32_t>(doip.size()),
                                               doipP));
    ASSERT_TRUE(NativePacketParser::parseFrame(can.data(), static_cast<uint32_t>(can.size()), canP,
                                               227));
    std::string err;
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("doip", doipP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("uds", doipP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("doip || uds", doipP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("can", canP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("can.id==0x123", canP, &err));
    EXPECT_TRUE(NativePacketParser::matchDisplayFilter("can.id==291", canP, &err)); // 十进制
    EXPECT_FALSE(NativePacketParser::matchDisplayFilter("can.id==0x124", canP, &err));
    EXPECT_FALSE(NativePacketParser::matchDisplayFilter("doip", canP, &err));
    EXPECT_TRUE(err.empty());
}

// ---- NativeAnalyzer（离线 pcap 解析）----
class NativeAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        auto f1 = tcpSynFrame();
        auto f2 = dnsQueryFrame();
        auto bytes = makePcapFile(f1, f2);
        pcapPath_  = "test_data/native_test.pcap";
        std::ofstream out(pcapPath_.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        out.close();
        f1Bytes_ = f1;
        f2Bytes_ = f2;
    }
    void TearDown() override { std::remove(pcapPath_.c_str()); }

    std::string pcapPath_;
    std::vector<unsigned char> f1Bytes_, f2Bytes_;
};

TEST_F(NativeAnalyzerTest, AnalyzesPcapAndHex)
{
    NativeAnalyzer analyzer;
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analyzeFile(pcapPath_, packets));
    ASSERT_EQ(packets.size(), 2u);

    EXPECT_EQ(packets[0]->frame_number, 1);
    EXPECT_EQ(packets[0]->src_ip, "192.168.1.10");
    EXPECT_EQ(packets[0]->protocol, "HTTP");
    EXPECT_EQ(packets[1]->frame_number, 2);
    EXPECT_EQ(packets[1]->protocol, "DNS");
    EXPECT_NEAR(packets[0]->time, 1.5, 1e-6);
    EXPECT_NEAR(packets[1]->time, 1.6, 1e-6);

    // hex：与写入的原始帧逐字节一致
    std::vector<unsigned char> hex;
    ASSERT_TRUE(analyzer.getPacketHexData(1, hex));
    ASSERT_EQ(hex.size(), f1Bytes_.size());
    EXPECT_EQ(std::memcmp(hex.data(), f1Bytes_.data(), hex.size()), 0);

    std::vector<unsigned char> hex2;
    ASSERT_TRUE(analyzer.getPacketHexData(2, hex2));
    EXPECT_EQ(std::memcmp(hex2.data(), f2Bytes_.data(), hex2.size()), 0);

    // 不存在的帧号
    std::vector<unsigned char> empty;
    EXPECT_FALSE(analyzer.getPacketHexData(99, empty));

    // 详情树
    DetailNode root;
    ASSERT_TRUE(analyzer.getPacketDetailTree(1, root));
    EXPECT_EQ(root.label, "Frame 1");

    // 显示过滤：两个包 src_ip 都是 192.168.1.10
    std::vector<uint32_t> frames;
    ASSERT_TRUE(analyzer.getFramesByDisplayFilter("ip.addr==192.168.1.10", frames));
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0], 1);
    EXPECT_EQ(frames[1], 2);

    std::string err;
    std::vector<uint32_t> bad;
    EXPECT_FALSE(analyzer.getFramesByDisplayFilter("bogus.field==1", bad, &err));
    EXPECT_FALSE(err.empty());
}

TEST_F(NativeAnalyzerTest, AnalyzesCanLinkTypePcap)
{
    // 链路类型 227（SocketCAN）的 pcap：解析 CAN 帧 + 详情树 + 显示过滤
    std::vector<unsigned char> data;
    pushHex(data, "023e000000000000"); // ISO-TP 单帧：TesterPresent
    auto canFrame = canSocketcanFrame(0x123, 8, data);
    auto bytes    = makePcapFileLinkType(227, canFrame);
    std::string canPath = "test_data/native_can.pcap";
    {
        std::ofstream out(canPath.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    NativeAnalyzer analyzer;
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analyzeFile(canPath, packets));
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0]->protocol, "UDS");
    EXPECT_EQ(packets[0]->can_id, 0x123u);
    EXPECT_NE(packets[0]->info.find("TesterPresent"), std::string::npos);

    DetailNode root;
    ASSERT_TRUE(analyzer.getPacketDetailTree(1, root));
    bool hasCan = false, hasUds = false;
    for (const auto& c : root.children)
    {
        if (c.label == "Controller Area Network")
            hasCan = true;
        if (c.label == "Unified Diagnostic Services")
            hasUds = true;
    }
    EXPECT_TRUE(hasCan);
    EXPECT_TRUE(hasUds);

    std::vector<uint32_t> frames;
    ASSERT_TRUE(analyzer.getFramesByDisplayFilter("can.id==0x123 && uds", frames));
    ASSERT_EQ(frames.size(), 1u);
    std::remove(canPath.c_str());
}

// ---- AnalysisSession native 集成（无 tshark 时后端自动降级）----
#include "AnalysisSession.hpp"

TEST(NativeSessionIntegration, WorksWithoutTshark)
{
    // 传无效 tshark 路径：构造函数内 tsharkAvailable=false → 启用自研引擎
    AnalysisSession session("/nonexistent/tshark", "test_data/ns_data");

    // 用 NativeAnalyzerTest 同款 pcap（2 包）
    auto f1 = tcpSynFrame();
    auto f2 = dnsQueryFrame();
    auto bytes = makePcapFile(f1, f2);
    std::string pcapPath = "test_data/ns_load.pcap";
    {
        std::ofstream out(pcapPath.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    ASSERT_TRUE(session.loadPcap(pcapPath));
    EXPECT_EQ(session.packetCount(), 2u);

    // hex（native reader）
    std::vector<unsigned char> hex;
    ASSERT_TRUE(session.getHex(1, hex));
    EXPECT_EQ(hex.size(), f1.size());

    // 详情树（自研分层）
    DetailNode root;
    ASSERT_TRUE(session.getDetailTree(1, root));
    EXPECT_EQ(root.label, "Frame 1");

    // 显示过滤（自研子集）
    std::vector<std::shared_ptr<Packet>> out;
    ASSERT_TRUE(session.queryDisplayFilter("tcp.port==80", out));
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0]->src_ip, "192.168.1.10");

    // 非法表达式：自研引擎报"unsupported field"
    std::string err;
    EXPECT_FALSE(session.queryDisplayFilter("bogus.field==1", out, &err));
    EXPECT_FALSE(err.empty());

    // 网卡枚举（libpcap）：不崩溃即可（可能因权限为空，不做非空断言）
    session.listAdapters();

    // SQLite 条件查询（native 模式同样入库）
    std::string jsonResult;
    std::map<std::string, std::string> cond;
    cond["ip_address"] = "192.168.1.*";
    ASSERT_TRUE(session.query(cond, jsonResult));
    EXPECT_NE(jsonResult.find("192.168.1.10"), std::string::npos);

    std::remove(pcapPath.c_str());
    // 清理 ns_data 目录
    std::remove("test_data/ns_data/pcaps/capture_1.pcap");
}

// savePcapAs：另存到尚不存在的多层目录时应自动创建父目录（mkdir -p 语义）。
TEST(NativeSessionSaveAs, CreatesNestedDirs)
{
    AnalysisSession session("/nonexistent/tshark", "test_data/save_data");

    auto        bytes    = makePcapFile(tcpSynFrame(), dnsQueryFrame());
    std::string pcapPath = "test_data/save_src.pcap";
    {
        std::ofstream out(pcapPath.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    ASSERT_TRUE(session.loadPcap(pcapPath));

    // 目标目录 test_data/save_out/a/b 事先不存在——savePcapAs 应自动补齐后再拷贝。
    std::string dest = "test_data/save_out/a/b/copy.pcap";
    ASSERT_TRUE(session.savePcapAs(dest));

    std::ifstream check(dest.c_str(), std::ios::binary);
    ASSERT_TRUE(check.good());
    check.seekg(0, std::ios::end);
    EXPECT_EQ(static_cast<size_t>(check.tellg()), bytes.size()); // 内容完整拷贝
    check.close();

    // 目标即源：短路视为成功，不报错。
    EXPECT_TRUE(session.savePcapAs(session.pcapPath()));

    // 清理
    std::remove(dest.c_str());
    std::remove("test_data/save_out/a/b");
    std::remove("test_data/save_out/a");
    std::remove("test_data/save_out");
    std::remove(pcapPath.c_str());
    std::remove("test_data/save_data/pcaps/capture_1.pcap");
}

// ---- 应用层协议测试 helper ----
// 完整以太网帧：eth + ipv4 + tcp + payload
std::vector<unsigned char> tcpPayloadFrame(const char* srcIp, const char* dstIp,
                                           uint16_t srcPort, uint16_t dstPort,
                                           const std::vector<unsigned char>& payload,
                                           bool fragMF = false)
{
    uint16_t total = static_cast<uint16_t>(20 + 20 + payload.size());
    auto     eth   = ethHeader(0x0800);
    auto     ip    = ipv4Header(srcIp, dstIp, 6, total);
    if (fragMF)
        ip[6] = 0x20; // flags MF（大端字段：flags 在字节 6-7 高 4 位）
    auto     tcp   = tcpHeader(srcPort, dstPort, 0x18); // PSH+ACK
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, tcp);
    pushBytes(frame, payload);
    return frame;
}

// 以太网 + IPv4 + UDP + payload
std::vector<unsigned char> udpPayloadFrame(const char* srcIp, const char* dstIp,
                                           uint16_t srcPort, uint16_t dstPort,
                                           const std::vector<unsigned char>& payload)
{
    uint16_t udpLen = static_cast<uint16_t>(8 + payload.size());
    auto     eth    = ethHeader(0x0800);
    auto     ip     = ipv4Header(srcIp, dstIp, 17, static_cast<uint16_t>(20 + udpLen));
    auto     udp    = udpHeader(srcPort, dstPort, udpLen);
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, udp);
    pushBytes(frame, payload);
    return frame;
}

std::vector<unsigned char> strVec(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

// ---- HTTP ----
TEST(NativeParserTest, ParsesHttpRequest)
{
    auto payload = strVec("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n");
    auto frame   = tcpPayloadFrame("192.168.1.10", "93.184.216.34", 5000, 80, payload);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "HTTP");
    EXPECT_NE(p.info.find("GET /index.html"), std::string::npos);
    EXPECT_NE(p.info.find("example.com"), std::string::npos);

    // 完整详情树含 HTTP 层
    DetailNode root;
    ASSERT_TRUE(NativePacketParser::buildDetailTree(frame.data(),
                                                    static_cast<uint32_t>(frame.size()), 1, 1,
                                                    root));
    bool hasHttp = false;
    for (const auto& c : root.children)
        if (c.label == "Hypertext Transfer Protocol") hasHttp = true;
    EXPECT_TRUE(hasHttp);
}

TEST(NativeParserTest, ParsesHttpResponse)
{
    auto payload = strVec("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 10\r\n\r\n");
    auto frame   = tcpPayloadFrame("93.184.216.34", "192.168.1.10", 80, 5000, payload);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "HTTP");
    EXPECT_NE(p.info.find("200"), std::string::npos);
    EXPECT_NE(p.info.find("OK"), std::string::npos);
}

// ---- TLS ClientHello + SNI ----
TEST(NativeParserTest, ParsesTlsClientHelloWithSni)
{
    std::vector<unsigned char> tls;
    // record: handshake(0x16) TLS1.2(0303) len
    pushByte(tls, 0x16); pushByte(tls, 0x03); pushByte(tls, 0x03);
    pushBE16(tls, 64); // record payload = handshake 4 + body 60
    // handshake: ClientHello(1) + length(3 字节)
    pushByte(tls, 0x01);
    pushByte(tls, 0x00); pushByte(tls, 0x00); pushByte(tls, 0x3c);
    // body: version 0303 + random 32 + sessionId len 0
    pushByte(tls, 0x03); pushByte(tls, 0x03);
    for (int i = 0; i < 32; ++i) pushByte(tls, 0x11);
    pushByte(tls, 0x00);
    // cipher suites: len 2, 0xc02f
    pushBE16(tls, 2); pushBE16(tls, 0xc02f);
    // compression: len 0
    pushByte(tls, 0x00);
    // extensions total: 20
    pushBE16(tls, 20);
    // SNI ext: type 0, len 16: listLen 14, nameType 0, nameLen 11, "example.com"
    pushBE16(tls, 0); pushBE16(tls, 16);
    pushBE16(tls, 14); pushByte(tls, 0); pushBE16(tls, 11);
    pushHex(tls, "6578616d706c652e636f6d"); // example.com

    auto frame = tcpPayloadFrame("192.168.1.10", "93.184.216.34", 5000, 443, tls);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "TLS");
    EXPECT_NE(p.info.find("Client Hello"), std::string::npos);
    EXPECT_NE(p.info.find("example.com"), std::string::npos);
    EXPECT_NE(p.info.find("TLS 1.2"), std::string::npos);
}

// ---- DNS 响应 ----
TEST(NativeParserTest, ParsesDnsResponse)
{
    std::vector<unsigned char> dns;
    pushBE16(dns, 0xabcd); // id
    pushBE16(dns, 0x8180); // response + RD + RA
    pushBE16(dns, 1); // QDCOUNT
    pushBE16(dns, 1); // ANCOUNT
    pushBE16(dns, 0);
    pushBE16(dns, 0);
    // question: example.com A IN
    pushByte(dns, 7); pushHex(dns, "6578616d706c65");
    pushByte(dns, 3); pushHex(dns, "636f6d");
    pushByte(dns, 0);
    pushBE16(dns, 1); pushBE16(dns, 1);
    // answer: name ptr 0xc00c, A, class IN, ttl 300, rdlen 4, 93.184.216.34
    pushHex(dns, "c00c");
    pushBE16(dns, 1); pushBE16(dns, 1); pushBE32(dns, 300); pushBE16(dns, 4);
    pushHex(dns, "5db8d822");

    auto frame = udpPayloadFrame("8.8.8.8", "192.168.1.10", 53, 53000, dns);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("query response"), std::string::npos);
    EXPECT_NE(p.info.find("A 93.184.216.34"), std::string::npos);
}

// ---- DHCP Discover ----

TEST(NativeParserTest, ParsesDnsResponseMultipleAnswers)
{
    std::vector<unsigned char> dns;
    pushBE16(dns, 0x1234);
    pushBE16(dns, 0x8180);
    pushBE16(dns, 1); // QD
    pushBE16(dns, 2); // AN = 2 条
    pushBE16(dns, 0); pushBE16(dns, 0);
    // question: example.com A
    pushByte(dns, 7); pushHex(dns, "6578616d706c65");
    pushByte(dns, 3); pushHex(dns, "636f6d");
    pushByte(dns, 0); pushBE16(dns, 1); pushBE16(dns, 1);
    // answer1: A 93.184.216.34
    pushHex(dns, "c00c"); pushBE16(dns, 1); pushBE16(dns, 1);
    pushBE32(dns, 300); pushBE16(dns, 4); pushHex(dns, "5db8d822");
    // answer2: AAAA 2606:...
    pushHex(dns, "c00c"); pushBE16(dns, 28); pushBE16(dns, 1);
    pushBE32(dns, 300); pushBE16(dns, 16); pushHex(dns, "26060000000000000000000000000064");

    uint16_t udpLen = static_cast<uint16_t>(8 + dns.size());
    auto     eth    = ethHeader(0x0800);
    auto     ip     = ipv4Header("8.8.8.8", "192.168.1.10", 17, static_cast<uint16_t>(20 + udpLen));
    auto     udp    = udpHeader(53, 53000, udpLen);
    std::vector<unsigned char> frame;
    pushBytes(frame, eth);
    pushBytes(frame, ip);
    pushBytes(frame, udp);
    pushBytes(frame, dns);

    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("A 93.184.216.34"), std::string::npos);
    // 第二条 AAAA 也应在摘要里
    EXPECT_NE(p.info.find("AAAA 2606"), std::string::npos);
}

TEST(NativeParserTest, ParsesDhcpDiscover)
{
    std::vector<unsigned char> dhcp;
    pushByte(dhcp, 0x01); // op request
    pushByte(dhcp, 0x01); // htype
    pushByte(dhcp, 0x06); // hlen
    pushByte(dhcp, 0x00); // hops
    pushBE32(dhcp, 0x12345678); // xid
    pushBE16(dhcp, 0); pushBE16(dhcp, 0); // secs flags
    for (int i = 0; i < 4; ++i) pushBE32(dhcp, 0); // ciaddr yiaddr siaddr giaddr
    for (int i = 0; i < 16; ++i) pushByte(dhcp, 0xaa); // chaddr
    for (int i = 0; i < 64; ++i) pushByte(dhcp, 0);    // sname
    for (int i = 0; i < 128; ++i) pushByte(dhcp, 0);   // file
    pushHex(dhcp, "63825363"); // magic cookie
    pushByte(dhcp, 53); pushByte(dhcp, 1); pushByte(dhcp, 1); // option 53 = Discover
    pushByte(dhcp, 50); pushByte(dhcp, 4); pushHex(dhcp, "c0a80164"); // option 50 requested IP
    pushByte(dhcp, 255); // end

    auto frame = udpPayloadFrame("0.0.0.0", "255.255.255.255", 68, 67, dhcp);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DHCP");
    EXPECT_NE(p.info.find("Discover"), std::string::npos);
}

// ---- ICMPv6 邻居请求 ----
TEST(NativeParserTest, ParsesIcmpv6NeighborSolicitation)
{
    std::vector<unsigned char> frame = ethHeader(0x86dd);
    pushBE32(frame, 0x60000000);
    pushBE16(frame, 32); // payload len = icmpv6 8 + target 16 = 24? 用 24
    // 修正：payload 是 ICMPv6 头 4 + target 16 = 20，但按 32 构造只影响 len 字段，不校验
    pushByte(frame, 58); // next header ICMPv6
    pushByte(frame, 64);
    pushHex(frame, "fe800000000000000000000000000001");
    pushHex(frame, "fe800000000000000000000000000002");
    // ICMPv6: type 135 (NS) code 0
    pushByte(frame, 135); pushByte(frame, 0);
    pushBE16(frame, 0); // checksum（不校验）
    pushHex(frame, "0000000000000000"); // reserved
    pushHex(frame, "fe8000000000000000000000000000aa"); // target

    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "ICMPv6");
    EXPECT_NE(p.info.find("Neighbor solicitation"), std::string::npos);
}

// ---- IP 分片 ----
TEST(NativeParserTest, MarksIpFragment)
{
    auto payload = strVec("fragment payload");
    auto frame   = tcpPayloadFrame("192.168.1.10", "93.184.216.34", 5000, 80, payload, true);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "HTTP");
    // 分片标记体现在详情树（Fragment 行）
    DetailNode root;
    ASSERT_TRUE(NativePacketParser::buildDetailTree(frame.data(),
                                                    static_cast<uint32_t>(frame.size()), 1, 1,
                                                    root));
    bool hasFrag = false;
    for (const auto& layer : root.children)
        if (layer.label.find("Internet Protocol") != std::string::npos)
            for (const auto& f : layer.children)
                if (f.label == "Fragment") hasFrag = true;
    EXPECT_TRUE(hasFrag);
}

// ---- 经典 pcap 大端格式 ----
// 与 makePcapFile 同布局，但 magic 与所有头字段按大端写入（magic 0xa1b2c3d4 在盘上即
// a1 b2 c3 d4）。验证 NativeAnalyzer 的大端分支与小端分支解析结果一致。
std::vector<unsigned char> makePcapFileBE(const std::vector<unsigned char>& f1,
                                          const std::vector<unsigned char>& f2)
{
    std::vector<unsigned char> v;
    pushBE32(v, 0xa1b2c3d4); // magic（大端在盘上为 a1 b2 c3 d4）
    pushBE16(v, 2);
    pushBE16(v, 4);
    pushBE32(v, 0);
    pushBE32(v, 0);
    pushBE32(v, 65535);
    pushBE32(v, 1); // LINKTYPE_ETHERNET
    // record 1：ts 1.5s（sec=1, usec=500000）
    pushBE32(v, 1);
    pushBE32(v, 500000);
    pushBE32(v, static_cast<uint32_t>(f1.size()));
    pushBE32(v, static_cast<uint32_t>(f1.size()));
    pushBytes(v, f1);
    // record 2：ts 1.6s
    pushBE32(v, 1);
    pushBE32(v, 600000);
    pushBE32(v, static_cast<uint32_t>(f2.size()));
    pushBE32(v, static_cast<uint32_t>(f2.size()));
    pushBytes(v, f2);
    return v;
}

TEST(NativeAnalyzerBE, ParsesBigEndianPcap)
{
    auto f1    = tcpSynFrame();
    auto f2    = dnsQueryFrame();
    auto bytes = makePcapFileBE(f1, f2);

    std::string path = "test_data/native_be.pcap";
    {
        std::ofstream out(path.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    NativeAnalyzer analyzer;
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analyzeFile(path, packets));
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_EQ(packets[0]->src_ip, "192.168.1.10");
    EXPECT_EQ(packets[0]->protocol, "HTTP");
    EXPECT_EQ(packets[1]->protocol, "DNS");
    EXPECT_NEAR(packets[0]->time, 1.5, 1e-6);
    EXPECT_NEAR(packets[1]->time, 1.6, 1e-6);

    // hex 与写入帧逐字节一致（大端读记录头不应影响数据区）
    std::vector<unsigned char> hex;
    ASSERT_TRUE(analyzer.getPacketHexData(1, hex));
    ASSERT_EQ(hex.size(), f1.size());
    EXPECT_EQ(std::memcmp(hex.data(), f1.data(), hex.size()), 0);

    std::remove(path.c_str());
}

// ---- pcapng（SHB + IDB[if_tsresol] + EPB）----
// 构造一个最小 pcapng：接口时间戳分辨率设为毫秒（if_tsresol=3 → 除数 1e3），
// EPB 时间戳 tick=1500 → 期望解析出的 time = 1.5s。验证 IDB 选项解析 + EPB 帧解析。
std::vector<unsigned char> makePcapNgFile(const std::vector<unsigned char>& frame)
{
    std::vector<unsigned char> v;

    // ---- SHB ----
    pushLe32(v, 0x0A0D0D0A); // block type
    pushLe32(v, 28);         // total length
    pushLe32(v, 0x1A2B3C4D); // byte-order magic（小端）
    pushLe16(v, 1);          // major
    pushLe16(v, 0);          // minor
    pushLe32(v, 0xffffffff); // section length low（-1 = 未知）
    pushLe32(v, 0xffffffff); // section length high
    pushLe32(v, 28);         // total length（尾部重复）

    // ---- IDB（带 if_tsresol=3）----
    // body: linktype(2) reserved(2) snaplen(4) + opt(if_tsresol) 8 + opt_endofopt 4 = 20
    // block = 8(头) + 20 + 4(尾) = 32
    pushLe32(v, 0x00000001); // block type IDB
    pushLe32(v, 32);         // total length
    pushLe16(v, 1);          // linktype = Ethernet
    pushLe16(v, 0);          // reserved
    pushLe32(v, 65535);      // snaplen
    // option if_tsresol：code=9 len=1 value=3（毫秒），补齐到 4 字节
    pushLe16(v, 9);
    pushLe16(v, 1);
    pushByte(v, 3);
    pushByte(v, 0); pushByte(v, 0); pushByte(v, 0); // padding
    // opt_endofopt
    pushLe16(v, 0);
    pushLe16(v, 0);
    pushLe32(v, 32); // total length（尾部重复）

    // ---- EPB ----
    // body: interface(4) tsHigh(4) tsLow(4) capLen(4) origLen(4) = 20 + data + pad
    uint32_t capLen = static_cast<uint32_t>(frame.size());
    uint32_t pad    = (4u - (capLen % 4u)) % 4u;
    uint32_t total  = 8u + 20u + capLen + pad + 4u;
    pushLe32(v, 0x00000006); // block type EPB
    pushLe32(v, total);
    pushLe32(v, 0);    // interface id 0
    pushLe32(v, 0);    // ts high
    pushLe32(v, 1500); // ts low：tick=1500，除数 1e3 → 1.5s
    pushLe32(v, capLen);
    pushLe32(v, capLen); // orig len
    pushBytes(v, frame);
    for (uint32_t i = 0; i < pad; ++i)
        pushByte(v, 0);
    pushLe32(v, total); // total length（尾部重复）

    return v;
}

TEST(NativeAnalyzerNg, ParsesPcapngWithTsResol)
{
    auto frame = tcpSynFrame();
    auto bytes = makePcapNgFile(frame);

    std::string path = "test_data/native_ng.pcapng";
    {
        std::ofstream out(path.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    NativeAnalyzer analyzer;
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analyzeFile(path, packets));
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0]->src_ip, "192.168.1.10");
    EXPECT_EQ(packets[0]->dst_port, 80);
    EXPECT_EQ(packets[0]->protocol, "HTTP");
    // if_tsresol=3（毫秒）× tick 1500 → 1.5s；若分辨率解析错误会退化为 1e6（=0.0015s）。
    EXPECT_NEAR(packets[0]->time, 1.5, 1e-6);

    std::remove(path.c_str());
}

// ---- Linux SLL / SLL2（tcpdump -i any）----
// SLL（linktype 113）：pkttype(2) arphrd(2) lladdrlen(2) lladdr(8) protocol(2) 共 16 字节，
// 随后是网络层。这里 protocol=0x0800（IPv4）+ IPv4/TCP。
std::vector<unsigned char> sllFrame()
{
    std::vector<unsigned char> frame;
    pushBE16(frame, 0);      // pkttype
    pushBE16(frame, 1);      // arphrd = Ethernet
    pushBE16(frame, 6);      // lladdrlen
    pushHex(frame, "001122334455"); // lladdr（8 字节，取前 6 + 2 字节补零）
    pushBE16(frame, 0);
    pushBE16(frame, 0x0800); // protocol
    pushBytes(frame, ipv4Header("10.1.1.1", "10.1.1.2", 6, 40));
    pushBytes(frame, tcpHeader(4444, 80, 0x02));
    return frame;
}

// SLL2（linktype 276）：protocol(2) reserved(2) ifindex(4) arphrd(2) pkttype(1) lladdrlen(1)
// lladdr(8) 共 20 字节，protocol 在最前。
std::vector<unsigned char> sll2Frame()
{
    std::vector<unsigned char> frame;
    pushBE16(frame, 0x0800); // protocol
    pushBE16(frame, 0);      // reserved
    pushBE32(frame, 2);      // ifindex
    pushBE16(frame, 1);      // arphrd
    pushByte(frame, 0);      // pkttype
    pushByte(frame, 6);      // lladdrlen
    pushHex(frame, "0011223344550000"); // lladdr（8 字节）
    pushBytes(frame, ipv4Header("10.2.2.1", "10.2.2.2", 17, 28));
    pushBytes(frame, udpHeader(6000, 53, 8));
    return frame;
}

TEST(NativeParserTest, ParsesSll)
{
    auto   frame = sllFrame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 113));
    EXPECT_EQ(p.src_ip, "10.1.1.1");
    EXPECT_EQ(p.dst_ip, "10.1.1.2");
    EXPECT_EQ(p.dst_port, 80);
    EXPECT_EQ(p.transport, "TCP");
}

TEST(NativeParserTest, ParsesSll2)
{
    auto   frame = sll2Frame();
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p, 276));
    EXPECT_EQ(p.src_ip, "10.2.2.1");
    EXPECT_EQ(p.dst_ip, "10.2.2.2");
    EXPECT_EQ(p.dst_port, 53);
    EXPECT_EQ(p.transport, "UDP");
}

// ---- DNS 压缩指针（RFC 1035 §4.1.4）----
TEST(NativeParserTest, ParsesDnsCnameWithCompressionPointer)
{
    std::vector<unsigned char> dns;
    pushBE16(dns, 0x9999);
    pushBE16(dns, 0x8180);
    pushBE16(dns, 1); // QDCOUNT
    pushBE16(dns, 1); // ANCOUNT
    pushBE16(dns, 0);
    pushBE16(dns, 0);
    // question: example.com A（起始偏移 12）
    pushByte(dns, 7); pushHex(dns, "6578616d706c65");
    pushByte(dns, 3); pushHex(dns, "636f6d");
    pushByte(dns, 0);
    pushBE16(dns, 1); pushBE16(dns, 1);
    // answer：name 用压缩指针 0xc00c 指回 offset 12，type=CNAME，rdata 也是指回 offset 12 的压缩指针
    // （CNAME 目标本身就是 example.com）——验证 rdata 域名解析能跟随压缩指针，而不是截断/乱码。
    pushHex(dns, "c00c");
    pushBE16(dns, 5); pushBE16(dns, 1); pushBE32(dns, 300);
    pushBE16(dns, 2); pushHex(dns, "c00c");

    auto frame = udpPayloadFrame("8.8.8.8", "192.168.1.10", 53, 53000, dns);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("CNAME example.com"), std::string::npos);
}

// ---- SSH（RFC 4253 §4.2，版本交换 banner）----
TEST(NativeParserTest, ParsesSshBanner)
{
    auto payload = strVec("SSH-2.0-OpenSSH_9.6\r\n");
    auto frame   = tcpPayloadFrame("192.168.1.10", "192.168.1.20", 51000, 22, payload);
    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "SSH");
    EXPECT_NE(p.info.find("SSH-2.0-OpenSSH_9.6"), std::string::npos);

    DetailNode root;
    ASSERT_TRUE(NativePacketParser::buildDetailTree(
        frame.data(), static_cast<uint32_t>(frame.size()), 1, 1, root));
    bool hasSsh = false;
    for (const auto& c : root.children)
    {
        if (c.label != "SSH Protocol")
            continue;
        hasSsh = true;
        ASSERT_FALSE(c.children.empty());
        EXPECT_NE(c.children[0].value.find("SSH-2.0-OpenSSH_9.6"), std::string::npos);
    }
    EXPECT_TRUE(hasSsh);
}

// ---- IPv6 分片（Fragment Header，proto 44）----
TEST(NativeParserTest, MarksIpv6Fragment)
{
    std::vector<unsigned char> frame = ethHeader(0x86dd);
    pushBE32(frame, 0x60000000);
    pushBE16(frame, 8 + 20); // payload len：Fragment Header(8) + TCP 头(20)
    pushByte(frame, 44);     // next header = Fragment Header
    pushByte(frame, 64);
    pushHex(frame, "fe800000000000000000000000000001");
    pushHex(frame, "fe800000000000000000000000000002");
    // Fragment Header：next(1)=TCP(6) reserved(1) fragOffset+flags(2) id(4)
    pushByte(frame, 6);
    pushByte(frame, 0);
    pushBE16(frame, 0x0008 | 0x0001); // offset=1（*8=8 字节）+ M=1（还有更多分片）
    pushBE32(frame, 0x12345678);
    pushBytes(frame, tcpHeader(51000, 5555, 0x10));

    Packet p;
    ASSERT_TRUE(NativePacketParser::parseFrame(frame.data(), static_cast<uint32_t>(frame.size()),
                                               p));
    EXPECT_EQ(p.protocol, "TCP");

    DetailNode root;
    ASSERT_TRUE(NativePacketParser::buildDetailTree(
        frame.data(), static_cast<uint32_t>(frame.size()), 1, 1, root));
    bool hasFrag = false;
    for (const auto& layer : root.children)
        if (layer.label.find("Internet Protocol") != std::string::npos)
            for (const auto& f : layer.children)
                if (f.label == "Fragment") hasFrag = true;
    EXPECT_TRUE(hasFrag);
}

// ---- ISO-TP（ISO 15765-2）多帧重组 ----
// 10 字节 UDS 报文（ReadDataByIdentifier 正响应），拆成 First Frame(6 字节) + 1 个 Consecutive Frame(4 字节)。
std::vector<unsigned char> isoTpUdsPayload()
{
    return {0x62, 0xF1, 0x90, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
}
std::vector<unsigned char> isoTpFirstFrame(const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> d;
    pushByte(d, 0x10);
    pushByte(d, static_cast<unsigned char>(payload.size()));
    for (size_t i = 0; i < 6 && i < payload.size(); ++i) pushByte(d, payload[i]);
    return d;
}
std::vector<unsigned char> isoTpConsecutiveFrame(const std::vector<unsigned char>& payload,
                                                 uint8_t seq)
{
    std::vector<unsigned char> d;
    pushByte(d, static_cast<unsigned char>(0x20 | (seq & 0x0F)));
    for (size_t i = 6; i < payload.size(); ++i) pushByte(d, payload[i]);
    while (d.size() < 8) pushByte(d, 0xAA); // CAN 帧补齐到 8 字节（填充）
    return d;
}

TEST(NativeParserTest, ParsesIsoTpMultiFrame)
{
    auto payload = isoTpUdsPayload();
    auto ffFrame = canSocketcanFrame(0x7E8, 8, isoTpFirstFrame(payload));
    auto cfFrame = canSocketcanFrame(0x7E8, 8, isoTpConsecutiveFrame(payload, 1));

    NativePacketParser::IsoTpReassembler isoTp;
    Packet pFf;
    ASSERT_TRUE(NativePacketParser::parseFrame(
        ffFrame.data(), static_cast<uint32_t>(ffFrame.size()), pFf, 227, &isoTp));
    EXPECT_NE(pFf.protocol, "UDS"); // 未凑满，不应误报完成
    EXPECT_NE(pFf.info.find("First Frame"), std::string::npos);
    EXPECT_NE(pFf.info.find("Len=10"), std::string::npos);

    Packet pCf;
    ASSERT_TRUE(NativePacketParser::parseFrame(
        cfFrame.data(), static_cast<uint32_t>(cfFrame.size()), pCf, 227, &isoTp));
    EXPECT_EQ(pCf.protocol, "UDS");
    EXPECT_NE(pCf.info.find("ReadDataByIdentifier"), std::string::npos);
}

// 多帧（小端经典 pcap）：供 NativeAnalyzer 集成测试构造含 FF+CF 的 CAN 抓包文件。
std::vector<unsigned char> makePcapFileLinkTypeMulti(
    uint32_t linkType, const std::vector<std::vector<unsigned char>>& frames)
{
    std::vector<unsigned char> v;
    pushLe32(v, 0xa1b2c3d4);
    pushLe16(v, 2);
    pushLe16(v, 4);
    pushLe32(v, 0);
    pushLe32(v, 0);
    pushLe32(v, 65535);
    pushLe32(v, linkType);
    for (const auto& f : frames)
    {
        pushLe32(v, 1); // ts_sec
        pushLe32(v, 0);
        pushLe32(v, static_cast<uint32_t>(f.size()));
        pushLe32(v, static_cast<uint32_t>(f.size()));
        pushBytes(v, f);
    }
    return v;
}

TEST_F(NativeAnalyzerTest, AnalyzesCanIsoTpMultiFrameAndReplaysDetailTree)
{
    auto payload = isoTpUdsPayload();
    auto ff       = canSocketcanFrame(0x7E8, 8, isoTpFirstFrame(payload));
    auto cf       = canSocketcanFrame(0x7E8, 8, isoTpConsecutiveFrame(payload, 1));
    auto bytes    = makePcapFileLinkTypeMulti(227, {ff, cf});
    std::string path = "test_data/native_isotp.pcap";
    {
        std::ofstream out(path.c_str(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    NativeAnalyzer analyzer;
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analyzeFile(path, packets));
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_NE(packets[0]->protocol, "UDS"); // First Frame 单独看未完成
    EXPECT_EQ(packets[1]->protocol, "UDS"); // Consecutive Frame 补满后识别为 UDS
    EXPECT_NE(packets[1]->info.find("ReadDataByIdentifier"), std::string::npos);

    // 只查最后一帧（不预先查前面的帧）：getPacketDetailTree 必须自行重放历史帧，
    // 才能在按需构建详情树时也看到完整重组后的 UDS 内容。
    DetailNode root;
    ASSERT_TRUE(analyzer.getPacketDetailTree(2, root));
    bool hasUds = false;
    for (const auto& c : root.children)
        if (c.label == "Unified Diagnostic Services")
            hasUds = true;
    EXPECT_TRUE(hasUds);

    // 乱序往回跳到第 1 帧、再跳回第 2 帧：增量重放缓存必须整体重置重放，不能残留
    // 跳回前的状态导致重复消费 First Frame 或漏算 Consecutive Frame。
    DetailNode root1;
    ASSERT_TRUE(analyzer.getPacketDetailTree(1, root1));
    DetailNode root2;
    ASSERT_TRUE(analyzer.getPacketDetailTree(2, root2));
    bool hasUdsAgain = false;
    for (const auto& c : root2.children)
        if (c.label == "Unified Diagnostic Services")
            hasUdsAgain = true;
    EXPECT_TRUE(hasUdsAgain);

    std::remove(path.c_str());
}
