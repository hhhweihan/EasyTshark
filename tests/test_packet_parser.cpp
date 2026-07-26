#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "PacketParser.hpp"
#include "tsharkDataType.hpp"

// PacketParser::parseLine 是不依赖 tshark / 无 IO 的纯函数，
// 因此这里用手工构造的制表符分隔行做确定性单测，完全不需要 pcap 文件或 tshark 进程。
namespace
{
    // 按 tshark "-T fields" 的输出规则，用 '\t' 拼接字段
    std::string joinFields(const std::vector<std::string>& fields)
    {
        std::string line;
        for (size_t i = 0; i < fields.size(); ++i)
        {
            if (i > 0)
            {
                line += '\t';
            }
            line += fields[i];
        }
        return line;
    }

    // 一组合法的 16 字段样例（IPv4 + TCP），供各用例按需改写单个字段
    // 下标：0 number 1 time 2 len 3 cap_len 4 eth.src 5 eth.dst 6 ip.src 7 ipv6.src
    //       8 ip.dst 9 ipv6.dst 10 tcp.srcport 11 udp.srcport 12 tcp.dstport 13 udp.dstport
    //      14 protocol 15 info
    std::vector<std::string> baseFields()
    {
        return {
            "5",              // frame.number
            "1700000000.5",   // frame.time_epoch
            "100",            // frame.len
            "96",             // frame.cap_len
            "00:11:22:33:44:55", // eth.src
            "aa:bb:cc:dd:ee:ff", // eth.dst
            "192.168.1.10",   // ip.src
            "",               // ipv6.src
            "8.8.8.8",        // ip.dst
            "",               // ipv6.dst
            "4321",           // tcp.srcport
            "",               // udp.srcport
            "80",             // tcp.dstport
            "",               // udp.dstport
            "TCP",            // _ws.col.Protocol
            "GET / HTTP/1.1", // _ws.col.Info
        };
    }
} // namespace

// 合法的 IPv4 + TCP 行应完整解析各字段
TEST(PacketParserTest, ParsesIpv4TcpLine)
{
    Packet packet;
    ASSERT_TRUE(PacketParser::parseLine(joinFields(baseFields()), packet));

    EXPECT_EQ(packet.frame_number, 5);
    EXPECT_DOUBLE_EQ(packet.time, 1700000000.5);
    EXPECT_EQ(packet.len, 100u);
    EXPECT_EQ(packet.cap_len, 96u);
    EXPECT_EQ(packet.src_mac, "00:11:22:33:44:55");
    EXPECT_EQ(packet.dst_mac, "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(packet.src_ip, "192.168.1.10");
    EXPECT_EQ(packet.dst_ip, "8.8.8.8");
    EXPECT_EQ(packet.src_port, 4321);
    EXPECT_EQ(packet.dst_port, 80);
    EXPECT_EQ(packet.protocol, "TCP");
    EXPECT_EQ(packet.info, "GET / HTTP/1.1");
}

// IPv4 字段为空时应回退到 IPv6 字段
TEST(PacketParserTest, FallsBackToIpv6WhenIpv4Empty)
{
    std::vector<std::string> fields = baseFields();
    fields[6] = "";        // ip.src 空
    fields[7] = "fe80::1"; // ipv6.src
    fields[8] = "";        // ip.dst 空
    fields[9] = "fe80::2"; // ipv6.dst

    Packet packet;
    ASSERT_TRUE(PacketParser::parseLine(joinFields(fields), packet));
    EXPECT_EQ(packet.src_ip, "fe80::1");
    EXPECT_EQ(packet.dst_ip, "fe80::2");
}

// TCP 端口为空时应采用 UDP 端口
TEST(PacketParserTest, UsesUdpPortsWhenTcpEmpty)
{
    std::vector<std::string> fields = baseFields();
    fields[10] = "";      // tcp.srcport 空
    fields[11] = "53";    // udp.srcport
    fields[12] = "";      // tcp.dstport 空
    fields[13] = "12345"; // udp.dstport
    fields[14] = "DNS";

    Packet packet;
    ASSERT_TRUE(PacketParser::parseLine(joinFields(fields), packet));
    EXPECT_EQ(packet.src_port, 53);
    EXPECT_EQ(packet.dst_port, 12345);
    EXPECT_EQ(packet.protocol, "DNS");
}

// 四个端口字段全空时端口保持默认值 0
TEST(PacketParserTest, LeavesPortsZeroWhenAllEmpty)
{
    std::vector<std::string> fields = baseFields();
    fields[10] = "";
    fields[11] = "";
    fields[12] = "";
    fields[13] = "";

    Packet packet;
    ASSERT_TRUE(PacketParser::parseLine(joinFields(fields), packet));
    EXPECT_EQ(packet.src_port, 0);
    EXPECT_EQ(packet.dst_port, 0);
}

// 字段数不足 16 应返回 false
TEST(PacketParserTest, ReturnsFalseOnTooFewFields)
{
    std::vector<std::string> fields(10, "x");
    Packet                   packet;
    EXPECT_FALSE(PacketParser::parseLine(joinFields(fields), packet));
}

// 末尾换行不应混入最后一个字段（info）
TEST(PacketParserTest, StripsTrailingNewline)
{
    std::string line = joinFields(baseFields()) + "\n";
    Packet      packet;
    ASSERT_TRUE(PacketParser::parseLine(line, packet));
    EXPECT_EQ(packet.info, "GET / HTTP/1.1");
    EXPECT_TRUE(packet.info.find('\n') == std::string::npos);
}
