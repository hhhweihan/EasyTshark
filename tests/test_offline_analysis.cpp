#include <gtest/gtest.h>
#include "PcapAnalyzer.hpp"
#include "PdmlToJsonConverter.hpp"
#include "test_fs_util.hpp"
#include "tsharkCommand.hpp"
#include "utils.hpp"

using testfs::makeDirs;
#include <memory>
#include <fstream>
#include <cstdio>

// 离线分析测试夹具
class OfflineAnalysisTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 确保测试目录存在
        makeDirs("test_data");
    }

    void TearDown() override {
        // 清理代码
    }

    // 测试夹具中的共享资源
    PcapAnalyzer        analyzer{TsharkCommand::defaultTsharkPath()};
    PdmlToJsonConverter converter{TsharkCommand::defaultTsharkPath()};
};

// SQLiteUtil测试夹具
class SQLiteUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 删除可能存在的旧测试数据库
        std::remove(dbPath.c_str());
    }
    
    void TearDown() override {
        // 清理测试数据库
        std::remove(dbPath.c_str());
    }
    
    // 测试数据库路径
    std::string dbPath = "test_db.sqlite";
};

// 集成测试夹具
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 创建测试目录
        makeDirs("test_data");

        // 删除可能存在的旧测试文件
        std::remove(testDbPath.c_str());
        std::remove(testXmlPath.c_str());
        std::remove(testJsonPath.c_str());
    }
    
    void TearDown() override {
        // 清理测试文件
        std::remove(testDbPath.c_str());
        std::remove(testXmlPath.c_str());
        std::remove(testJsonPath.c_str());
    }
    
    // 测试文件路径
    std::string testPcapPath = "test_data/test.pcap";
    std::string testDbPath = "test_data/test.db";
    std::string testXmlPath = "test_data/test.xml";
    std::string testJsonPath = "test_data/test.json";
    
    // 测试对象
    PcapAnalyzer        analyzer{TsharkCommand::defaultTsharkPath()};
    PdmlToJsonConverter converter{TsharkCommand::defaultTsharkPath()};
};

// 测试SQLiteUtil类的基本功能
TEST_F(SQLiteUtilTest, BasicFunctions) {
    // 创建SQLiteUtil实例
    SQLiteUtil sqliteUtil(dbPath);
    
    // 测试创建表
    EXPECT_TRUE(sqliteUtil.createPacketTable());
    
    // 创建测试数据包
    std::vector<std::shared_ptr<Packet>> packets;
    auto packet = std::make_shared<Packet>();
    packet->frame_number = 1;
    packet->time = 1234567890.123;
    packet->cap_len = 100;
    packet->len = 120;
    packet->src_mac = "00:11:22:33:44:55";
    packet->dst_mac = "AA:BB:CC:DD:EE:FF";
    packet->src_ip = "192.168.1.1";
    packet->src_location = "中国-北京";
    packet->src_port = 8080;
    packet->dst_ip = "192.168.1.2";
    packet->dst_location = "中国-上海";
    packet->dst_port = 80;
    packet->protocol = "TCP";
    packet->info = "测试数据包";
    packet->file_offset = 42;
    
    packets.push_back(packet);
    
    // 测试插入数据包
    EXPECT_TRUE(sqliteUtil.insertPacket(packets));
    
    // 测试查询数据包
    std::vector<std::shared_ptr<Packet>> queriedPackets;
    EXPECT_TRUE(sqliteUtil.queryPacket(queriedPackets));
    
    // 验证查询结果
    ASSERT_EQ(queriedPackets.size(), 1);
    EXPECT_EQ(queriedPackets[0]->frame_number, 1);
    EXPECT_DOUBLE_EQ(queriedPackets[0]->time, 1234567890.123);
    EXPECT_EQ(queriedPackets[0]->cap_len, 100);
    EXPECT_EQ(queriedPackets[0]->len, 120);
    EXPECT_EQ(queriedPackets[0]->src_mac, "00:11:22:33:44:55");
    EXPECT_EQ(queriedPackets[0]->dst_mac, "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(queriedPackets[0]->src_ip, "192.168.1.1");
    EXPECT_EQ(queriedPackets[0]->src_location, "中国-北京");
    EXPECT_EQ(queriedPackets[0]->src_port, 8080);
    EXPECT_EQ(queriedPackets[0]->dst_ip, "192.168.1.2");
    EXPECT_EQ(queriedPackets[0]->dst_location, "中国-上海");
    EXPECT_EQ(queriedPackets[0]->dst_port, 80);
    EXPECT_EQ(queriedPackets[0]->protocol, "TCP");
    EXPECT_EQ(queriedPackets[0]->info, "测试数据包");
    EXPECT_EQ(queriedPackets[0]->file_offset, 42);
}

// 测试离线分析功能
TEST_F(OfflineAnalysisTest, OfflineAnalysis) {
    // 创建测试PCAP文件路径
    // 注意：这个测试需要一个有效的PCAP文件，可以在测试前创建或使用已有的文件
    std::string testPcapPath = "test_data/test.pcap";
    
    // 如果没有测试PCAP文件，可以跳过这个测试
    std::ifstream testFile(testPcapPath);
    if (!testFile.good()) {
        GTEST_SKIP() << "跳过离线分析测试，因为测试PCAP文件不存在: " << testPcapPath;
    }
    testFile.close();
    
    // 测试离线分析功能
    std::vector<std::shared_ptr<Packet>> packets;
    EXPECT_TRUE(analyzer.analysisFile(testPcapPath, packets));

    // 验证分析结果
    EXPECT_GT(packets.size(), 0) << "应该至少解析出一个数据包";

    // 检查第一个数据包的基本属性
    if (!packets.empty()) {
        EXPECT_GT(packets[0]->frame_number, 0);
        EXPECT_GT(packets[0]->time, 0);
        EXPECT_GT(packets[0]->cap_len, 0);
        EXPECT_GT(packets[0]->len, 0);
        EXPECT_FALSE(packets[0]->src_mac.empty());
        EXPECT_FALSE(packets[0]->dst_mac.empty());
    }
}

// 流式分析（主题 9）：回调式重载逐包回调、不累积到 allPackets，
// 其回调次数应与累积式解析出的包数完全一致。
TEST_F(OfflineAnalysisTest, StreamingMatchesAccumulating) {
    std::string testPcapPath = "test_data/test.pcap";

    std::ifstream testFile(testPcapPath);
    if (!testFile.good()) {
        GTEST_SKIP() << "跳过流式分析测试，因为测试PCAP文件不存在: " << testPcapPath;
    }
    testFile.close();

    // 累积式：拿到全量包数作为基准
    std::vector<std::shared_ptr<Packet>> packets;
    ASSERT_TRUE(analyzer.analysisFile(testPcapPath, packets));

    // 流式：只数回调次数，不保留任何 Packet
    size_t       streamed = 0;
    PcapAnalyzer streamingAnalyzer{TsharkCommand::defaultTsharkPath()};
    ASSERT_TRUE(streamingAnalyzer.analysisFile(
        testPcapPath, [&streamed](const Packet&) { ++streamed; }));

    EXPECT_EQ(streamed, packets.size()) << "流式回调次数应等于累积解析出的包数";
}

// 测试PCAP到XML和JSON的转换功能
TEST_F(OfflineAnalysisTest, FileConversion) {
    // 创建测试PCAP文件路径
    std::string testPcapPath = "test_data/test.pcap";
    std::string testXmlPath = "test_data/test.xml";
    std::string testJsonPath = "test_data/test.json";
    
    // 如果没有测试PCAP文件，可以跳过这个测试
    std::ifstream testFile(testPcapPath);
    if (!testFile.good()) {
        GTEST_SKIP() << "跳过文件转换测试，因为测试PCAP文件不存在: " << testPcapPath;
    }
    testFile.close();
    
    // 删除可能存在的旧测试文件
    std::remove(testXmlPath.c_str());
    std::remove(testJsonPath.c_str());
    
    // 测试PCAP到XML的转换
    EXPECT_TRUE(converter.convertPcapToXml(testPcapPath, testXmlPath));

    // 验证XML文件已创建
    std::ifstream xmlFile(testXmlPath);
    EXPECT_TRUE(xmlFile.good()) << "XML文件应该已创建";
    xmlFile.close();

    // 测试XML到JSON的转换
    EXPECT_TRUE(converter.convertXmlToJson(testXmlPath, testJsonPath));

    // 验证JSON文件已创建
    std::ifstream jsonFile(testJsonPath);
    EXPECT_TRUE(jsonFile.good()) << "JSON文件应该已创建";
    jsonFile.close();
    
    // 清理测试文件
    std::remove(testXmlPath.c_str());
    std::remove(testJsonPath.c_str());
}

// 测试IP地理位置解析功能
TEST(IP2RegionUtilTest, IPLocationLookup) {
    // 初始化IP2RegionUtil
    // 注意：这个测试需要有效的IP2Region数据库文件
    std::string dbPath = "resources/ip2region.xdb";
    
    std::ifstream dbFile(dbPath);
    if (!dbFile.good()) {
        GTEST_SKIP() << "跳过IP地理位置测试，因为IP2Region数据库文件不存在: " << dbPath;
    }
    dbFile.close();
    
    // 初始化IP2RegionUtil
    EXPECT_TRUE(IP2RegionUtil::init(dbPath));
    
    // 测试公共IP地址的地理位置解析
    std::string location = IP2RegionUtil::getIpLocation("114.114.114.114"); // 114DNS的IP
    EXPECT_FALSE(location.empty()) << "应该能够解析公共IP地址的地理位置";
    
    // 测试内网IP地址
    location = IP2RegionUtil::getIpLocation("192.168.1.1");
    EXPECT_TRUE(location.empty() || location == "内网") << "内网IP应该返回空或'内网'";
    
    // 测试无效IP地址
    location = IP2RegionUtil::getIpLocation("999.999.999.999");
    EXPECT_TRUE(location.empty()) << "无效IP应该返回空字符串";
}

// 集成测试：测试完整的离线分析流程
TEST_F(IntegrationTest, OfflineAnalysisWorkflow) {
    // 如果没有测试PCAP文件，可以跳过这个测试
    std::ifstream testFile(testPcapPath);
    if (!testFile.good()) {
        GTEST_SKIP() << "跳过集成测试，因为测试PCAP文件不存在: " << testPcapPath;
    }
    testFile.close();
    
    // 创建SQLiteUtil实例
    SQLiteUtil sqliteUtil(testDbPath);
    
    // 创建数据表
    EXPECT_TRUE(sqliteUtil.createPacketTable());
    
    // 解析PCAP文件
    std::vector<std::shared_ptr<Packet>> packets;
    EXPECT_TRUE(analyzer.analysisFile(testPcapPath, packets));
    EXPECT_GT(packets.size(), 0) << "应该至少解析出一个数据包";

    // 将数据包插入到数据库
    EXPECT_TRUE(sqliteUtil.insertPacket(packets));

    // 将PCAP文件转换为XML
    EXPECT_TRUE(converter.convertPcapToXml(testPcapPath, testXmlPath));

    // 将XML文件转换为JSON
    EXPECT_TRUE(converter.convertXmlToJson(testXmlPath, testJsonPath));
    
    // 验证所有输出文件都已创建
    std::ifstream dbFile(testDbPath);
    EXPECT_TRUE(dbFile.good()) << "数据库文件应该已创建";
    dbFile.close();
    
    std::ifstream xmlFile(testXmlPath);
    EXPECT_TRUE(xmlFile.good()) << "XML文件应该已创建";
    xmlFile.close();
    
    std::ifstream jsonFile(testJsonPath);
    EXPECT_TRUE(jsonFile.good()) << "JSON文件应该已创建";
    jsonFile.close();
}