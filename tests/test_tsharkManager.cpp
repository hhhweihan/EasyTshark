#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "PdmlToJsonConverter.hpp"
#include "test_fs_util.hpp"
#include "tsharkCommand.hpp"

using testfs::fileExists;
using testfs::makeDirs;
using testfs::removeTree;

// 创建测试目录和文件的辅助函数
void createTestFiles()
{
    // 确保测试目录存在
    std::string testDir = "test_data";
    makeDirs(testDir);

    // 创建测试XML文件
    std::string xmlContent = R"(<?xml version="1.0" encoding="utf-8"?>
<pdml xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="0" creator="wireshark/3.6.2" time="Thu Mar 14 05:20:00 2024" capture_file="capture.pcap">
  <packet>
    <proto name="frame" showname="Frame 1: 74 bytes on wire" size="74" pos="0">
      <field name="frame.time" showname="Arrival Time: Mar 14, 2024 05:19:57.000000000 UTC" size="0" pos="0" show="Mar 14, 2024 05:19:57.000000000 UTC"/>
    </proto>
    <proto name="eth" showname="Ethernet II, Src: 00:0c:29:8d:5a:b1, Dst: 00:50:56:c0:00:08" size="14" pos="0">
      <field name="eth.dst" showname="Destination: 00:50:56:c0:00:08" size="6" pos="0" show="00:50:56:c0:00:08"/>
      <field name="eth.src" showname="Source: 00:0c:29:8d:5a:b1" size="6" pos="6" show="00:0c:29:8d:5a:b1"/>
    </proto>
  </packet>
</pdml>)";

    std::ofstream xmlFile(testDir + "/test.xml");
    xmlFile << xmlContent;
    xmlFile.close();
}

class TsharkToolsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        createTestFiles();
        converter = new PdmlToJsonConverter(TsharkCommand::defaultTsharkPath());
    }

    void TearDown() override
    {
        delete converter;
        // 清理测试文件
        removeTree("test_data");
    }

    PdmlToJsonConverter* converter;
};

// 测试XML到JSON的转换
TEST_F(TsharkToolsTest, ConvertXmlToJson)
{
    std::string xmlFile  = "test_data/test.xml";
    std::string jsonFile = "test_data/test.json";

    ASSERT_TRUE(converter->convertXmlToJson(xmlFile, jsonFile));

    // 验证JSON文件是否存在
    ASSERT_TRUE(fileExists(jsonFile));

    // 读取JSON文件内容并验证
    std::ifstream jsonFileStream(jsonFile);
    std::string   jsonContent((std::istreambuf_iterator<char>(jsonFileStream)),
                              std::istreambuf_iterator<char>());
    jsonFileStream.close();

    // 验证JSON内容包含预期的字段
    EXPECT_TRUE(jsonContent.find("pdml") != std::string::npos);
    EXPECT_TRUE(jsonContent.find("packet") != std::string::npos);
    EXPECT_TRUE(jsonContent.find("proto") != std::string::npos);
    EXPECT_TRUE(jsonContent.find("eth.dst") != std::string::npos);
    EXPECT_TRUE(jsonContent.find("00:50:56:c0:00:08") != std::string::npos);
}

// 测试获取网络适配器信息
TEST_F(TsharkToolsTest, GetNetworkAdapterInfo)
{
    std::vector<AdapterInfo> adapters =
        TsharkCommand::listNetworkAdapters(TsharkCommand::defaultTsharkPath());

    // 验证至少有一个网络适配器
    EXPECT_GT(adapters.size(), 0);

    // 验证第一个适配器的ID和名称不为空
    if (!adapters.empty())
    {
        EXPECT_GT(adapters[0].id, 0);
        EXPECT_FALSE(adapters[0].name.empty());
    }
}

// 测试转换器构造函数
TEST_F(TsharkToolsTest, Constructor)
{
    // 验证tsharkPath不为空
    EXPECT_FALSE(converter->getTsharkPath().empty());
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}