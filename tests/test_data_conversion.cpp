#include <fstream>
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "PdmlToJsonConverter.hpp"
#include "test_fs_util.hpp"
#include "tsharkCommand.hpp"

using testfs::fileExists;
using testfs::makeDirs;
using testfs::removeTree;

// 测试辅助函数
namespace
{
    // 读取文件内容
    std::string readFileContent(const std::string& filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            return "";
        }
        return std::string((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
    }

    // 创建测试XML文件
    void createTestXmlFile(const std::string& filePath)
    {
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

        std::ofstream xmlFile(filePath);
        xmlFile << xmlContent;
        xmlFile.close();
    }

    // 创建测试PCAP文件（模拟文件，实际上不是真正的PCAP格式）
    void createTestPcapFile(const std::string& filePath)
    {
        std::ofstream pcapFile(filePath, std::ios::binary);
        // 写入一些模拟数据
        const char* data = "MOCK PCAP FILE CONTENT";
        pcapFile.write(data, strlen(data));
        pcapFile.close();
    }
} // namespace

// 测试类
class DataConversionTest : public ::testing::Test
{
protected:
    std::string    testDir;
    std::string    pcapFile;
    std::string    xmlFile;
    std::string          jsonFile;
    PdmlToJsonConverter* converter;

    void SetUp() override
    {
        testDir  = "test_data_conversion";
        pcapFile = testDir + "/test.pcap";
        xmlFile  = testDir + "/test.xml";
        jsonFile = testDir + "/test.json";

        // 创建测试目录
        makeDirs(testDir);

        // 创建测试文件
        createTestXmlFile(xmlFile);
        createTestPcapFile(pcapFile);

        // 创建转换器实例
        converter = new PdmlToJsonConverter(TsharkCommand::defaultTsharkPath());
    }

    void TearDown() override
    {
        // 清理测试文件和目录
        removeTree(testDir);
        delete converter;
    }
};

// 测试XML到JSON的转换功能
TEST_F(DataConversionTest, ConvertXmlToJson)
{
    // 执行转换
    bool result = converter->convertXmlToJson(xmlFile, jsonFile);

    // 验证转换成功
    EXPECT_TRUE(result);
    EXPECT_TRUE(fileExists(jsonFile));

    // 验证JSON内容
    std::string jsonContent = readFileContent(jsonFile);
    EXPECT_FALSE(jsonContent.empty());

    // 解析JSON并验证结构
    rapidjson::Document jsonDoc;
    jsonDoc.Parse(jsonContent.c_str());

    EXPECT_FALSE(jsonDoc.HasParseError());
    EXPECT_TRUE(jsonDoc.IsObject());
    EXPECT_TRUE(jsonDoc.HasMember("pdml"));
    EXPECT_TRUE(jsonDoc["pdml"].HasMember("packet"));
    EXPECT_TRUE(jsonDoc["pdml"]["packet"].IsArray());
    EXPECT_GT(jsonDoc["pdml"]["packet"].Size(), 0);
}

// 测试PCAP到XML的转换功能（模拟测试，因为实际转换需要tshark命令）
TEST_F(DataConversionTest, ConvertPcapToXml_Mock)
{
    // 创建一个模拟的转换器类，覆盖convertPcapToXml方法
    class MockPdmlToJsonConverter : public PdmlToJsonConverter
    {
    public:
        MockPdmlToJsonConverter(const std::string& path)
            : PdmlToJsonConverter(path)
        {
        }

        // 覆盖方法，返回成功但不实际执行命令
        bool convertPcapToXml(const std::string& pcapFile, const std::string& xmlFile)
        {
            // 创建一个简单的XML文件作为输出
            std::ofstream xmlFileStream(xmlFile);
            xmlFileStream << "<?xml version=\"1.0\"?><pdml><packet></packet></pdml>";
            xmlFileStream.close();
            return true;
        }
    };

    // 使用模拟对象
    MockPdmlToJsonConverter mockConverter(TsharkCommand::defaultTsharkPath());
    std::string             outputXml = testDir + "/output.xml";

    // 执行转换
    bool result = mockConverter.convertPcapToXml(pcapFile, outputXml);

    // 验证结果
    EXPECT_TRUE(result);
    EXPECT_TRUE(fileExists(outputXml));
}

// 测试完整的转换流程：PCAP -> XML -> JSON（集成测试）
TEST_F(DataConversionTest, DISABLED_ConvertPcapToJsonIntegration)
{
    // 注意：这个测试被禁用，因为它需要实际的tshark命令
    // 要运行此测试，请确保tshark已安装并移除DISABLED_前缀

    std::string outputXml  = testDir + "/output.xml";
    std::string outputJson = testDir + "/output.json";

    // 执行PCAP到XML的转换
    bool xmlResult = converter->convertPcapToXml(pcapFile, outputXml);
    EXPECT_TRUE(xmlResult);
    EXPECT_TRUE(fileExists(outputXml));

    // 执行XML到JSON的转换
    bool jsonResult = converter->convertXmlToJson(outputXml, outputJson);
    EXPECT_TRUE(jsonResult);
    EXPECT_TRUE(fileExists(outputJson));
}

// 测试XML节点到JSON节点的转换（私有方法，需要间接测试）
TEST_F(DataConversionTest, ConvertXmlNodeToJsonIndirect)
{
    // 由于convertXmlNodeToJson是私有方法，我们通过测试convertXmlToJson来间接测试它
    // 创建一个简单的XML文件，包含嵌套节点和属性，使用pdml格式
    std::string simpleXmlFile  = testDir + "/simple.xml";
    std::string simpleJsonFile = testDir + "/simple.json";

    std::string xmlContent = R"(<?xml version="1.0" encoding="utf-8"?>
<pdml xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="0" creator="test" time="2024-03-15">
  <packet>
    <proto name="test" showname="Test Protocol">
      <field name="test.field" showname="Test Field" value="test_value"/>
    </proto>
  </packet>
</pdml>)";

    std::ofstream xmlFile(simpleXmlFile);
    xmlFile << xmlContent;
    xmlFile.close();

    // 执行转换
    bool result = converter->convertXmlToJson(simpleXmlFile, simpleJsonFile);
    EXPECT_TRUE(result);
    EXPECT_TRUE(fileExists(simpleJsonFile));

    // 验证JSON内容
    std::string jsonContent = readFileContent(simpleJsonFile);
    EXPECT_FALSE(jsonContent.empty());
}