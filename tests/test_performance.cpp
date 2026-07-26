#include <algorithm>
#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include <numeric>
#include <string>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <vector>

#include "PdmlToJsonConverter.hpp"
#include "test_fs_util.hpp"
#include "tsharkCommand.hpp"

using testfs::fileExists;
using testfs::makeDirs;
using testfs::removeTree;

// 测试辅助函数
namespace
{
    // 创建大型XML测试文件
    void createLargeXmlFile(const std::string& filePath, int numPackets)
    {
        std::ofstream xmlFile(filePath);

        // 写入XML头部
        xmlFile << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        xmlFile << "<pdml xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" version=\"0\" "
                   "creator=\"wireshark/3.6.2\" time=\"Thu Mar 14 05:20:00 2024\" "
                   "capture_file=\"capture.pcap\">\n";

        // 生成多个数据包
        for (int i = 0; i < numPackets; ++i)
        {
            xmlFile << "  <packet>\n";
            xmlFile << "    <proto name=\"frame\" showname=\"Frame " << (i + 1)
                    << ": 74 bytes on wire\" size=\"74\" pos=\"0\">\n";
            xmlFile << "      <field name=\"frame.number\" showname=\"Frame Number: " << (i + 1)
                    << "\" size=\"0\" pos=\"0\" show=\"" << (i + 1) << "\"/>\n";
            xmlFile << "      <field name=\"frame.time\" showname=\"Arrival Time: Mar 14, 2024 "
                       "05:19:57.000000000 UTC\" size=\"0\" pos=\"0\" show=\"Mar 14, 2024 "
                       "05:19:57.000000000 UTC\"/>\n";
            xmlFile << "    </proto>\n";
            xmlFile << "    <proto name=\"eth\" showname=\"Ethernet II, Src: 00:0c:29:8d:5a:b1, "
                       "Dst: 00:50:56:c0:00:08\" size=\"14\" pos=\"0\">\n";
            xmlFile << "      <field name=\"eth.dst\" showname=\"Destination: 00:50:56:c0:00:08\" "
                       "size=\"6\" pos=\"0\" show=\"00:50:56:c0:00:08\"/>\n";
            xmlFile << "      <field name=\"eth.src\" showname=\"Source: 00:0c:29:8d:5a:b1\" "
                       "size=\"6\" pos=\"6\" show=\"00:0c:29:8d:5a:b1\"/>\n";
            xmlFile << "    </proto>\n";
            xmlFile << "  </packet>\n";
        }

        // 写入XML尾部
        xmlFile << "</pdml>\n";

        xmlFile.close();
    }
} // namespace

// 性能测试类
class PerformanceTest : public ::testing::Test
{
protected:
    std::string          testDir;
    PdmlToJsonConverter* converter;

    void SetUp() override
    {
        testDir = "test_performance";
        makeDirs(testDir);
        converter = new PdmlToJsonConverter(TsharkCommand::defaultTsharkPath());
    }

    void TearDown() override
    {
        removeTree(testDir);
        delete converter;
    }

    // 测量函数执行时间的辅助方法
    template <typename Func> long long measureExecutionTime(Func func)
    {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    }
};

// 测试XML到JSON转换的性能
TEST_F(PerformanceTest, DISABLED_XmlToJsonPerformance)
{
    // 注意：这个测试被禁用，因为它可能会运行较长时间
    // 要运行此测试，请移除DISABLED_前缀

    // 测试不同大小的XML文件
    std::vector<int>       packetCounts = {10, 100, 1000};
    std::vector<long long> executionTimes;

    for (int numPackets : packetCounts)
    {
        std::string xmlFile  = testDir + "/test_" + std::to_string(numPackets) + ".xml";
        std::string jsonFile = testDir + "/test_" + std::to_string(numPackets) + ".json";

        // 创建测试XML文件
        createLargeXmlFile(xmlFile, numPackets);

        // 测量转换时间
        long long duration =
            measureExecutionTime([&]() { converter->convertXmlToJson(xmlFile, jsonFile); });

        executionTimes.push_back(duration);

        // 验证转换成功
        EXPECT_TRUE(fileExists(jsonFile));

        std::cout << "转换 " << numPackets << " 个数据包耗时: " << duration << " 毫秒" << std::endl;
    }

    // 验证性能随数据量增加而变化
    // 注意：这只是一个简单的检查，实际上性能可能受多种因素影响
    EXPECT_LT(executionTimes[0], executionTimes[1]);
    EXPECT_LT(executionTimes[1], executionTimes[2]);
}

// 测试多次转换的性能稳定性
TEST_F(PerformanceTest, DISABLED_ConversionStability)
{
    // 注意：这个测试被禁用，因为它可能会运行较长时间
    // 要运行此测试，请移除DISABLED_前缀

    // 创建测试XML文件
    std::string xmlFile = testDir + "/stability_test.xml";
    createLargeXmlFile(xmlFile, 100);

    // 多次执行转换，测量每次的执行时间
    const int              numRuns = 5;
    std::vector<long long> executionTimes;

    for (int i = 0; i < numRuns; ++i)
    {
        std::string jsonFile = testDir + "/stability_test_" + std::to_string(i) + ".json";

        long long duration =
            measureExecutionTime([&]() { converter->convertXmlToJson(xmlFile, jsonFile); });

        executionTimes.push_back(duration);
        std::cout << "运行 #" << (i + 1) << " 耗时: " << duration << " 毫秒" << std::endl;
    }

    // 计算平均值和标准差
    double sum  = std::accumulate(executionTimes.begin(), executionTimes.end(), 0.0);
    double mean = sum / executionTimes.size();

    double sq_sum = std::inner_product(
        executionTimes.begin(), executionTimes.end(), executionTimes.begin(), 0.0,
        std::plus<double>(), [mean](double x, double y) { return (x - mean) * (y - mean); });
    double stddev = std::sqrt(sq_sum / executionTimes.size());

    std::cout << "平均执行时间: " << mean << " 毫秒" << std::endl;
    std::cout << "标准差: " << stddev << " 毫秒" << std::endl;

    // 验证性能稳定性（标准差不应过大）
    // 这里使用相对标准差（标准差/平均值）作为稳定性指标
    double rsd = (stddev / mean) * 100.0; // 相对标准差，以百分比表示
    std::cout << "相对标准差: " << rsd << "%" << std::endl;

    // 相对标准差应小于一定阈值（例如20%）
    EXPECT_LT(rsd, 20.0);
}