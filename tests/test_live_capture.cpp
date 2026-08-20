#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "LiveCapture.hpp"

// 实时抓包路径的集成测试（POSIX）：用一段假 tshark 脚本替代真实 tshark。
// 脚本忽略所有参数，直接向 stdout 打 3 行 tshark -T fields 格式的报文摘要
// （16 个 tab 分隔字段，顺序与 TsharkCommand::tsharkFieldArgs / PacketParser 对应），
// 然后 sleep 保持——模拟真实 tshark 抓包挂起、等停止信号收尾的行为。
// 验证：startCapture 成功返回、回调逐包收到、字段解析正确、stopCapture 幂等收尾。
#if !defined(_WIN32)

namespace
{
const char* kScript = R"SCRIPT(
#!/bin/sh
# 假 tshark：输出 3 行 fields 摘要后保持挂起，等 SIGTERM 收尾。
printf '1\t1787130000.123\t64\t64\t00:11:22:33:44:55\t66:77:88:99:aa:bb\t192.168.1.1\t\t192.168.1.2\t\t1234\t\t80\t\tTCP\tSYN from fake tshark\n'
printf '2\t1787130000.223\t128\t128\t00:11:22:33:44:55\t66:77:88:99:aa:bb\t192.168.1.1\t\t192.168.1.2\t\t1234\t\t80\t\tTCP\tACK\n'
printf '3\t1787130000.323\t96\t96\t00:11:22:33:44:55\t66:77:88:99:aa:bb\t192.168.1.1\t\t192.168.1.2\t\t\t\t53\t\tUDP\tDNS query\n'
exec sleep 1000  # exec: sh 被替换为 sleep，pid 不变，SIGTERM 直达
)SCRIPT";
} // namespace

class LiveCaptureFakeTsharkTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // 生成假 tshark 脚本（每次测试独立文件，避免并发冲突）
        scriptPath_ = "test_data/fake_tshark_live_" + std::to_string(::getpid()) + ".sh";
        std::ofstream out(scriptPath_.c_str());
        ASSERT_TRUE(out.good()) << "无法创建假 tshark 脚本";
        out << kScript;
        out.close();
        // 可执行权限
        ASSERT_EQ(std::system(("chmod +x " + scriptPath_).c_str()), 0);
    }

    void TearDown() override { std::remove(scriptPath_.c_str()); }

    std::string scriptPath_;
};

TEST_F(LiveCaptureFakeTsharkTest, StreamsThreePacketsAndStops)
{
    // ip2RegionDbPath 传不存在的路径：初始化失败仅 warning，不影响抓包
    LiveCapture capture(scriptPath_, "test_data/no_such_xdb.bin");

    std::atomic<int> received{0};
    std::string      firstSrcIp;
    std::string      firstProto;
    std::string      captureFile = "test_data/fake_capture.pcap";

    ASSERT_TRUE(capture.startCapture("fake-adapter",
                                     [&received, &firstSrcIp, &firstProto](
                                         const std::shared_ptr<Packet>& p)
                                     {
                                         if (received.load() == 0)
                                         {
                                             firstSrcIp = p->src_ip;
                                             firstProto = p->protocol;
                                         }
                                         received.fetch_add(1);
                                     },
                                     captureFile));

    // 等待脚本输出 3 行被解析（回调执行）；最多等 5s
    for (int i = 0; i < 100 && received.load() < 3; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(received.load(), 3);
    EXPECT_EQ(firstSrcIp, "192.168.1.1");
    EXPECT_EQ(firstProto, "TCP");

    // 停止：发 SIGTERM 令脚本收尾，join 工作线程
    EXPECT_TRUE(capture.stopCapture());
    // 幂等：重复 stop 不崩溃、返回合理值（未在抓包）
    capture.stopCapture();
    EXPECT_FALSE(capture.isCapturing());
}

TEST_F(LiveCaptureFakeTsharkTest, MissingExecutableFailsFast)
{
    // 不存在的 tshark 路径：fork 会成功（PopenEx 返回管道），但子进程 execvp 失败后
    // 立即 _exit(127)，读循环收到 EOF 快速收尾。验证：不崩溃、最终不再处于抓包状态。
    LiveCapture capture("test_data/definitely_not_a_tshark_binary_xyz",
                        "test_data/no_such_xdb.bin");
    bool ok = capture.startCapture("fake-adapter");
    // fork 成功即返回 true（进程已拉起）；exec 失败由线程内 EOF 收尾体现
    EXPECT_TRUE(ok);
    // 等待线程收尾（读循环 EOF + PcloseEx 回收），最多 5s
    for (int i = 0; i < 100 && capture.isCapturing(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(capture.isCapturing());
}

#endif // !defined(_WIN32)

#if defined(_WIN32)
TEST(LiveCaptureWinTest, SkippedOnWindows)
{
    GTEST_SKIP() << "假 tshark 脚本测试仅支持 POSIX（Windows 需 .bat 方案，暂未实现）";
}
#endif
