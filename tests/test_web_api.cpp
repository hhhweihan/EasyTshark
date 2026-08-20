#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include "httplib/httplib.h"
#include "AnalysisSession.hpp"
#include "web/WebServer.hpp"

// Web 路由层的 in-process 集成测试：
// 与生产入口（main_web.cpp）共用同一份 registerWebRoutes 路由逻辑，在后台线程
// listen 一个固定端口，用 httplib::Client 发真实 HTTP 请求验证：
//   - 令牌鉴权（无 token / 错 token → 401，对 token → 200）
//   - Origin 校验（不匹配 → 403）
//   - /api/load 路径白名单（白名单外 → 403）
// 不依赖真实 tshark：AnalysisSession 构造即可，抓包/解析类接口不在本测试范围。
class WebServerTest : public ::testing::Test {
protected:
    static const int kPort = 18123; // 固定端口；本测试串行执行，单进程内无冲突
    static const char* const kToken;

    void SetUp() override {
        server_   = std::unique_ptr<httplib::Server>(new httplib::Server());
        session_  = std::unique_ptr<AnalysisSession>(new AnalysisSession("", "data"));
        registerWebRoutes(*server_, *session_, kToken);

        std::atomic<bool> started{false};
        listenThread_ = std::thread([this, &started]() {
            started.store(true);
            server_->listen("127.0.0.1", kPort);
        });
        while (!started.load())
            std::this_thread::yield();
        // 等 listen 真正就绪（bind 完成）再发请求
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    void TearDown() override {
        server_->stop();
        if (listenThread_.joinable())
            listenThread_.join();
    }

    std::pair<int, std::string> get(const std::string& path, const std::string& token,
                                    const std::string& origin = "")
    {
        httplib::Client cli("127.0.0.1", kPort);
        httplib::Headers h;
        if (!token.empty())
            h.emplace("X-Auth-Token", token);
        if (!origin.empty())
            h.emplace("Origin", origin);
        auto res = cli.Get(path, h);
        if (!res)
            return {0, ""};
        return {res->status, res->body};
    }

    std::unique_ptr<httplib::Server> server_;
    std::unique_ptr<AnalysisSession> session_;
    std::thread listenThread_;
};

const char* const WebServerTest::kToken = "test-token-abc";

TEST_F(WebServerTest, RequiresToken)
{
    auto [noToken, bodyNo] = get("/api/status", "");
    EXPECT_EQ(noToken, 401);

    auto [wrongToken, bodyWrong] = get("/api/status", "wrong");
    EXPECT_EQ(wrongToken, 401);

    auto [ok, bodyOk] = get("/api/status", kToken);
    EXPECT_EQ(ok, 200);
    EXPECT_NE(bodyOk.find("\"count\""), std::string::npos);
}

TEST_F(WebServerTest, RejectsForeignOrigin)
{
    auto [status, body] = get("/api/status", kToken, "http://evil.example.com");
    EXPECT_EQ(status, 403);
}

TEST_F(WebServerTest, AcceptsMatchingOrigin)
{
    auto [status, body] = get("/api/status", kToken, "http://127.0.0.1:18123");
    EXPECT_EQ(status, 200);
}

TEST_F(WebServerTest, LoadPathWhitelist)
{
    httplib::Client cli("127.0.0.1", kPort);

    // 白名单外路径（/etc/hosts）→ 403
    auto res1 = cli.Post("/api/load", {{ "X-Auth-Token", kToken }},
                         R"({"path":"/etc/hosts"})", "application/json");
    EXPECT_EQ(res1->status, 403);

    // 白名单内（data/ 下）路径不存在 → 解析失败（非 403）
    auto res2 = cli.Post("/api/load", {{ "X-Auth-Token", kToken }},
                         R"({"path":"data/does_not_exist.pcap"})", "application/json");
    EXPECT_NE(res2->status, 403);
    EXPECT_NE(res2->status, 401);
}

TEST_F(WebServerTest, PacketsPagingShape)
{
    httplib::Client cli("127.0.0.1", kPort);

    // 未载入任何文件：分页返回空数组、total 0，且不 500
    auto res = cli.Get("/api/packets?page=0&pageSize=10",
                       {{"X-Auth-Token", kToken}});
    EXPECT_EQ(res->status, 200);
    EXPECT_NE(res->body.find("\"total\":0"), std::string::npos);
    EXPECT_NE(res->body.find("\"packets\":[]"), std::string::npos);

    // 无 token 的分页请求 → 401
    auto resNoTok = cli.Get("/api/packets?page=0&pageSize=10");
    EXPECT_EQ(resNoTok->status, 401);
}
