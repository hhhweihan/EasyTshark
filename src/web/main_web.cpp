// EasyTshark Web 前端入口：解析参数、定位 tshark、启动 HTTP 服务并托管 web/ 静态前端。
// 路由逻辑在 web/WebServer.cpp（registerWebRoutes），本文件只做入口装配。

#include <cstdlib>
#include <random>
#include <string>

#if defined(_WIN32)
#include <direct.h> // _fullpath
#endif

#include "httplib/httplib.h"

#include "AnalysisSession.hpp"
#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"
#include "web/WebServer.hpp"

namespace
{
// 在候选目录里找到静态前端目录（源码树 web/ 与产物 output/web 都可能相对 cwd）。
std::string resolveWebRoot()
{
    const char* candidates[] = {"web", "output/web", "./web"};
    for (const char* c : candidates)
    {
        // 用 index.html 是否存在判断该目录就位
        std::string probe = std::string(c) + "/index.html";
        FILE*       f     = std::fopen(probe.c_str(), "rb");
        if (f)
        {
            std::fclose(f);
            return c;
        }
    }
    return "web"; // 兜底：即便未找到也返回默认值，静态挂载失败仅影响页面、不影响 API
}
} // namespace

int main(int argc, char* argv[])
{
    // 绑定地址与端口：默认只在本机回环上监听（远程访问请走 SSH 端口转发）。
    // 覆盖优先级：命令行参数 > 环境变量 > 默认值。
    std::string host = "127.0.0.1";
    int         port = 8080;
    // 访问令牌：环境变量 EASYTSHARK_WEB_TOKEN 或 --token 指定；未指定则随机生成并打印。
    std::string token;

    if (const char* h = std::getenv("EASYTSHARK_WEB_HOST"))
        host = h;
    if (const char* p = std::getenv("EASYTSHARK_WEB_PORT"))
        port = std::atoi(p);
    if (const char* t = std::getenv("EASYTSHARK_WEB_TOKEN"))
        token = t;
    for (int i = 1; i + 1 < argc; i += 2)
    {
        std::string flag = argv[i];
        if (flag == "--host")
            host = argv[i + 1];
        else if (flag == "--port")
            port = std::atoi(argv[i + 1]);
        else if (flag == "--token")
            token = argv[i + 1];
    }

    if (token.empty())
    {
        // 随机生成 32 个十六进制字符（128 位熵）。
        std::random_device rd;
        std::string        hex = "0123456789abcdef";
        for (int i = 0; i < 32; ++i)
            token.push_back(hex[rd() % 16]);
    }

    // logs/ 只保留最近 10 个日志文件，防止无限累积。
    CommonUtil::pruneLogFiles("logs", 10);

    std::string ts = CommonUtil::get_timestamp();
    loguru::add_file(("logs/web_" + ts + ".log").c_str(), loguru::Append, loguru::Verbosity_MAX);

    // 自动定位 tshark：环境变量 EASYTSHARK_TSHARK → 默认路径 → PATH →（Win）注册表 → 常见目录。
    AnalysisSession session(TsharkCommand::resolveTsharkPath(), "data");
    if (!TsharkCommand::tsharkAvailable(session.tsharkPath()))
    {
        LOG_F(INFO, "未检测到 tshark（%s）：已启用内置解析引擎（libpcap + 自研协议解析），"
                    "离线分析/实时抓包/详情树/常用过滤可用；安装 Wireshark 可解锁完整协议支持：%s",
              session.tsharkPath().c_str(), TsharkCommand::wiresharkDownloadUrl().c_str());
    }

    httplib::Server svr;
    // 请求体上限：httplib 默认 SIZE_MAX，鉴权在 body 读入之后才发生，超大 POST 可在授权前 OOM。
    svr.set_payload_max_length(16u * 1024 * 1024);
    registerWebRoutes(svr, session, token);

    // 托管静态前端：httplib 挂载该目录后，访问 / 会在目录内回退到 index.html（非 HTTP 重定向）。
    std::string webRoot = resolveWebRoot();
    if (!svr.set_mount_point("/", webRoot))
        LOG_F(WARNING, "静态目录挂载失败：%s（API 仍可用，页面不可用）", webRoot.c_str());

    LOG_F(INFO, "EasyTshark Web 服务启动：http://%s:%d  （静态目录 %s）", host.c_str(), port,
          webRoot.c_str());
    std::printf("EasyTshark Web 服务已启动：http://%s:%d\n", host.c_str(), port);
    std::printf("（默认只绑本机回环；远程访问请用 SSH 端口转发，勿裸绑 0.0.0.0）\n");
    std::printf("访问令牌（Token）：%s\n", token.c_str());
    std::printf("浏览器首次打开页面时请输入该令牌（令牌会保存在浏览器本地）。\n");
    std::fflush(stdout);

    LOG_F(INFO, "访问令牌: %s", token.c_str());

    if (!svr.listen(host.c_str(), port))
    {
        std::fprintf(stderr, "监听 %s:%d 失败（端口被占用？）\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
