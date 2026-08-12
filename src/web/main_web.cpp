// EasyTshark Web 前端入口
//
// 第三个前端（与 CLI 的 main.cpp、GUI 的 gui/main_gui.cpp 并列）：用 cpp-httplib 起一个
// HTTP 服务，对外暴露 REST/JSON API，并托管 web/ 下的纯 HTML/JS 前端。所有抓包 / 解析 /
// 入库 / 查询逻辑仍然只经 AnalysisSession 门面——本文件只做“HTTP 请求 ↔ 门面调用”的装配，
// 不碰任何 tshark / 数据库细节。这样引擎可跑在无图形界面的机器上，用户从浏览器远程访问。
//
// 线程约定：httplib 每个连接一个线程，处理器可能并发进入。门面约定“快照读线程安全，但
// 载入/抓包等写操作需调用方串行化”，故这里用一把 opMutex_ 把所有会改会话状态的处理器串起来
// （单用户分析工具吞吐无压力，粗粒度锁最简单也最安全）。实时抓包的回调在抓包线程执行，只把
// 包推进带独立锁的 liveBuffer_，与 opMutex_ 互不阻塞。
//
// 安全：默认只绑 127.0.0.1，远程访问请走 SSH 端口转发，不要裸绑 0.0.0.0（本服务会驱动
// 特权抓包）。可用命令行参数或环境变量覆盖 host/port。

#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "AnalysisSession.hpp"
#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"
#include "tsharkDataType.hpp"
#include "utils.hpp"

namespace
{
using PacketPtr = std::shared_ptr<Packet>;

// ---- 服务器共享状态 ----
struct WebState
{
    AnalysisSession& session;

    // 串行化所有会改会话状态（载入 / 抓包 / 过滤 / 查询 / 取详情）的处理器，满足门面的
    // “写操作需调用方串行化”约定；同时避免并发处理器交叉驱动 analyzer_/tshark 子进程。
    std::mutex opMutex;

    // 实时抓包缓冲：抓包途中 packetsSnapshot() 为空，实时包只经 onPacket 回调而来，
    // 先攒在这里（独立锁），前端按 since 增量轮询取走（对应 GUI 的 liveIncoming/drainLive）。
    std::mutex             liveMutex;
    std::vector<PacketPtr> liveBuffer;

    explicit WebState(AnalysisSession& s) : session(s) {}
};

// ---- 小工具 ----

void sendJson(httplib::Response& res, const std::string& body, int status = 200)
{
    res.status = status;
    res.set_content(body, "application/json; charset=utf-8");
}

// 统一的错误响应：{"error":"..."}（消息里的引号 / 反斜杠做最小转义，避免拼坏 JSON）。
void sendError(httplib::Response& res, const std::string& msg, int status = 500)
{
    std::string escaped;
    escaped.reserve(msg.size() + 8);
    for (char c : msg)
    {
        if (c == '"' || c == '\\')
            escaped.push_back('\\');
        if (c == '\n' || c == '\r' || c == '\t')
            escaped.push_back(' ');
        else
            escaped.push_back(c);
    }
    sendJson(res, "{\"error\":\"" + escaped + "\"}", status);
}

// 解析请求体 JSON；失败返回 false。空体按空对象处理（无字段即可）。
bool parseBody(const httplib::Request& req, rapidjson::Document& doc)
{
    if (req.body.empty())
    {
        doc.SetObject();
        return true;
    }
    doc.Parse(req.body.c_str());
    return !doc.HasParseError() && doc.IsObject();
}

// 取字符串字段；不存在或类型不符时置空串。
std::string jsonStr(const rapidjson::Document& doc, const char* key)
{
    if (doc.HasMember(key) && doc[key].IsString())
        return doc[key].GetString();
    return std::string();
}

// 把协议分层树递归序列化成 rapidjson 值：{label,value,children:[...]}。
// DetailNode 只承载展示文本，这里逐层拷贝即可（详情单包解析，规模小，不必用 StringRef）。
rapidjson::Value detailToJson(const DetailNode& node, rapidjson::Document::AllocatorType& alloc)
{
    rapidjson::Value obj(rapidjson::kObjectType);
    obj.AddMember("label", rapidjson::Value(node.label.c_str(), alloc), alloc);
    obj.AddMember("value", rapidjson::Value(node.value.c_str(), alloc), alloc);

    rapidjson::Value children(rapidjson::kArrayType);
    for (const DetailNode& child : node.children)
        children.PushBack(detailToJson(child, alloc), alloc);
    obj.AddMember("children", children, alloc);
    return obj;
}

std::string toHexString(const std::vector<unsigned char>& bytes)
{
    static const char* kHex = "0123456789abcdef";
    std::string        out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes)
    {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

// ---- 路由注册 ----

void registerRoutes(httplib::Server& svr, WebState& st)
{
    // 服务运行状态：前端轮询用（实时抓包时据此拉取增量、更新计数）。
    svr.Get("/api/status", [&st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st.opMutex);
        size_t                      liveCount;
        {
            std::lock_guard<std::mutex> llk(st.liveMutex);
            liveCount = st.liveBuffer.size();
        }
        std::string body = "{\"capturing\":" +
                           std::string(st.session.isCapturing() ? "true" : "false") +
                           ",\"count\":" + std::to_string(st.session.packetCount()) +
                           ",\"live\":" + std::to_string(liveCount) + "}";
        sendJson(res, body);
    });

    // 报文列表：
    //   - 带 ?since=N：返回实时缓冲区中下标 N 起的增量（抓包途中用）。
    //   - 不带 since：返回已解析入库后的完整快照（离线 / 抓包停止后）。
    // 两条路径都复用 CommonUtil::packetsToJson，与 CLI/GUI 的查询序列化同一份字段约定。
    svr.Get("/api/packets", [&st](const httplib::Request& req, httplib::Response& res)
    {
        if (req.has_param("since"))
        {
            size_t since = static_cast<size_t>(std::strtoul(req.get_param_value("since").c_str(),
                                                            nullptr, 10));
            std::vector<PacketPtr>      slice;
            {
                std::lock_guard<std::mutex> llk(st.liveMutex);
                if (since < st.liveBuffer.size())
                    slice.assign(st.liveBuffer.begin() + since, st.liveBuffer.end());
            }
            sendJson(res, CommonUtil::packetsToJson(slice));
            return;
        }

        std::lock_guard<std::mutex> lk(st.opMutex);
        sendJson(res, CommonUtil::packetsToJson(st.session.packetsSnapshot()));
    });

    // 指定帧号的原始字节（十六进制视图）。
    svr.Get(R"(/api/hex/(\d+))", [&st](const httplib::Request& req, httplib::Response& res)
    {
        uint32_t                    frame = static_cast<uint32_t>(std::stoul(req.matches[1]));
        std::lock_guard<std::mutex> lk(st.opMutex);
        std::vector<unsigned char>  bytes;
        if (!st.session.getHex(frame, bytes))
        {
            sendError(res, "取十六进制失败（帧不存在或文件未就绪）", 404);
            return;
        }
        sendJson(res, "{\"frame\":" + std::to_string(frame) + ",\"hex\":\"" + toHexString(bytes) +
                          "\"}");
    });

    // 指定帧号的协议分层树（详情面板）。
    svr.Get(R"(/api/detail/(\d+))", [&st](const httplib::Request& req, httplib::Response& res)
    {
        uint32_t                    frame = static_cast<uint32_t>(std::stoul(req.matches[1]));
        std::lock_guard<std::mutex> lk(st.opMutex);
        DetailNode                  root;
        if (!st.session.getDetailTree(frame, root))
        {
            sendError(res, "解析协议详情失败（帧不存在或文件未就绪）", 404);
            return;
        }
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Value tree = detailToJson(root, doc.GetAllocator());
        doc.AddMember("detail", tree, doc.GetAllocator());
        rapidjson::StringBuffer                    buf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
        doc.Accept(writer);
        sendJson(res, buf.GetString());
    });

    // 载入并解析服务器本地的一个 pcap 文件（注意：路径在服务器端文件系统解析）。
    svr.Post("/api/load", [&st](const httplib::Request& req, httplib::Response& res)
    {
        rapidjson::Document doc;
        if (!parseBody(req, doc))
        {
            sendError(res, "请求体不是合法 JSON", 400);
            return;
        }
        std::string path = jsonStr(doc, "path");
        if (path.empty())
        {
            sendError(res, "缺少 path 字段", 400);
            return;
        }
        std::lock_guard<std::mutex> lk(st.opMutex);
        try
        {
            if (!st.session.loadPcap(path))
            {
                sendError(res, "载入/解析 pcap 失败");
                return;
            }
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("载入失败：") + e.what());
            return;
        }
        sendJson(res, "{\"ok\":true,\"count\":" + std::to_string(st.session.packetCount()) + "}");
    });

    // tshark 显示过滤（-Y）：在当前报文集上按表达式筛选，返回命中的子集。
    svr.Post("/api/filter", [&st](const httplib::Request& req, httplib::Response& res)
    {
        rapidjson::Document doc;
        if (!parseBody(req, doc))
        {
            sendError(res, "请求体不是合法 JSON", 400);
            return;
        }
        std::string expr = jsonStr(doc, "expr");
        if (expr.empty())
        {
            sendError(res, "缺少 expr 字段", 400);
            return;
        }
        std::lock_guard<std::mutex> lk(st.opMutex);
        std::vector<PacketPtr>      out;
        try
        {
            if (!st.session.queryDisplayFilter(expr, out))
            {
                sendError(res, "过滤失败（表达式非法或文件未就绪）");
                return;
            }
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("过滤失败：") + e.what());
            return;
        }
        sendJson(res, CommonUtil::packetsToJson(out));
    });

    // 结构化查询（MAC/IP/端口/归属地，参数化防注入）。门面 query() 已直接返回 JSON，透传。
    svr.Post("/api/query", [&st](const httplib::Request& req, httplib::Response& res)
    {
        rapidjson::Document doc;
        if (!parseBody(req, doc))
        {
            sendError(res, "请求体不是合法 JSON", 400);
            return;
        }
        std::map<std::string, std::string> cond;
        const char* keys[] = {"mac_address", "ip_address", "port", "location"};
        for (const char* k : keys)
        {
            std::string v = jsonStr(doc, k);
            if (!v.empty())
                cond[k] = v;
        }
        if (cond.empty())
        {
            sendError(res, "未指定任何查询条件", 400);
            return;
        }
        std::lock_guard<std::mutex> lk(st.opMutex);
        std::string                 jsonResult;
        if (!st.session.query(cond, jsonResult))
        {
            sendError(res, "查询失败（是否已载入 pcap？）");
            return;
        }
        sendJson(res, jsonResult);
    });

    // 网卡列表（实时抓包用）。listAdapters 会启动 tshark，未安装时抛异常，须兜住。
    svr.Get("/api/adapters", [&st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st.opMutex);
        try
        {
            std::vector<AdapterInfo> adapters = st.session.listAdapters();
            rapidjson::Document      doc;
            doc.SetArray();
            rapidjson::Document::AllocatorType& alloc = doc.GetAllocator();
            for (const AdapterInfo& a : adapters)
            {
                rapidjson::Value obj(rapidjson::kObjectType);
                obj.AddMember("id", a.id, alloc);
                obj.AddMember("name", rapidjson::Value(a.name.c_str(), alloc), alloc);
                obj.AddMember("remark", rapidjson::Value(a.remark.c_str(), alloc), alloc);
                doc.PushBack(obj, alloc);
            }
            rapidjson::StringBuffer                    buf;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
            doc.Accept(writer);
            sendJson(res, buf.GetString());
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("获取网卡失败：") + e.what() + "（请确认已安装 Wireshark）");
        }
    });

    // 开始实时抓包：清空 live 缓冲，回调把每个包推进缓冲（前端按 since 增量轮询）。
    svr.Post("/api/capture/start", [&st](const httplib::Request& req, httplib::Response& res)
    {
        rapidjson::Document doc;
        if (!parseBody(req, doc))
        {
            sendError(res, "请求体不是合法 JSON", 400);
            return;
        }
        std::string adapter = jsonStr(doc, "adapter");
        if (adapter.empty())
        {
            sendError(res, "缺少 adapter 字段", 400);
            return;
        }
        std::lock_guard<std::mutex> lk(st.opMutex);
        if (st.session.isCapturing())
        {
            sendError(res, "已在抓包中", 409);
            return;
        }
        {
            std::lock_guard<std::mutex> llk(st.liveMutex);
            st.liveBuffer.clear();
        }
        WebState* sp = &st; // 回调在抓包线程执行：只把包推进带锁缓冲，绝不碰其它状态
        bool      ok = false;
        try
        {
            ok = st.session.startLiveCapture(adapter, [sp](const PacketPtr& p)
            {
                std::lock_guard<std::mutex> llk(sp->liveMutex);
                sp->liveBuffer.push_back(p);
            });
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("启动抓包失败：") + e.what());
            return;
        }
        if (!ok)
        {
            sendError(res, "启动抓包失败（检查网卡 / 抓包权限）");
            return;
        }
        sendJson(res, "{\"ok\":true}");
    });

    // 停止抓包并解析入库：完成后 packetsSnapshot() 才有完整结果、hex/详情才可用。
    svr.Post("/api/capture/stop", [&st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st.opMutex);
        try
        {
            if (!st.session.stopLiveCapture())
            {
                sendError(res, "停止抓包或解析失败");
                return;
            }
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("停止失败：") + e.what());
            return;
        }
        sendJson(res, "{\"ok\":true,\"count\":" + std::to_string(st.session.packetCount()) + "}");
    });

    // tshark 路径：GET 查看当前解析到的路径与可用性；POST 手动指定（无需重编译）。
    svr.Get("/api/tshark", [&st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st.opMutex);
        std::string                 path      = st.session.tsharkPath();
        bool                        available = TsharkCommand::tsharkAvailable(path);
        std::string                 escaped;
        for (char c : path)
        {
            if (c == '"' || c == '\\')
                escaped.push_back('\\');
            escaped.push_back(c);
        }
        sendJson(res, "{\"path\":\"" + escaped + "\",\"available\":" +
                          (available ? "true" : "false") + "}");
    });

    svr.Post("/api/tshark", [&st](const httplib::Request& req, httplib::Response& res)
    {
        rapidjson::Document doc;
        if (!parseBody(req, doc))
        {
            sendError(res, "请求体不是合法 JSON", 400);
            return;
        }
        std::string path = jsonStr(doc, "path");
        if (path.empty())
        {
            sendError(res, "缺少 path 字段", 400);
            return;
        }
        std::lock_guard<std::mutex> lk(st.opMutex);
        st.session.setTsharkPath(path);
        bool available = TsharkCommand::tsharkAvailable(path);
        sendJson(res, "{\"ok\":true,\"available\":" + std::string(available ? "true" : "false") +
                          "}");
    });
}

// 在若干候选目录里找到静态前端目录（源码树 web/ 与产物 output/web 都可能是运行时 cwd 的相对位置）。
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

    if (const char* h = std::getenv("EASYTSHARK_WEB_HOST"))
        host = h;
    if (const char* p = std::getenv("EASYTSHARK_WEB_PORT"))
        port = std::atoi(p);
    for (int i = 1; i + 1 < argc; i += 2)
    {
        std::string flag = argv[i];
        if (flag == "--host")
            host = argv[i + 1];
        else if (flag == "--port")
            port = std::atoi(argv[i + 1]);
    }

    std::string ts = CommonUtil::get_timestamp();
    loguru::add_file(("logs/web_" + ts + ".log").c_str(), loguru::Append, loguru::Verbosity_MAX);

    // 自动定位 tshark：环境变量 EASYTSHARK_TSHARK → 默认路径 → PATH →（Win）注册表 → 常见目录。
    AnalysisSession session(TsharkCommand::resolveTsharkPath(), "data");
    if (!TsharkCommand::tsharkAvailable(session.tsharkPath()))
    {
        LOG_F(WARNING, "未检测到 tshark（%s）。抓包/解析类接口会失败，请安装 Wireshark：%s",
              session.tsharkPath().c_str(), TsharkCommand::wiresharkDownloadUrl().c_str());
    }

    WebState        state(session);
    httplib::Server svr;
    registerRoutes(svr, state);

    // 托管静态前端；根路径重定向到 index.html。
    std::string webRoot = resolveWebRoot();
    if (!svr.set_mount_point("/", webRoot))
        LOG_F(WARNING, "静态目录挂载失败：%s（API 仍可用，页面不可用）", webRoot.c_str());

    LOG_F(INFO, "EasyTshark Web 服务启动：http://%s:%d  （静态目录 %s）", host.c_str(), port,
          webRoot.c_str());
    std::printf("EasyTshark Web 服务已启动：http://%s:%d\n", host.c_str(), port);
    std::printf("（默认只绑本机回环；远程访问请用 SSH 端口转发，勿裸绑 0.0.0.0）\n");
    std::fflush(stdout);

    if (!svr.listen(host.c_str(), port))
    {
        std::fprintf(stderr, "监听 %s:%d 失败（端口被占用？）\n", host.c_str(), port);
        return 1;
    }
    return 0;
}
