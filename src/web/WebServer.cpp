// EasyTshark Web 前端路由层：把 HTTP 路由、令牌鉴权、Origin 校验、/api/load 路径白名单集中于此，
// 生产入口与单元测试复用。所有逻辑经 AnalysisSession 门面，本文件只做 HTTP 请求 ↔ 门面调用的装配。
//
// 线程：httplib 每连接一线程，处理器可能并发进入；用 opMutex_ 串行化所有写操作（粗粒度锁，
// 单用户工具足够）；实时抓包回调在抓包线程执行，只推进带独立锁的 liveBuffer_，与 opMutex_ 互不阻塞。
// 安全：所有 /api/* 须带 X-Auth-Token；浏览器请求还校验 Origin==Host（防 DNS rebinding）；
// /api/load 仅允许用户主目录或 data/ 下的文件。静态资源不要求 token。

#include <climits>
#include <cstdlib>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <direct.h> // _fullpath
#endif

#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"
#include "tsharkDataType.hpp"
#include "utils.hpp"
#include "web/WebServer.hpp"

namespace
{
using PacketPtr = std::shared_ptr<Packet>;

// ---- 服务器共享状态 ----
struct WebState
{
    AnalysisSession& session;

    // 访问令牌：所有 /api/* 请求须带 X-Auth-Token 头。
    std::string token;

    // 串行化所有会改会话状态的处理器，满足门面“写操作需调用方串行化”约定。
    std::mutex opMutex;

    // 实时抓包缓冲：实时包经 onPacket 回调攒在此（独立锁），前端按 since 增量轮询取走。
    // 上限 kMaxLiveBuffer：超限丢弃最旧包避免内存无限增长；liveBase 记录已丢弃数，
    // 使前端 since 绝对序号语义不变。
    static const size_t kMaxLiveBuffer = 100000;
    std::mutex          liveMutex;
    std::deque<PacketPtr> liveBuffer;
    size_t                liveBase = 0;

    explicit WebState(AnalysisSession& s, std::string tok) : session(s), token(std::move(tok)) {}
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

// 访问令牌校验：/api/* 须带 X-Auth-Token 且与令牌一致。静态资源不带 token，不受影响。
bool authorized(const httplib::Request& req, const std::string& token)
{
    const std::string& got = req.get_header_value("X-Auth-Token");
    if (token.empty() || got.size() != token.size())
        return false;
    // 恒定时间比较：逐字节累积异或，不因首个不同字节而提前返回，消除计时侧信道。
    unsigned char diff = 0;
    for (size_t i = 0; i < token.size(); ++i)
        diff |= static_cast<unsigned char>(got[i] ^ token[i]);
    return diff == 0;
}

// 浏览器跨站防御：带 Origin 头时其 host 必须与 Host 头一致，否则视为 DNS rebinding 拒绝。
// 非浏览器（curl）无 Origin 头，仍须通过 token 校验。
bool originAllowed(const httplib::Request& req)
{
    const std::string& origin = req.get_header_value("Origin");
    if (origin.empty() || origin == "null") // 无 Origin（curl）或 file:// 打开的页面
        return true;                        // （后者仍过不了 token 校验）
    const std::string& host = req.get_header_value("Host");
    if (host.empty())
        return false;
    // Origin 形如 http://host:port 或 https://host:port，取 "//" 后的 host[:port] 部分
    size_t scheme = origin.find("://");
    std::string originHost =
        scheme == std::string::npos ? origin : origin.substr(scheme + 3);
    // 去掉可能的尾部 '/'（Origin 规范不带，但防御性处理）
    while (!originHost.empty() && originHost.back() == '/')
        originHost.pop_back();
    return originHost == host;
}

// 把路径规范为绝对路径（POSIX realpath，Windows _fullpath）；文件不存在时返回空串。
std::string normalizePath(const std::string& p)
{
    if (p.empty())
        return std::string();
#if defined(_WIN32)
    char buf[MAX_PATH];
    if (_fullpath(buf, p.c_str(), MAX_PATH) != nullptr)
        return std::string(buf);
    return std::string();
#else
    char buf[PATH_MAX];
    if (realpath(p.c_str(), buf) != nullptr)
        return std::string(buf);
    return std::string();
#endif
}

// 路径前缀匹配：abs 等于 root，或以 root + 路径分隔符开头。
bool pathUnder(const std::string& abs, const std::string& root)
{
    if (abs == root)
        return true;
    if (root.empty() || abs.size() <= root.size())
        return false;
#if defined(_WIN32)
    bool sep = abs[root.size()] == '\\' || abs[root.size()] == '/';
#else
    bool sep = abs[root.size()] == '/';
#endif
    return sep && abs.compare(0, root.size(), root) == 0;
}

// /api/load 路径白名单：只允许用户主目录或 data/ 下的文件，避免任意文件被读取解析。
bool isPathAllowed(const std::string& p)
{
    std::string abs = normalizePath(p);
    if (abs.empty())
    {
        // 文件不存在时回退检查父目录归属（realpath 对不存在路径失败，但越权判断只看路径归属）。
        size_t slash = p.find_last_of("/\\");
        if (slash == std::string::npos)
            return false;
        abs = normalizePath(p.substr(0, slash));
        if (abs.empty())
            return false;
    }
#if defined(_WIN32)
    std::string home;
    if (const char* h = std::getenv("USERPROFILE"))
        home = h;
#else
    std::string home;
    if (const char* h = std::getenv("HOME"))
        home = h;
#endif
    if (!home.empty() && pathUnder(abs, home))
        return true;
    std::string dataAbs = normalizePath("data");
    return !dataAbs.empty() && pathUnder(abs, dataAbs);
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

void registerRoutes(httplib::Server& svr, std::shared_ptr<WebState> st)
{
    // 全局鉴权（pre-routing）：/api/* 须通过 token + Origin 双重校验；静态资源放行。
    svr.set_pre_routing_handler([st](const httplib::Request& req, httplib::Response& res)
    {
        if (req.path.compare(0, 5, "/api/") != 0 && req.path != "/api")
            return httplib::Server::HandlerResponse::Unhandled; // 静态资源放行
        if (!authorized(req, st->token))
        {
            sendError(res, "未授权：请提供 X-Auth-Token 头（令牌见服务器启动输出）", 401);
            return httplib::Server::HandlerResponse::Handled;
        }
        if (!originAllowed(req))
        {
            sendError(res, "跨站请求被拒绝：Origin 与 Host 不一致", 403);
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 服务运行状态：前端轮询用（实时抓包时据此拉取增量、更新计数）。
    svr.Get("/api/status", [st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st->opMutex);
        size_t                      liveCount;
        {
            std::lock_guard<std::mutex> llk(st->liveMutex);
            liveCount = st->liveBuffer.size();
        }
        std::string body = "{\"capturing\":" +
                           std::string(st->session.isCapturing() ? "true" : "false") +
                           ",\"count\":" + std::to_string(st->session.packetCount()) +
                           ",\"live\":" + std::to_string(liveCount) + "}";
        sendJson(res, body);
    });

    // 报文列表三种模式：?since=N 取实时缓冲增量（N 为绝对序号，丢旧包时后端自动对齐）；
    //   ?page=P&pageSize=S 分页返回快照切片；无参数返回完整快照。
    svr.Get("/api/packets", [st](const httplib::Request& req, httplib::Response& res)
    {
        if (req.has_param("since"))
        {
            size_t since = static_cast<size_t>(std::strtoul(req.get_param_value("since").c_str(),
                                                            nullptr, 10));
            std::vector<PacketPtr> slice;
            {
                std::lock_guard<std::mutex> llk(st->liveMutex);
                size_t start = since >= st->liveBase ? since - st->liveBase : 0;
                if (start < st->liveBuffer.size())
                    slice.assign(st->liveBuffer.begin() + start, st->liveBuffer.end());
            }
            sendJson(res, CommonUtil::packetsToJson(slice));
            return;
        }

        if (req.has_param("page"))
        {
            long page = std::strtol(req.get_param_value("page").c_str(), nullptr, 10);
            long pageSize =
                req.has_param("pageSize")
                    ? std::strtol(req.get_param_value("pageSize").c_str(), nullptr, 10)
                    : 100;
            if (page < 0)
                page = 0;
            if (pageSize < 1)
                pageSize = 1;
            if (pageSize > 1000)
                pageSize = 1000; // 单页上限，防手滑拉爆

            std::lock_guard<std::mutex> lk(st->opMutex);
            auto                        snap = st->session.packetsSnapshot();
            if (!snap)
            {
                sendJson(res,
                         "{\"total\":0,\"page\":0,\"pageSize\":" + std::to_string(pageSize) +
                             ",\"packets\":[]}");
                return;
            }
            size_t total = snap->size();
            size_t begin = static_cast<size_t>(page) * pageSize;
            if (begin >= total)
            {
                begin = 0; // 越界（如删除后页码失效）回首页
                page  = 0;
            }
            size_t end = std::min(total, begin + static_cast<size_t>(pageSize));
            std::vector<PacketPtr> slice(snap->begin() + begin, snap->begin() + end);

            // 用 rapidjson 组装 {total,page,pageSize,packets:[...]}，packets 复用 packetsToJson 结果。
            rapidjson::Document doc;
            doc.SetObject();
            doc.AddMember("total", static_cast<uint64_t>(total), doc.GetAllocator());
            doc.AddMember("page", static_cast<int>(page), doc.GetAllocator());
            doc.AddMember("pageSize", static_cast<int>(pageSize), doc.GetAllocator());
            rapidjson::Document innerDoc;
            innerDoc.Parse(CommonUtil::packetsToJson(slice).c_str());
            rapidjson::Value packetsVal;
            packetsVal.CopyFrom(innerDoc["packets"], doc.GetAllocator());
            doc.AddMember("packets", packetsVal, doc.GetAllocator());
            rapidjson::StringBuffer                    buf;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
            doc.Accept(writer);
            sendJson(res, buf.GetString());
            return;
        }

        std::lock_guard<std::mutex> lk(st->opMutex);
        auto                        snap = st->session.packetsSnapshot();
        sendJson(res, CommonUtil::packetsToJson(*snap));
    });

    // 指定帧号的原始字节（十六进制视图）。
    svr.Get(R"(/api/hex/(\d+))", [st](const httplib::Request& req, httplib::Response& res)
    {
        // 用 strtoul 而非会抛 out_of_range 的 stoul：超长数字串越界返回 ULONG_MAX，自然走 404。
        uint32_t                    frame =
            static_cast<uint32_t>(std::strtoul(req.matches[1].str().c_str(), nullptr, 10));
        std::lock_guard<std::mutex> lk(st->opMutex);
        std::vector<unsigned char>  bytes;
        if (!st->session.getHex(frame, bytes))
        {
            sendError(res, "取十六进制失败（帧不存在或文件未就绪）", 404);
            return;
        }
        sendJson(res, "{\"frame\":" + std::to_string(frame) + ",\"hex\":\"" + toHexString(bytes) +
                          "\"}");
    });

    // 指定帧号的协议分层树（详情面板）。
    svr.Get(R"(/api/detail/(\d+))", [st](const httplib::Request& req, httplib::Response& res)
    {
        uint32_t                    frame =
            static_cast<uint32_t>(std::strtoul(req.matches[1].str().c_str(), nullptr, 10));
        std::lock_guard<std::mutex> lk(st->opMutex);
        DetailNode                  root;
        if (!st->session.getDetailTree(frame, root))
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
    svr.Post("/api/load", [st](const httplib::Request& req, httplib::Response& res)
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
        std::lock_guard<std::mutex> lk(st->opMutex);
        // 路径白名单：只允许载入用户主目录 / data/ 下的文件，避免任意文件被读取。
        if (!isPathAllowed(path))
        {
            sendError(res, "路径不在允许范围内（仅限用户主目录或 data/ 下的文件）", 403);
            return;
        }
        try
        {
            if (!st->session.loadPcap(path))
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
        sendJson(res, "{\"ok\":true,\"count\":" + std::to_string(st->session.packetCount()) + "}");
    });

    // tshark 显示过滤（-Y）：在当前报文集上按表达式筛选，返回命中的子集。
    svr.Post("/api/filter", [st](const httplib::Request& req, httplib::Response& res)
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
        std::lock_guard<std::mutex> lk(st->opMutex);
        std::vector<PacketPtr>      out;
        std::string                 filterErr;
        try
        {
            if (!st->session.queryDisplayFilter(expr, out, &filterErr))
            {
                // 透传 tshark 的具体报错（如字段名拼错），比笼统的“过滤失败”有用得多
                sendError(res, filterErr.empty() ? std::string("过滤失败（表达式非法或文件未就绪）")
                                                 : std::string("过滤失败：") + filterErr);
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
    svr.Post("/api/query", [st](const httplib::Request& req, httplib::Response& res)
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
        std::lock_guard<std::mutex> lk(st->opMutex);
        std::string                 jsonResult;
        if (!st->session.query(cond, jsonResult))
        {
            sendError(res, "查询失败（是否已载入 pcap？）");
            return;
        }
        sendJson(res, jsonResult);
    });

    // 网卡列表（实时抓包用）。listAdapters 会启动 tshark，未安装时抛异常，须兜住。
    svr.Get("/api/adapters", [st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st->opMutex);
        try
        {
            std::vector<AdapterInfo> adapters = st->session.listAdapters();
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
    svr.Post("/api/capture/start", [st](const httplib::Request& req, httplib::Response& res)
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
        std::lock_guard<std::mutex> lk(st->opMutex);
        if (st->session.isCapturing())
        {
            sendError(res, "已在抓包中", 409);
            return;
        }
        {
            std::lock_guard<std::mutex> llk(st->liveMutex);
            st->liveBuffer.clear();
            st->liveBase = 0;
        }
        WebState* sp = st.get(); // 回调在抓包线程执行：只把包推进带锁缓冲，绝不碰其它状态
        bool      ok = false;
        try
        {
            ok = st->session.startLiveCapture(adapter, [sp](const PacketPtr& p)
            {
                std::lock_guard<std::mutex> llk(sp->liveMutex);
                sp->liveBuffer.push_back(p);
                // 上限：每包至多丢弃 1 个最旧包，deque::pop_front 为 O(1)
                if (sp->liveBuffer.size() > WebState::kMaxLiveBuffer)
                {
                    sp->liveBuffer.pop_front();
                    ++sp->liveBase;
                }
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
    svr.Post("/api/capture/stop", [st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st->opMutex);
        try
        {
            if (!st->session.stopLiveCapture())
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
        sendJson(res, "{\"ok\":true,\"count\":" + std::to_string(st->session.packetCount()) + "}");
    });

    // tshark 路径：GET 查看当前解析到的路径与可用性；POST 手动指定（无需重编译）。
    svr.Get("/api/tshark", [st](const httplib::Request&, httplib::Response& res)
    {
        std::lock_guard<std::mutex> lk(st->opMutex);
        std::string                 path      = st->session.tsharkPath();
        bool                        available = TsharkCommand::tsharkAvailable(path);
        std::string                 escaped;
        for (char c : path)
        {
            if (c == '"' || c == '\\')
                escaped.push_back('\\');
            escaped.push_back(c);
        }
        sendJson(res, "{\"path\":\"" + escaped + "\",\"available\":" +
                          (available ? "true" : "false") + ",\"engine\":\"" +
                          st->session.engineName() + "\"}");
    });

    svr.Post("/api/tshark", [st](const httplib::Request& req, httplib::Response& res)
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
        std::lock_guard<std::mutex> lk(st->opMutex);
        st->session.setTsharkPath(path);
        bool available = TsharkCommand::tsharkAvailable(path);
        sendJson(res, "{\"ok\":true,\"available\":" + std::string(available ? "true" : "false") +
                          "}");
    });

    // 导出当前报文快照为 CSV（服务器端路径），供 Excel / 数据分析工具二次加工。
    // 路径同样受白名单约束（只写用户主目录或 data/ 下）。
    svr.Post("/api/export/csv", [st](const httplib::Request& req, httplib::Response& res)
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
        if (!isPathAllowed(path))
        {
            sendError(res, "路径不在允许范围内（仅限用户主目录或 data/ 下的文件）", 403);
            return;
        }
        std::lock_guard<std::mutex> lk(st->opMutex);
        try
        {
            if (!st->session.exportPacketsCsv(path))
            {
                sendError(res, "导出 CSV 失败（是否已载入 pcap？）");
                return;
            }
        }
        catch (const std::exception& e)
        {
            sendError(res, std::string("导出 CSV 失败：") + e.what());
            return;
        }
        sendJson(res, "{\"ok\":true,\"path\":\"" + path + "\"}");
    });
}
} // namespace

void registerWebRoutes(httplib::Server& svr, AnalysisSession& session,
                       const std::string& token)
{
    std::shared_ptr<WebState> state(new WebState(session, token));
    registerRoutes(svr, state);
}
