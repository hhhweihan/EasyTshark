// EasyTshark 原生前端
//
// 用 Dear ImGui（即时模式 GUI）+ GLFW/OpenGL3 后端把核心能力可视化。UI 只通过
// AnalysisSession 门面访问数据，不直接触碰 tshark / 解析 / 数据库细节——这就是
// 项目里的“核心库 ↔ UI 层”边界（同进程，不是网络前后端分离）。
//
// 布局采用 Tab 风格（顶部工具栏 + 过滤栏 + 报文/会话/统计/查询 分页 + 底部状态栏），
// 在此之上补齐各分页的功能与显示。
//
// 线程约定：耗时操作（载入 pcap、停止抓包后解析入库）放到 std::async 的后台任务里跑，
// UI 线程每帧只轮询任务是否完成，从不阻塞在解析上；完成后在 UI 线程刷新报文快照。

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#include "AnalysisSession.hpp"
#include "tsharkCommand.hpp"
#include "tsharkDataType.hpp"

namespace
{

using PacketPtr = std::shared_ptr<Packet>;

// ---- 会话 / 统计聚合的数据结构 ----

// 一条通信会话（按五元组归并的双向流）：端点、传输层、涉及的协议集合、包数/字节数。
struct SessionInfo
{
    std::string           endpointA; // 规范化后较小的一端 "ip:port"
    std::string           endpointB; // 较大的一端
    std::string           transport; // TCP / UDP / 空
    std::set<std::string> protocols; // 出现过的最高层协议（DNS/HTTP/TLS...）
    uint64_t              packets = 0;
    uint64_t              bytes   = 0;
};

// 计数条目（IP / 协议 / 归属地统计共用）：名字 + 包数 + 字节数。
struct CountItem
{
    std::string name;
    uint64_t    packets = 0;
    uint64_t    bytes   = 0;
};

// 界面状态：把一次会话的 UI 侧数据集中在一处，便于各面板读写。
struct AppState
{
    AnalysisSession& session;

    // 报文列表快照（从门面拷贝而来，UI 线程独占，绘制时不加锁）
    std::vector<PacketPtr> packets;
    PacketPtr              selectedPkt;        // 选中的报文（用指针而非下标，兼容分页/过滤）
    std::vector<unsigned char> hex;            // 选中包的原始字节
    uint32_t                   hexFrame = 0;   // hex 对应的帧号
    DetailNode                 detail;         // 选中包的协议分层树
    bool                       detailLoaded = false;

    // 过滤：view = 在 (全部 或 显示过滤结果) 基础上再按协议快速分类筛选后的可见集合
    std::vector<PacketPtr> view;
    bool                   viewDirty         = true;
    int                    protoCategory     = 0;     // 0全部 1ARP 2ICMP 3ICMPv6
    char                   filterExpr[256]   = {0};   // tshark 显示过滤表达式
    bool                   displayFilterOn   = false;
    std::vector<PacketPtr> displayFiltered;           // tshark -Y 命中的报文子集

    // 分页（非实时抓包时生效）
    int pageSize = 100;
    int page     = 0; // 0-based

    // 离线载入 / 保存
    char pcapPathInput[512] = {0};
    char savePathInput[512] = {0};

    // 抓包
    std::vector<AdapterInfo> adapters;
    char                     adapterName[128] = {0};

    // 实时抓包：抓包线程通过回调把包投进 liveIncoming（加锁），UI 线程每帧取出
    // 追加到 packets，实现边抓边显示。liveCapturing 标记当前处于实时模式。
    std::mutex             liveMutex;
    std::vector<PacketPtr> liveIncoming;
    bool                   liveCapturing = false;
    bool                   autoScroll    = true;

    // 会话 / 统计的缓存：仅当报文数量变化时重建，避免每帧 O(N) 聚合。
    size_t                   analyticsBuiltCount = (size_t)-1;
    std::vector<SessionInfo> sessions;
    std::vector<CountItem>   ipStats;
    std::vector<CountItem>   protoStats;
    std::vector<CountItem>   locStats;
    int                      sessionCategory = 0; // 0全部 1TCP 2UDP 3DNS 4HTTP 5TLS 6SSH

    // 状态栏用的廉价累加值（增量维护，不每帧遍历）
    uint64_t totalBytes = 0;

    // 查询（结构化）
    char        qMac[128] = {0};
    char        qIp[128]  = {0};
    char        qPort[64] = {0};
    char        qLoc[128] = {0};
    std::string queryResult;

    // 后台任务
    std::future<bool>     pending;
    bool                  busy   = false;
    std::string           status = "就绪";
    std::function<void()> onDone; // 任务成功后在 UI 线程执行的收尾（刷新快照等）

    // 显示过滤的后台结果暂存：后台线程写 filterScratch，完成后在 UI 线程 swap 进
    // displayFiltered，避免后台改写 displayFiltered 与 UI 绘制读它竞态。
    std::vector<PacketPtr> filterScratch;

    // 选中报文协议详情的后台加载：getDetailTree 要新起一个 tshark 单包 PDML 解析
    // （约百毫秒），放后台避免每次点选卡 UI 帧。detailResult 由后台线程写、就绪后
    // pollDetail 在 UI 线程取用。detailDraining 暂存被新点选取代、尚未完成的旧任务，
    // 避免在点击处析构 std::async future 时阻塞 UI（其析构会 join 后台线程）。
    std::future<bool>              detailPending;
    std::shared_ptr<DetailNode>    detailResult;
    uint32_t                       detailFrame = 0;
    std::vector<std::future<bool>> detailDraining;

    // tshark 可执行文件路径输入框：允许用户在 GUI 里手动指定 tshark(.exe)，无需重编译。
    // 构造时用会话当前（已自动解析）的路径回填，方便查看/修改。
    char tsharkPathInput[512] = {0};

    explicit AppState(AnalysisSession& s) : session(s)
    {
        std::snprintf(tsharkPathInput, sizeof(tsharkPathInput), "%s", s.tsharkPath().c_str());
    }
};

// ---- 小工具 ----

bool containsIgnore(const std::string& hay, const char* needle)
{
    return hay.find(needle) != std::string::npos;
}

// 判断是否内网 / 环回地址（用于行内“内网”标签）。
bool isPrivateIp(const std::string& ip)
{
    if (ip.empty())
        return false;
    if (ip.compare(0, 3, "10.") == 0)
        return true;
    if (ip.compare(0, 8, "192.168.") == 0)
        return true;
    if (ip.compare(0, 4, "127.") == 0)
        return true;
    if (ip.compare(0, 4, "172.") == 0)
    {
        size_t dot = ip.find('.', 4);
        if (dot != std::string::npos)
        {
            int o = std::atoi(ip.substr(4, dot - 4).c_str());
            if (o >= 16 && o <= 31)
                return true;
        }
    }
    if (ip == "::1")
        return true;
    if (ip.compare(0, 4, "fe80") == 0)
        return true;
    if (ip.compare(0, 2, "fc") == 0 || ip.compare(0, 2, "fd") == 0)
        return true;
    return false;
}

// 协议名 → 颜色：为表格协议列提供彩色徽标，便于快速区分。
ImVec4 protocolColor(const std::string& proto)
{
    if (containsIgnore(proto, "TCP"))
        return ImVec4(0.55f, 0.75f, 1.00f, 1.0f); // 蓝
    if (containsIgnore(proto, "UDP"))
        return ImVec4(0.45f, 0.85f, 0.75f, 1.0f); // 青
    if (containsIgnore(proto, "DNS"))
        return ImVec4(1.00f, 0.72f, 0.35f, 1.0f); // 橙
    if (containsIgnore(proto, "HTTP"))
        return ImVec4(0.55f, 0.90f, 0.45f, 1.0f); // 绿
    if (containsIgnore(proto, "TLS") || containsIgnore(proto, "SSL"))
        return ImVec4(0.80f, 0.60f, 1.00f, 1.0f); // 紫
    if (containsIgnore(proto, "SSH"))
        return ImVec4(0.70f, 0.80f, 0.95f, 1.0f);
    if (containsIgnore(proto, "ICMP"))
        return ImVec4(1.00f, 0.55f, 0.70f, 1.0f); // 粉
    if (containsIgnore(proto, "ARP"))
        return ImVec4(0.95f, 0.90f, 0.45f, 1.0f); // 黄
    return ImVec4(0.80f, 0.80f, 0.80f, 1.0f);
}

// 把 frame.time_epoch（自 1970 起的秒，带小数）格式化成人类可读的本地时间
// "MM-DD HH:MM:SS.mmm"。原始时间戳信息量大但不直观，单独给一列易读时间。
// localtime 的静态缓冲不可重入，按平台用 localtime_s / localtime_r 写入栈上 tm。
std::string formatEpoch(double epoch)
{
    if (epoch <= 0.0)
        return "";
    std::time_t secs = static_cast<std::time_t>(epoch);
    int         ms   = static_cast<int>((epoch - static_cast<double>(secs)) * 1000.0 + 0.5);
    if (ms >= 1000) // 进位到下一秒，避免出现 ".1000"
    {
        ms = 0;
        secs += 1;
    }
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &secs);
#else
    localtime_r(&secs, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d-%02d %02d:%02d:%02d.%03d", tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    return buf;
}

// 报文是否属于当前协议快速分类（报文页左侧“数据包”类目的前端过滤）。
bool matchesCategory(const Packet& p, int cat)
{
    switch (cat)
    {
    case 1:
        return containsIgnore(p.protocol, "ARP");
    case 2:
        return p.protocol == "ICMP"; // 精确匹配，避免把 ICMPv6 也算进来
    case 3:
        return containsIgnore(p.protocol, "ICMPv6");
    default:
        return true; // 0：全部
    }
}

// ---- 后台任务调度 ----

void beginAsync(AppState& s, std::function<bool()> op, std::function<void()> done,
                const std::string& status)
{
    if (s.busy)
        return;
    s.busy    = true;
    s.status  = status;
    s.onDone  = std::move(done);
    s.pending = std::async(std::launch::async, std::move(op));
}

void pollAsync(AppState& s)
{
    if (!s.busy || !s.pending.valid())
        return;
    if (s.pending.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return;

    bool ok = false;
    try
    {
        ok = s.pending.get();
    }
    catch (const std::exception& e)
    {
        // 后台任务（载入 pcap、抓包、显示过滤等）内部启动 tshark 失败时会抛异常，
        // future::get 会在 UI 线程重新抛出。这里兜住，转成失败状态，避免闪退。
        ok       = false;
        s.busy   = false;
        s.status = std::string("失败：") + e.what();
        s.onDone = nullptr;
        return;
    }
    s.busy   = false;
    s.status = ok ? "完成" : "失败";
    if (ok && s.onDone)
        s.onDone(); // 放在默认状态文案之后：onDone 可写入更具体的状态（如“过滤命中 N”）
    s.onDone = nullptr;
}

// ---- 视图 / 选中 / 分析数据 ----

// 依据 显示过滤 + 协议分类 重建可见集合 view（非实时抓包时使用）。
void rebuildView(AppState& s)
{
    const std::vector<PacketPtr>& base = s.displayFilterOn ? s.displayFiltered : s.packets;
    s.view.clear();
    s.view.reserve(base.size());
    for (const PacketPtr& p : base)
    {
        if (matchesCategory(*p, s.protoCategory))
            s.view.push_back(p);
    }
    // 夹紧当前页码
    int totalPages = std::max(1, (int)((s.view.size() + s.pageSize - 1) / s.pageSize));
    if (s.page >= totalPages)
        s.page = totalPages - 1;
    if (s.page < 0)
        s.page = 0;
    s.viewDirty = false;
}

// 加载选中报文的 hex（同步、开销小）与协议分层树（后台、避免卡帧）
void loadSelected(AppState& s)
{
    s.hex.clear();
    s.detail       = DetailNode();
    s.detailLoaded = false;
    if (!s.selectedPkt)
        return;
    // 实时抓包途中离线分析尚未跑：随机读文件与 currentFilePath 都还没就绪，
    // 此时取 hex/详情必然失败（且会刷 ERR 日志）。等“停止并分析”后再取。
    if (s.liveCapturing)
        return;
    // 后台正在解析/入库时，analyzer_ 的文件与随机读取器正被改写，此刻取包会与之竞态；
    // 等任务完成（refreshPackets 后）再取。
    if (s.busy)
        return;

    uint32_t frame = (uint32_t)s.selectedPkt->frame_number;
    // hex 走 mmap 随机读，开销极小，直接同步取。
    if (s.session.getHex(frame, s.hex))
        s.hexFrame = frame;

    // 协议详情放后台：若上一次点选的任务还没跑完，先把它移进 draining 暂存，
    // 不在点击处析构其 future（那会 join 后台线程、阻塞 UI）；pollDetail 里就绪后回收。
    if (s.detailPending.valid())
        s.detailDraining.push_back(std::move(s.detailPending));
    s.detailResult                   = std::make_shared<DetailNode>();
    s.detailFrame                    = frame;
    AnalysisSession*            sess = &s.session;
    std::shared_ptr<DetailNode> out  = s.detailResult;
    s.detailPending                  = std::async(std::launch::async,
                                                  [sess, frame, out]() -> bool
                                                  {
                                     try
                                     {
                                         return sess->getDetailTree(frame, *out);
                                     }
                                     catch (...)
                                     {
                                         return false;
                                     }
                                                  });
}

// 每帧轮询协议详情后台任务：就绪则把结果搬到 s.detail 供详情面板绘制。
void pollDetail(AppState& s)
{
    // 回收已完成的被取代任务（其 future 析构会 join，故只回收已就绪的，避免阻塞）
    for (size_t i = 0; i < s.detailDraining.size();)
    {
        if (s.detailDraining[i].wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            s.detailDraining[i].get();
            s.detailDraining.erase(s.detailDraining.begin() + i);
        }
        else
        {
            ++i;
        }
    }

    if (!s.detailPending.valid())
        return;
    if (s.detailPending.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return;

    bool ok = s.detailPending.get();
    if (ok && s.detailResult)
    {
        s.detail       = std::move(*s.detailResult);
        s.detailLoaded = true;
    }
    else
    {
        s.detail       = DetailNode();
        s.detailLoaded = false;
    }
    s.detailResult.reset();
}

// 从门面刷新报文快照（在 UI 线程调用）
void refreshPackets(AppState& s)
{
    s.packets     = s.session.packetsSnapshot();
    s.selectedPkt = nullptr;
    s.hex.clear();
    s.detail       = DetailNode();
    s.detailLoaded = false;
    // 可能有针对旧文件的详情任务在跑：移进 draining 等其自然结束回收，别在此析构阻塞。
    if (s.detailPending.valid())
        s.detailDraining.push_back(std::move(s.detailPending));
    s.detailResult.reset();
    s.displayFilterOn = false;
    s.displayFiltered.clear();
    s.page       = 0;
    s.viewDirty  = true;
    s.totalBytes = 0;
    for (const PacketPtr& p : s.packets)
        s.totalBytes += p->len;
}

// 每帧把抓包线程投递的实时包取出，追加到列表（UI 线程调用，短暂持锁只做 swap）。
void drainLive(AppState& s)
{
    std::vector<PacketPtr> batch;
    {
        std::lock_guard<std::mutex> lk(s.liveMutex);
        if (s.liveIncoming.empty())
            return;
        batch.swap(s.liveIncoming);
    }
    for (const PacketPtr& p : batch)
        s.totalBytes += p->len;
    s.packets.insert(s.packets.end(), batch.begin(), batch.end());
    s.viewDirty = true;
}

// 仅当报文数量变化时重建会话 / 统计聚合，避免每帧 O(N)。
void ensureAnalytics(AppState& s)
{
    if (s.analyticsBuiltCount == s.packets.size())
        return;
    s.analyticsBuiltCount = s.packets.size();

    // 会话：按五元组（规范化端点对）归并
    std::map<std::string, SessionInfo> sessMap;
    // 统计：IP / 协议 / 归属地 计数
    std::map<std::string, CountItem> ipMap, protoMap, locMap;

    for (const PacketPtr& pp : s.packets)
    {
        const Packet& p = *pp;

        // ---- 会话 ----
        if (!p.src_ip.empty() && !p.dst_ip.empty())
        {
            std::string a = p.src_ip + ":" + std::to_string(p.src_port);
            std::string b = p.dst_ip + ":" + std::to_string(p.dst_port);
            std::string key = (a < b) ? (a + "|" + b) : (b + "|" + a);
            SessionInfo& si = sessMap[key];
            if (si.packets == 0)
            {
                si.endpointA = (a < b) ? a : b;
                si.endpointB = (a < b) ? b : a;
                si.transport = p.transport;
            }
            if (!p.protocol.empty())
                si.protocols.insert(p.protocol);
            si.packets++;
            si.bytes += p.len;
        }

        // ---- 协议统计 ----
        if (!p.protocol.empty())
        {
            CountItem& c = protoMap[p.protocol];
            c.name = p.protocol;
            c.packets++;
            c.bytes += p.len;
        }

        // ---- IP 统计（源、目的各计一次）----
        for (const std::string* ip : {&p.src_ip, &p.dst_ip})
        {
            if (ip->empty())
                continue;
            CountItem& c = ipMap[*ip];
            c.name = *ip;
            c.packets++;
            c.bytes += p.len;
        }

        // ---- 归属地 / 国家统计 ----
        for (const std::string* loc : {&p.src_location, &p.dst_location})
        {
            if (loc->empty())
                continue;
            CountItem& c = locMap[*loc];
            c.name = *loc;
            c.packets++;
            c.bytes += p.len;
        }
    }

    auto toSortedVec = [](std::map<std::string, CountItem>& m)
    {
        std::vector<CountItem> v;
        v.reserve(m.size());
        for (auto& kv : m)
            v.push_back(kv.second);
        std::sort(v.begin(), v.end(),
                  [](const CountItem& x, const CountItem& y) { return x.packets > y.packets; });
        return v;
    };

    s.sessions.clear();
    s.sessions.reserve(sessMap.size());
    for (auto& kv : sessMap)
        s.sessions.push_back(kv.second);
    std::sort(s.sessions.begin(), s.sessions.end(),
              [](const SessionInfo& x, const SessionInfo& y) { return x.packets > y.packets; });

    s.ipStats    = toSortedVec(ipMap);
    s.protoStats = toSortedVec(protoMap);
    s.locStats   = toSortedVec(locMap);
}

bool sessionMatches(const SessionInfo& si, int cat)
{
    auto hasProto = [&](const char* n)
    {
        for (const std::string& p : si.protocols)
            if (containsIgnore(p, n))
                return true;
        return false;
    };
    switch (cat)
    {
    case 1:
        return si.transport == "TCP";
    case 2:
        return si.transport == "UDP";
    case 3:
        return hasProto("DNS");
    case 4:
        return hasProto("HTTP");
    case 5:
        return hasProto("TLS") || hasProto("SSL");
    case 6:
        return hasProto("SSH");
    default:
        return true;
    }
}

// ---- 面板 ----

// 顶部工具栏：离线载入 / 保存 / 实时抓包控制，收敛到一行区域。
void drawToolbar(AppState& s)
{
    // 离线载入
    ImGui::TextUnformatted("分析文件:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##pcap", "PCAP 文件路径", s.pcapPathInput, sizeof(s.pcapPathInput));
    ImGui::SameLine();
    // 抓包进行中禁止载入离线 pcap：两者都会驱动解析/入库，并发会互相踩 analyzer_ 状态。
    ImGui::BeginDisabled(s.busy || s.session.isCapturing());
    if (ImGui::Button("载入并分析"))
    {
        std::string path = s.pcapPathInput;
        beginAsync(s, [&s, path]() { return s.session.loadPcap(path); },
                   [&s]() { refreshPackets(s); }, "正在解析 pcap...");
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::TextUnformatted("  |  保存:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240);
    ImGui::InputTextWithHint("##savepath", "另存为 .pcap 路径", s.savePathInput,
                             sizeof(s.savePathInput));
    ImGui::SameLine();
    ImGui::BeginDisabled(s.busy || s.session.pcapPath().empty());
    if (ImGui::Button("保存"))
    {
        std::string dest = s.savePathInput;
        s.status = s.session.savePcapAs(dest) ? ("已保存: " + dest) : "保存失败";
    }
    ImGui::EndDisabled();

    // tshark 路径：显示当前解析到的路径，允许手动改指到 tshark(.exe) 后应用（无需重编译）。
    // 未检测到时红字提示并给出下载地址，引导用户安装 Wireshark。
    ImGui::TextUnformatted("tshark 路径:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(360);
    ImGui::InputTextWithHint("##tsharkpath", "tshark 可执行文件完整路径", s.tsharkPathInput,
                             sizeof(s.tsharkPathInput));
    ImGui::SameLine();
    ImGui::BeginDisabled(s.busy || s.session.isCapturing());
    if (ImGui::Button("应用路径"))
    {
        s.session.setTsharkPath(s.tsharkPathInput);
        if (TsharkCommand::tsharkAvailable(s.tsharkPathInput))
            s.status = "已应用 tshark 路径";
        else
            s.status = "路径无效：该位置未找到 tshark，请重新指定";
    }
    ImGui::EndDisabled();
    if (!TsharkCommand::tsharkAvailable(s.tsharkPathInput))
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f),
                           "未检测到 tshark，请安装 Wireshark: %s",
                           TsharkCommand::wiresharkDownloadUrl().c_str());
    }

    // 实时抓包
    ImGui::TextUnformatted("实时抓包:");
    ImGui::SameLine();
    if (ImGui::Button("刷新网卡"))
    {
        // 枚举网卡会启动 tshark 子进程；若 tshark 未安装/不在默认路径，listAdapters 会抛
        // std::runtime_error。这里必须捕获——否则异常冲出 ImGui 帧循环导致整个窗口闪退。
        try
        {
            s.adapters = s.session.listAdapters();
            if (s.adapters.empty())
                s.status = "未找到网卡（请确认已安装 Wireshark 且有足够权限）";
            else
                s.status = "已刷新网卡，共 " + std::to_string(s.adapters.size()) + " 个";
        }
        catch (const std::exception& e)
        {
            s.adapters.clear();
            s.adapterName[0] = 0;
            s.status         = std::string("刷新网卡失败：") + e.what() +
                       "（请确认已安装 Wireshark：C:\\Program Files\\Wireshark\\tshark.exe）";
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    if (ImGui::BeginCombo("##adapter", s.adapterName[0] ? s.adapterName : "选择网卡"))
    {
        for (const auto& a : s.adapters)
        {
            bool        sel   = (std::strcmp(s.adapterName, a.name.c_str()) == 0);
            std::string label = a.name + " (" + a.remark + ")";
            if (ImGui::Selectable(label.c_str(), sel))
                std::snprintf(s.adapterName, sizeof(s.adapterName), "%s", a.name.c_str());
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(s.busy || s.session.isCapturing() || s.adapterName[0] == 0);
    if (ImGui::Button("开始抓包"))
    {
        std::string adapter = s.adapterName;
        s.packets.clear();
        s.view.clear();
        s.selectedPkt = nullptr;
        s.hex.clear();
        s.detail       = DetailNode();
        s.detailLoaded = false;
        s.totalBytes   = 0;
        {
            std::lock_guard<std::mutex> lk(s.liveMutex);
            s.liveIncoming.clear();
        }
        AppState* sp = &s; // 回调在抓包线程执行：只把包推进带锁队列，绝不碰 ImGui
        bool      ok = s.session.startLiveCapture(
            adapter, [sp](const PacketPtr& p)
            {
                std::lock_guard<std::mutex> lk(sp->liveMutex);
                sp->liveIncoming.push_back(p);
            });
        if (ok)
        {
            s.liveCapturing = true;
            s.status        = "实时抓包中: " + adapter;
        }
        else
        {
            s.status = "启动抓包失败（检查网卡 / BPF 权限）";
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(s.busy || !s.session.isCapturing());
    if (ImGui::Button("停止并分析"))
    {
        s.liveCapturing = false;
        beginAsync(s, [&s]() { return s.session.stopLiveCapture(); },
                   [&s]() { refreshPackets(s); }, "停止抓包并解析...");
    }
    ImGui::EndDisabled();
}

// 过滤栏：tshark 显示过滤表达式 + 协议快速分类。
void drawFilterBar(AppState& s)
{
    ImGui::SetNextItemWidth(360);
    bool enter = ImGui::InputTextWithHint("##filter", "请输入过滤表达式（如 tcp.port==80 && ip.addr==1.2.3.4）",
                                          s.filterExpr, sizeof(s.filterExpr),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(s.busy || s.liveCapturing || s.packets.empty());
    bool find = ImGui::Button("查找");
    if ((find || enter) && s.filterExpr[0])
    {
        // 显示过滤要跑一次 tshark（-Y），放后台，避免在 UI 线程同步等待卡帧。
        // 后台写 filterScratch，成功后在 onDone（UI 线程）swap 进 displayFiltered。
        std::string expr = s.filterExpr;
        AppState*   sp   = &s;
        beginAsync(s,
                   [sp, expr]() { return sp->session.queryDisplayFilter(expr, sp->filterScratch); },
                   [sp]()
                   {
                       sp->displayFiltered.swap(sp->filterScratch);
                       sp->filterScratch.clear();
                       sp->displayFilterOn = true;
                       sp->page            = 0;
                       sp->viewDirty       = true;
                       sp->selectedPkt     = nullptr;
                       sp->status = "过滤命中 " + std::to_string(sp->displayFiltered.size()) +
                                    " 个报文";
                   },
                   "正在按表达式过滤...");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("清除过滤"))
    {
        s.filterExpr[0]   = 0;
        s.displayFilterOn = false;
        s.displayFiltered.clear();
        s.page        = 0;
        s.viewDirty   = true;
        s.selectedPkt = nullptr;
    }

    ImGui::SameLine();
    ImGui::TextUnformatted("  分类:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    const char* cats[] = {"全部数据包", "ARP", "ICMP", "ICMPv6"};
    if (ImGui::Combo("##cat", &s.protoCategory, cats, IM_ARRAYSIZE(cats)))
    {
        s.page      = 0;
        s.viewDirty = true;
    }
}

// 一行报文的实际绘制（供分页 / 实时两条路径复用）。
void drawPacketRow(AppState& s, const PacketPtr& p)
{
    ImGui::TableNextRow();

    ImGui::TableSetColumnIndex(0);
    char label[32];
    std::snprintf(label, sizeof(label), "%d", p->frame_number);
    if (ImGui::Selectable(label, s.selectedPkt == p, ImGuiSelectableFlags_SpanAllColumns))
    {
        s.selectedPkt = p;
        loadSelected(s);
    }

    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(formatEpoch(p->time).c_str());

    ImGui::TableSetColumnIndex(2);
    ImGui::Text("%.6f", p->time);

    // 源 IP/Mac（+ 内网标签）
    ImGui::TableSetColumnIndex(3);
    ImGui::TextUnformatted(p->src_ip.empty() ? p->src_mac.c_str() : p->src_ip.c_str());
    if (isPrivateIp(p->src_ip))
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[内网]");
    }
    ImGui::TableSetColumnIndex(4);
    ImGui::TextUnformatted(p->src_location.c_str());
    ImGui::TableSetColumnIndex(5);
    if (p->src_port)
        ImGui::Text("%u", p->src_port);

    // 目的 IP/Mac（+ 内网标签）
    ImGui::TableSetColumnIndex(6);
    ImGui::TextUnformatted(p->dst_ip.empty() ? p->dst_mac.c_str() : p->dst_ip.c_str());
    if (isPrivateIp(p->dst_ip))
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[内网]");
    }
    ImGui::TableSetColumnIndex(7);
    ImGui::TextUnformatted(p->dst_location.c_str());
    ImGui::TableSetColumnIndex(8);
    if (p->dst_port)
        ImGui::Text("%u", p->dst_port);

    // 协议（彩色徽标）
    ImGui::TableSetColumnIndex(9);
    ImGui::TextColored(protocolColor(p->protocol), "%s", p->protocol.c_str());

    ImGui::TableSetColumnIndex(10);
    ImGui::Text("%u", p->len);
    ImGui::TableSetColumnIndex(11);
    ImGui::TextUnformatted(p->info.c_str());
}

void drawPacketTable(AppState& s)
{
    if (!s.liveCapturing && s.viewDirty)
        rebuildView(s);

    if (s.liveCapturing)
    {
        ImGui::Text("报文数: %zu", s.packets.size());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.3f, 1.0f), "● 实时抓包中");
        ImGui::SameLine();
        ImGui::Checkbox("自动滚动", &s.autoScroll);
    }
    else
    {
        ImGui::Text("共 %zu 条%s", s.view.size(), s.displayFilterOn ? "（已过滤）" : "");
    }

    // ScrollX：窗口偏窄时列会被挤压到显示不全（IP/归属地被截成“...”）。开启横向滚动后
    // 各列保持固定宽度、总宽超出可视区时可左右拖动查看完整内容。
    // 注意：ScrollX 下 WidthStretch 列不再自动填充，故下面把原先拉伸的列改为固定宽度。
    const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                                  ImGuiTableFlags_Resizable;
    // 表格占据除底部分页条外的空间
    float tableHeight = ImGui::GetContentRegionAvail().y - (s.liveCapturing ? 0.0f : 34.0f);
    if (ImGui::BeginTable("packets", 12, flags, ImVec2(0, tableHeight)))
    {
        // 冻结表头行 + 首列（No.）：横向滚动时帧号始终可见，便于对照
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableSetupColumn("时间", ImGuiTableColumnFlags_WidthFixed, 135);
        ImGui::TableSetupColumn("时间戳", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("源IP/Mac", ImGuiTableColumnFlags_WidthFixed, 175);
        ImGui::TableSetupColumn("源归属地", ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableSetupColumn("源端口", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("目的IP/Mac", ImGuiTableColumnFlags_WidthFixed, 175);
        ImGui::TableSetupColumn("目的归属地", ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableSetupColumn("目的端口", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("协议", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("大小", ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableSetupColumn("信息", ImGuiTableColumnFlags_WidthFixed, 600);
        ImGui::TableHeadersRow();

        if (s.liveCapturing)
        {
            // 实时：整表滚动 + 自动跟随，不分页（保持流式观感）
            ImGuiListClipper clipper;
            clipper.Begin((int)s.packets.size());
            while (clipper.Step())
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++)
                    drawPacketRow(s, s.packets[row]);
            if (s.autoScroll)
                ImGui::SetScrollHereY(1.0f);
        }
        else
        {
            // 离线：分页渲染当前页切片
            int begin = s.page * s.pageSize;
            int end   = std::min((int)s.view.size(), begin + s.pageSize);
            for (int row = begin; row < end; row++)
                drawPacketRow(s, s.view[row]);
        }
        ImGui::EndTable();
    }

    if (!s.liveCapturing)
    {
        int totalPages = std::max(1, (int)((s.view.size() + s.pageSize - 1) / s.pageSize));
        ImGui::BeginDisabled(s.page <= 0);
        if (ImGui::Button("上一页"))
            s.page--;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(s.page >= totalPages - 1);
        if (ImGui::Button("下一页"))
            s.page++;
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::Text("第 %d / %d 页", s.page + 1, totalPages);
        ImGui::SameLine();
        ImGui::TextUnformatted("  每页:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80);
        const char* sizes[]  = {"50", "100", "200", "500"};
        int         sizeVals[] = {50, 100, 200, 500};
        int         cur      = 1;
        for (int i = 0; i < 4; i++)
            if (sizeVals[i] == s.pageSize)
                cur = i;
        if (ImGui::Combo("##pgsize", &cur, sizes, IM_ARRAYSIZE(sizes)))
        {
            s.pageSize = sizeVals[cur];
            s.page     = 0;
        }
    }
}

// 递归渲染协议分层树的一个节点
void renderDetailNode(const DetailNode& n, int idx)
{
    ImGui::PushID(idx);
    if (n.children.empty())
    {
        std::string text = n.label;
        if (!n.value.empty())
            text += ": " + n.value;
        ImGui::TreeNodeEx(text.c_str(), ImGuiTreeNodeFlags_Leaf |
                                            ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                            ImGuiTreeNodeFlags_Bullet);
    }
    else if (ImGui::TreeNode(n.label.c_str()))
    {
        int i = 0;
        for (const DetailNode& c : n.children)
            renderDetailNode(c, i++);
        ImGui::TreePop();
    }
    ImGui::PopID();
}

void drawDetail(AppState& s)
{
    if (!s.selectedPkt)
    {
        ImGui::TextUnformatted("（选中一个报文查看详情）");
        return;
    }
    if (s.liveCapturing)
    {
        ImGui::TextUnformatted("（实时抓包中，点击“停止并分析”后可查看协议详情与十六进制）");
        return;
    }

    // 协议分层树（占上半区）
    ImGui::TextUnformatted("协议分层:");
    // 加 HorizontalScrollbar：深层嵌套字段展开后单行常超出可视宽度，
    // 无横向滚动只能被裁剪；有了它可左右拖动查看完整内容。
    ImGui::BeginChild("prototree", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.5f), true,
                      ImGuiWindowFlags_HorizontalScrollbar);
    if (s.detailLoaded && !s.detail.children.empty())
    {
        int i = 0;
        for (const DetailNode& proto : s.detail.children)
            renderDetailNode(proto, i++);
    }
    else if (s.detailPending.valid())
    {
        ImGui::TextUnformatted("（正在解析协议详情...）");
    }
    else
    {
        ImGui::TextUnformatted("（无协议详情 / 解析失败）");
    }
    ImGui::EndChild();

    // 十六进制（占下半区）
    ImGui::Text("十六进制 (帧 %u, %zu 字节)", s.hexFrame, s.hex.size());
    ImGui::BeginChild("hex", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    for (size_t off = 0; off < s.hex.size(); off += 16)
    {
        char line[128];
        int  n = std::snprintf(line, sizeof(line), "%04zx  ", off);
        for (size_t i = 0; i < 16; ++i)
        {
            if (off + i < s.hex.size())
                n += std::snprintf(line + n, sizeof(line) - n, "%02x ", s.hex[off + i]);
            else
                n += std::snprintf(line + n, sizeof(line) - n, "   ");
        }
        n += std::snprintf(line + n, sizeof(line) - n, " ");
        for (size_t i = 0; i < 16 && off + i < s.hex.size(); ++i)
        {
            unsigned char c = s.hex[off + i];
            n += std::snprintf(line + n, sizeof(line) - n, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        ImGui::TextUnformatted(line);
    }
    ImGui::EndChild();
}

void drawSessions(AppState& s)
{
    ensureAnalytics(s);

    ImGui::TextUnformatted("会话类型:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160);
    const char* cats[] = {"全部会话", "TCP会话", "UDP会话", "DNS会话",
                          "HTTP会话", "SSL/TLS会话", "SSH会话"};
    ImGui::Combo("##sesscat", &s.sessionCategory, cats, IM_ARRAYSIZE(cats));

    size_t shown = 0;
    for (const SessionInfo& si : s.sessions)
        if (sessionMatches(si, s.sessionCategory))
            shown++;
    ImGui::SameLine();
    ImGui::Text("  共 %zu 个会话", shown);

    const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("sessions", 6, flags))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("端点 A", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("端点 B", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("传输层", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("协议", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("包数", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("字节", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableHeadersRow();

        for (const SessionInfo& si : s.sessions)
        {
            if (!sessionMatches(si, s.sessionCategory))
                continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(si.endpointA.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(si.endpointB.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(si.transport.c_str());
            ImGui::TableSetColumnIndex(3);
            std::string protos;
            for (const std::string& pr : si.protocols)
                protos += (protos.empty() ? "" : ",") + pr;
            ImGui::TextUnformatted(protos.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%llu", (unsigned long long)si.packets);
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%llu", (unsigned long long)si.bytes);
        }
        ImGui::EndTable();
    }
}

// 通用计数表（IP / 协议 / 归属地 统计共用）
void drawCountTable(const char* id, const char* nameCol, const std::vector<CountItem>& items)
{
    const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY;
    if (ImGui::BeginTable(id, 3, flags))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(nameCol, ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("包数", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("字节", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableHeadersRow();
        for (const CountItem& c : items)
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(c.name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%llu", (unsigned long long)c.packets);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%llu", (unsigned long long)c.bytes);
        }
        ImGui::EndTable();
    }
}

void drawStatistics(AppState& s)
{
    ensureAnalytics(s);
    if (ImGui::BeginTabBar("stattabs"))
    {
        if (ImGui::BeginTabItem("IP统计"))
        {
            ImGui::Text("共 %zu 个 IP", s.ipStats.size());
            drawCountTable("ipstat", "IP 地址", s.ipStats);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("协议统计"))
        {
            ImGui::Text("共 %zu 种协议", s.protoStats.size());
            drawCountTable("protostat", "协议", s.protoStats);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("国家统计"))
        {
            ImGui::Text("共 %zu 个归属地", s.locStats.size());
            drawCountTable("locstat", "归属地 / 国家", s.locStats);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void drawQuery(AppState& s)
{
    ImGui::TextUnformatted("按条件查询（支持 * 模糊匹配，留空忽略）");
    ImGui::InputTextWithHint("MAC", "如 00:11:22:*", s.qMac, sizeof(s.qMac));
    ImGui::InputTextWithHint("IP", "如 192.168.*", s.qIp, sizeof(s.qIp));
    ImGui::InputTextWithHint("端口", "如 80*", s.qPort, sizeof(s.qPort));
    ImGui::InputTextWithHint("归属地", "如 深圳*", s.qLoc, sizeof(s.qLoc));

    ImGui::BeginDisabled(s.busy);
    if (ImGui::Button("查询"))
    {
        std::map<std::string, std::string> cond;
        if (s.qMac[0])
            cond["mac_address"] = s.qMac;
        if (s.qIp[0])
            cond["ip_address"] = s.qIp;
        if (s.qPort[0])
            cond["port"] = s.qPort;
        if (s.qLoc[0])
            cond["location"] = s.qLoc;
        s.queryResult.clear();
        if (cond.empty())
            s.queryResult = "未指定任何查询条件";
        else if (!s.session.query(cond, s.queryResult))
            s.queryResult = "查询失败（是否已载入 pcap？）";
    }
    ImGui::EndDisabled();

    ImGui::Separator();
    ImGui::BeginChild("qresult", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(s.queryResult.c_str());
    ImGui::EndChild();
}

void drawStatusBar(AppState& s)
{
    ImGui::Separator();
    ImGui::Text("数据包总数: %zu", s.packets.size());
    ImGui::SameLine();
    ImGui::Text("  |  总字节数: %llu", (unsigned long long)s.totalBytes);
    ImGui::SameLine();
    ImGui::Text("  |  状态: %s", s.busy ? "处理中..." : s.status.c_str());
    ImGui::SameLine();
    float rightBtn = ImGui::GetContentRegionAvail().x - 70;
    if (rightBtn > 0)
        ImGui::SameLine(ImGui::GetCursorPosX() + rightBtn);
    if (ImGui::Button("关于"))
        ImGui::OpenPopup("关于 EasyTshark");

    if (ImGui::BeginPopupModal("关于 EasyTshark", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::TextUnformatted("EasyTshark · 网络抓包与协议分析工具");
        ImGui::Spacing();
        ImGui::TextUnformatted("基于 Wireshark / tshark 内核，支持实时抓包、离线 pcap 分析");
        ImGui::TextUnformatted("以及会话追踪、协议分布与流量趋势统计。");
        ImGui::Spacing();
        ImGui::TextUnformatted("界面框架：Dear ImGui + GLFW / OpenGL3");
        ImGui::Text("运行依赖：Wireshark（tshark）  ·  %s",
                    TsharkCommand::wiresharkDownloadUrl().c_str());
        ImGui::Separator();
        if (ImGui::Button("关闭"))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

// 尝试加载一款带中文字形的系统字体，让归属地 / 概要里的中文正常显示。
void setupChineseFont()
{
    const char* candidates[] = {
#if defined(_WIN32)
        // Windows 常见中文字体（微软雅黑 / 黑体 / 宋体），随系统预装。
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
#else
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
#endif
    };
    ImGuiIO& io = ImGui::GetIO();
    for (const char* path : candidates)
    {
        FILE* f = std::fopen(path, "rb");
        if (!f)
            continue;
        std::fclose(f);
        io.Fonts->AddFontFromFileTTF(path, 16.0f, nullptr,
                                     io.Fonts->GetGlyphRangesChineseFull());
        return;
    }
}

void glfwErrorCallback(int error, const char* description)
{
    std::fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

} // namespace

int main(int, char**)
{
    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit())
    {
        std::fprintf(stderr, "glfwInit 失败\n");
        return 1;
    }

    // OpenGL 3.2 Core + 前向兼容（macOS 必需）
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow* window = glfwCreateWindow(1360, 860, "EasyTshark", nullptr, nullptr);
    if (!window)
    {
        std::fprintf(stderr, "创建窗口失败\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    setupChineseFont();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // 自动定位 tshark：环境变量 EASYTSHARK_TSHARK → 默认路径 → PATH →（Win）注册表 → 常见目录。
    AnalysisSession session(TsharkCommand::resolveTsharkPath(), "data");
    AppState        state(session);

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();
        pollAsync(state);
        pollDetail(state); // 取回后台解析好的选中包协议详情
        drainLive(state);  // 取出抓包线程投递的实时包，追加到列表

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // 单一主窗口铺满视口
        const ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::Begin("EasyTshark", nullptr,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                         ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        drawToolbar(state);
        ImGui::Separator();
        drawFilterBar(state);
        ImGui::Separator();

        // 主区：给状态栏预留底部空间
        ImGui::BeginChild("main", ImVec2(0, ImGui::GetContentRegionAvail().y - 30));
        if (ImGui::BeginTabBar("tabs"))
        {
            if (ImGui::BeginTabItem("报文"))
            {
                // 左列表 / 右详情
                ImGui::BeginChild("list", ImVec2(ImGui::GetContentRegionAvail().x * 0.62f, 0));
                drawPacketTable(state);
                ImGui::EndChild();
                ImGui::SameLine();
                ImGui::BeginChild("detail", ImVec2(0, 0));
                drawDetail(state);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("通信会话"))
            {
                drawSessions(state);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("统计分析"))
            {
                drawStatistics(state);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("查询"))
            {
                drawQuery(state);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("进程分析"))
            {
                ImGui::TextDisabled("进程分析（socket→进程 映射）依赖平台特定能力，暂未实现。");
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::EndChild();

        drawStatusBar(state);

        ImGui::End();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.10f, 0.10f, 0.12f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // 若还在抓包，先停掉，避免退出时子进程 / 线程悬挂
    if (session.isCapturing())
        session.stopLiveCapture();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
