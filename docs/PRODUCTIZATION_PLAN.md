# EasyTshark 进阶落地方案（学习项目视角）

> 本文承接 `REFACTOR_ROADMAP.md`（7 个重构主题已完成 + 两轮性能优化），
> 回答「若朝企业级方向发展，作为**学习项目**该分步做什么」。
> **定位**：不追求真·产品化，而是借企业级议题练 C++ 架构、并发、系统编程与 GUI。
> **约束沿用**：全程 **C++11**、仅本地构建（不引 CI）、跨平台（Linux + macOS，Windows 待主题 1 二期）。
> 主题编号接续 `REFACTOR_ROADMAP.md`，从**主题 8** 起。

---

## 现状与差距（简述）

现在是：**单进程 CLI + 全量报文驻内存（`PcapAnalyzer::allPackets`）+ SQLite + 每次 fork tshark 子进程**，交互靠 `std::cin/cout`。作为 demo 完整，但离"可长期演进的应用"差三块地基：

1. **核心库与调用方耦合**：`main.cpp` 把交互输入、文件复制、入库、查询流程混在一起；`FlowMonitor::getAdaptersFlowTrendData` 甚至**没有消费者**——说明缺一个稳定的对外门面。
2. **全量内存**：大 pcap 会 OOM，无法流式。
3. **没有 UI**：能力无法直观呈现（尤其实时流量趋势、hex）。

下面三个主题按依赖顺序解决，且每个都是独立、可验证的 C++ 学习单元。

---

## 主题 8 — 核心库 / 应用层解耦（门面 API）【地基，先做】

### 为什么
UI（无论 ImGui 还是别的）绝不能直接去碰 `PcapAnalyzer` / `tshark` 细节，否则 UI 与解析逻辑焊死、无法单测、无法替换。先立一层**稳定门面**，把「一次分析会话」抽象出来。

### 做什么
- 新增 `AnalysisSession`（`include/AnalysisSession.hpp` + `src/AnalysisSession.cpp`），聚合现有四个职责类 + `SQLiteUtil`，对外暴露**面向意图**的接口，例如：
  - `bool openPcap(const std::string& path);`
  - `size_t packetCount() const;`
  - `std::shared_ptr<Packet> getPacket(size_t index) const;`（或按 frame_number）
  - `bool getHex(uint32_t frameNumber, std::vector<unsigned char>& out);`
  - `bool query(const std::map<std::string,std::string>& conditions, std::string& jsonOut);`
  - `bool startLiveCapture(const std::string& adapter);` / `stopLiveCapture();`
  - `void flowTrendSnapshot(std::map<std::string,std::map<long,long>>& out);`（封装 `FlowMonitor`，终于给它一个消费者）
- `main.cpp` 瘦身为**只做 CLI 装配**，业务流程搬进 `AnalysisSession`；后续 ImGui 前端复用同一个门面。
- 线程模型明确：分析/抓包在 worker 线程，门面对外提供**线程安全的快照获取**（为 UI 线程做准备）。

### 教学点
门面模式、依赖倒置、UI 无关的核心库设计、并发下的"快照"读取。

### 验证
现有 `ctest` 全绿不变；新增 `AnalysisSession` 的集成单测（用手工 pcap，覆盖 open→count→getPacket→getHex→query 一条线）。

---

## 主题 9 — 流式解析（去全量内存）【规模化关键】

### 为什么
`analysisFile` 目前把所有 `Packet` 塞进 `allPackets` 常驻内存。GB 级 pcap 直接 OOM。企业级 NTA 的第一课就是**包只过一遍、不常驻**。

### 做什么
- 给 `PcapAnalyzer::analysisFile` 增加**回调 / 迭代**式重载：`bool analysisFile(path, const std::function<void(const Packet&)>& onPacket);`（C++11 的 `std::function` 即可），逐包回调，不累积。
- 入库/统计改为在回调里**分批 flush**（复用已有的 SQLite 事务批量插入）。
- 全量列表按需：UI 要看某一页时，靠 `file_offset` + `PcapFileReader`（本轮已用 mmap 实现）随机取；或让 SQLite 承担分页查询（`LIMIT/OFFSET` 或按 frame_number 游标）。
- `allPackets` 从"全量真源"降级为"可选缓存/被 UI 分页取代"。

### 教学点
流式处理 vs 全量、`std::function` 回调、生产者-消费者、分页游标、mmap 随机访问（已具备）。

### 验证
用一个较大的 pcap 观察常驻内存不随包数线性膨胀；分页取包与旧全量结果一致。

---

## 主题 10 — Dear ImGui 原生前端【呈现层，压轴】

> 你已 clone `../imgui`（Dear ImGui 1.92.9，含 GLFW/OpenGL3/Metal/SDL 后端与 mac 示例）。
> ImGui 是**即时模式、单进程**：这里的"前后端分离"= 主题 8 的核心库/UI 边界，**不引入网络 C/S**。

### 技术选型
- **后端**：`GLFW + OpenGL3`（`imgui_impl_glfw` + `imgui_impl_opengl3`）。理由：一套后端 Linux/macOS/Windows 通吃，最契合项目跨平台目标；mac 上也可选 Metal，但 OpenGL3 最省心。
- **接入方式**：把 `imgui.cpp / imgui_draw.cpp / imgui_tables.cpp / imgui_widgets.cpp / imgui_demo.cpp` 与选定的两个 backend 文件**加入本项目构建**（vendored）。事件循环骨架直接照抄 `../imgui/examples/example_glfw_opengl3/main.cpp`。
- **依赖**：GLFW（**vendored 源码**，clone 进 `include/glfw`，CMake `add_subdirectory` 一起编译——本机 Homebrew 不可用，且这也更贴合“本地构建”与 imgui 相同的 vendoring 方式；与 rapidjson/rapidxml/ip2region 一致，第三方库放 `include/<名字>/`）、OpenGL（系统自带，mac 额外 `-framework OpenGL` 并 `GL_SILENCE_DEPRECATION`）。
- **两个可选扩展**（drop-in，强烈建议）：
  - `imgui_memory_editor.h`（来自 `ocornut/imgui_club`，单头文件）→ 直接渲染 `getHex()` 返回的字节，做 Wireshark 式 hex 面板。
  - **ImPlot**（`epezent/implot`，另一个仓库，同样 vendored）→ 画每块网卡的实时流量趋势，消费 `flowTrendSnapshot()`。

### 界面模块（对应现有能力，一一映射）
| 面板 | ImGui 控件 | 数据来源（门面） |
|------|-----------|-----------------|
| 报文列表 | `BeginTable` + `ImGuiListClipper`（只渲染可见行，配合主题 9 分页，扛大列表） | `packetCount()` / `getPacket(i)` |
| 报文详情 | 树形 `TreeNode`（协议分层） | PDML→JSON（`PdmlToJsonConverter`，含中文翻译 trie） |
| Hex 视图 | `imgui_memory_editor` | `getHex(frameNumber)` |
| 过滤/查询 | `InputText` + 表单 | `query(conditions)`（已参数化防注入） |
| 实时流量趋势 | ImPlot 折线图 | `flowTrendSnapshot()`（终于用上 `FlowMonitor`） |
| 抓包控制 | 网卡下拉 + 开始/停止按钮 | `startLiveCapture/stopLiveCapture`（`listNetworkAdapters`） |

### 线程模型（关键，也是学习重点）
- **UI 必须在主线程**（GLFW/OpenGL 要求）。
- 抓包/解析/查询在 **worker 线程**，结果通过**线程安全队列 / 快照**交给 UI（呼应主题 8）。UI 每帧只读快照，绝不阻塞在解析上。
- 复用本轮 FlowMonitor 的 joinable + `stopFlag` 优雅停机经验，推广到所有 worker。

### 教学点
即时模式 GUI 原理、渲染循环、UI 线程模型、`ImGuiListClipper` 与分页协作、把已有 core 无侵入地"装"上界面。

### 验证
先跑通 `example_glfw_opengl3` 确认环境；再逐面板接门面；用手工 pcap 端到端：打开→列表→选中→详情+hex→查询过滤；实时抓包→流量趋势动起来。

---

## 建议实施顺序

```
主题 8（门面解耦）  →  主题 9（流式解析）  →  主题 10（ImGui 前端）
      ↑ 先立边界             ↑ 让大文件可行            ↑ 有了边界与数据才好接 UI
```

- 8 必须最先（否则 UI 无从对接）。
- 9 可与 10 并行推进，但列表分页面板依赖 9 的成果。
- 10 内部再分三小步：环境跑通 → 只读面板（列表/详情/hex/查询）→ 实时面板（抓包/流量图）。

---

## 明确「不做」（超出学习项目范围）

- **Web 前后端 / gRPC / REST 服务化**：ImGui 单进程方案已满足"UI 与 core 分离"的学习目标，不必上网络层。
- **外部数据库（ClickHouse 等）/ 分布式抓包 / 10Gbps 高速采集**：真·产品化才需要，规模远超学习目标。
- **CI/CD、容器编排、RBAC/多租户/合规**：企业运维与合规议题，与"练 C++"无关，明确排除。
- **直接链 libwireshark 替换 tshark 子进程**：性能收益属产品级考量；学习项目保留 tshark 子进程即可（已 argv 化、无注入）。

> 这些不是"以后也不做"，而是"作为学习项目的当前边界"。若某天真要产品化，另起 `PRODUCT_ROADMAP` 重新排序。
