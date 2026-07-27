# EasyTshark 重构路线图

> 本文档记录把 EasyTshark 从"能跑的工具"发展为**有价值的 C++ 学习项目**的重构计划。
> 约束：**刻意固定 C++11**（贴合网络安全 / 嵌入式 / 车载领域保守的工具链），不使用 C++14/17 特性。
> 目标环境：**多平台（Linux + macOS 都要能编译运行）**。
> 推进方式：**分主题逐个实施**，每个主题讲清"为什么"，尽量验证后再进行下一个。

---

## 已完成：性能优化（13 项，已写入代码）

| # | 优化项 | 位置 |
|---|--------|------|
| 1 | IP2Region 数据库每包重载 → 仅初始化一次 | `tsharkManager.cpp::analysisFile` |
| 2 | 删除 `parseLine` 内每行重复且未使用的 IP2Region init | `tsharkManager.cpp::parseLine` |
| 3 | 存储线程 100ms 轮询 → `condition_variable` 唤醒 | `tsharkManager.cpp::storageThreadEntry` |
| 4 | 值传参 → `const&`（`parseLine`/`analysisFile`/`captureWorkThreadEntry`） | 多处 |
| 5 | `processPacket` 用 `const shared_ptr&`，规避原子引用计数 | `tsharkManager.cpp::processPacket` |
| 6 | range-for 按值拷贝 → `const auto&` | `printAllPackets`/`stopMonitorAdaptersFlowTrend` |
| 7 | `analysisFile(…, packets)` 加 `reserve` | `tsharkManager.cpp` |
| 8 | 流量趋势 `find`+`at` 双查找合并为单次 | `getAdaptersFlowTrendData` |
| 9 | 删除重复的 `translationMap2` 与 `compareMapPerformance` | `utils.cpp` |
| 10 | 查询结果 JSON 用 `StringRef` + 数组 `Reserve`，避免拷贝进 allocator | `utils.cpp::packetsToJson` |
| 11 | 消除 `parseLine` 内多余的 `stringstream` 拷贝 | `tsharkManager.cpp::parseLine` |
| 12 | 附带 bug：`getPacketHexData` 缺 `seekg`，总是从文件头读错数据 | `tsharkManager.cpp` |
| 13 | 附带 bug：`getNetworkAdapterInfo` 重复解析同一行产生重复网卡 | `tsharkManager.cpp` |

---

## 已完成：第二轮性能优化（OS / 底层视角，7 项）

> 背景：从操作系统 / 计算机底层角度复审各热路径，落地全部可行项。同时确认
> `FlowMonitor` 目前无 main 调用方、`getAdaptersFlowTrendData` 无消费者（改动无回归面），
> 且 `UTF8ToANSIString` 为死代码（**故不优化死代码**，删除归主题 6）。

| # | 优化项 | 位置 | 底层要点 |
|---|--------|------|---------|
| 14 | 实时抓包命令去掉 `-T fields`（只 `-w -F pcap`） | `LiveCapture.cpp` | 免去 tshark 对每包完整 dissect + 字符串格式化；本线程本就不消费字段 |
| 15 | 抓包 read 热循环移除逐 chunk 同步日志 | `LiveCapture.cpp` | 同步日志 I/O 会串行化并顶满管道 64KB 缓冲的背压 |
| 16 | fd→网卡 反查改 `unordered_map`（O(1)） | `FlowMonitor.cpp/.hpp` | 取代每次 read 对监控 map 的线性 `fileno==fd` 扫描；map node 地址稳定，存裸指针安全 |
| 17 | `getAdaptersFlowTrendData` 稀疏化 | `FlowMonitor.cpp` | 用 `lower_bound/upper_bound` 只搬有流量的秒，不再逐秒稠密填 0；语义：缺失秒=无流量 |
| 18 | 移除 300 秒淘汰的逐条日志 | `FlowMonitor.cpp` | 高频淘汰路径去掉热循环内 `LOG_F` |
| 19 | 监控线程 detached → joinable + `stopFlag` + 析构兜底 | `FlowMonitor.cpp/.hpp` | 优雅停机：先置位再 join（无锁）再撕毁 map，消除线程读裸指针竞态；兼正确性修复 |
| 20 | `getPacketHexData` 一次打开多次随机读（新增 `PcapFileReader`） | `PcapFileReader.*`, `PcapAnalyzer.*` | 消除每次取包重复 `open/close`；POSIX 走 `mmap`（免 lseek+read 双系统调用与内核→用户拷贝，缺页按需调页），非 POSIX 走 `ifstream` 兜底 |

**未做（有意）**：`UTF8ToANSIString` 缓存 `iconv_t`——该函数零调用方，属死代码，优化无意义，删除留待主题 6。

**验证**：`ctest` 维持 27 passed / 3 skipped / 0 failed；补手工 pcap 后离线三例（`OfflineAnalysis*` / `IntegrationTest`）全部转为 PASS，端到端走通 `PcapFileReader::open`(mmap)；独立冒烟确认 `getPacketHexData` 经 mmap 返回的 58 字节与构造帧逐字节一致（dst MAC、payload marker 均正确）。

---

## 进度总览

| 主题 | 状态 |
|------|------|
| 1 跨平台抽象 | ✅ 第一期完成（macOS 打通；Windows 待第二期） |
| 2 安全加固（Shell + SQL 注入） | ✅ 已完成 |
| 3 错误处理统一 | ✅ 已完成 |
| 4 类拆分（God Class） | ✅ 已完成（彻底拆分，`TsharkManager` 移除） |
| 5 可测试性 | ✅ 已完成（parseLine 抽为纯函数并独立单测；测试去 shell 化） |
| 6 死代码清理 | ✅ 已完成 |
| 7 README（本地构建部署） | ✅ 已完成 |

---

## 待办主题（按建议顺序）

### 主题 1 — 跨平台抽象（地基）

- **状态：第一期（macOS）已完成。** 关键结论：抓包引擎不是障碍（tshark 三平台通吃），macOS 唯一的拦路虎是 Linux 专有的 `epoll`；其余 POSIX 调用 mac 全支持。
- **平台区分策略**：大分歧（epoll 这类整套 API）→ 独立文件 + CMake 选择编译，业务代码零 `#ifdef`；小分歧（默认路径、link 库）→ 就地 `#if defined(__APPLE__)/(_WIN32)/else`。
- **落成（第一期）**：
  - 新增事件轮询抽象 `include/platform/EventPoller.hpp` + `src/platform/EventPollerPoll.cpp`（基于 POSIX `poll()`，Linux + macOS 共用一份；线程安全：持锁拷贝 fd 快照后再 `poll`，不阻塞并发 add/remove）。
  - `tsharkManager.cpp` 删除 `#include <sys/epoll.h>`，三处 epoll（`captureWorkThreadEntry` / `startMonitorAdaptersFlowTrend` / `adapterFlowTrendMonitorThreadEntry` / `stopMonitorAdaptersFlowTrend`）改用 `EventPoller`；顺带修复监控线程 `while(true)+epoll_wait(-1)` 无退出条件的线程泄漏（改为带超时轮询 + `size()==0` 退出）。
  - `tsharkPath` / `editcapPath` 构造函数按平台给默认值（mac 指向 `Wireshark.app` 内路径），新增 `setTsharkPath` / `setEditcapPath` 可覆盖。
  - `CMakeLists.txt`：ccache 改为"存在才用"；link 库平台化（Linux `dl`、macOS `iconv`）；加入 `EventPollerPoll.cpp`。`tests/CMakeLists.txt` 的 `dl` 也加 `NOT APPLE` 守卫。
  - **验证**：整个项目在 macOS 上用官方 CMake 流程完整构建成功（此前因 epoll 不可能）；`ctest` 全套 **21 passed / 3 skipped（缺 pcap 资源）/ 0 failed**；端到端冒烟经真实 tshark 枚举出 21 块网卡。
  - **构建注记**：CMake 4.x 已移除对 `cmake_minimum_required < 3.5` 的兼容，而所用 googletest 1.11.0 恰好触发，需 `cmake -S . -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5`（或后续升级 gtest 到支持 C++11 且 min≥3.5 的版本）。
  - **附带修复**：ctest 暴露出 `buildFuzzyQuery` 地理位置查询的既存缺陷——当输入含 `*`（如 `湖南*长沙`）时漏加前后 `%`，导致中间通配匹配失败；改为无条件 `%...%` 包裹（`src/utils.cpp`）。
- **第二期（Windows，待办）**：进程创建（`CreateProcess` + 匿名管道，替代 fork/execvp）、I/O 多路复用（`WaitForMultipleObjects`/`PeekNamedPipe`，管道不能用 `WSAPoll`）、`iconv` 替代（`MultiByteToWideChar` 或全程 UTF-8）。
- **教学点**：接口与实现分离、可移植性设计、「宏 vs 拆文件」的取舍。
- **代表文件**：`include/platform/EventPoller.hpp`、`src/platform/EventPollerPoll.cpp`、`src/tsharkManager.cpp`、`CMakeLists.txt`。

### 主题 2 — 安全加固 ✅ 已完成

- **问题 A（Shell 注入）**：`ProcessUtil::PopenEx` 虽 `fork` 但走 `execl("/bin/sh","sh","-c",command)`；`Exec` 用 `system()`；`main.cpp` 大量 `"rm -rf "+dir`、`"cp "+path` 字符串拼接。命令中的 `;` `|` `$()` 等元字符都会被 shell 解释。
- **方案 A**：`PopenEx`/`Exec` 改为接收 `argv` 向量并 `execvp(argv[0], argv)`，绕开 shell；`main.cpp` 的 rm/cp/mkdir 改用程序内逻辑或 argv 调用。
- **落成**：
  - `ProcessUtil` 新增 `argv` 向量版 `Exec` / `PopenEx`（`execvp`）及配套 `PcloseEx`（关闭管道 + `waitpid` 回收子进程）；旧 `const char*` 版保留并加 `@warning` 注明注入风险。
  - `tsharkManager.cpp` 所有 tshark 调用改用 argv 版 `PopenEx`（`analysisFile` / `getNetworkAdapterInfo` / `startMonitorAdaptersFlowTrend` / `captureWorkThreadEntry` / `convertPcapToXml`），`convertPcapToXml` 不再用 `>` 重定向而是父进程读管道写文件。
  - `main.cpp` 的 `mkdir -p` / `rm -rf` / `cp` / `mv` 全部改为程序内实现（`mkdir` / `opendir`+`remove` / 流式复制 / `rename` 带回退），无 `system()` 残留。
- **问题 B（SQL 注入）**：`SQLiteUtil::buildFuzzyQuery` 用字符串拼接构造 SQL。
- **方案 B / 落成**：`buildFuzzyQuery` 改为生成 `?` 占位符 SQL 并输出 `BindParam` 列表；`queryPackets` 用 `sqlite3_bind_int` / `sqlite3_bind_text`(`SQLITE_TRANSIENT`) 按序绑定。端口纯数字走整数精确匹配，否则文本模糊匹配（避免 `stoi` 抛异常）。
- **教学点**：注入原理与防御、进程创建的正确姿势。
- **代表文件**：`src/processUtil.cpp`、`src/main.cpp`、`src/utils.cpp`。

### 主题 3 — 错误处理统一 ✅ 已完成

- **问题**：`analysisFile` 解析失败用 `assert(false)`（release 构建下被去除，等于无防护）；`getPacketHexData` 打开文件失败仅 `LOG` 却继续 `read`。
- **落成**：
  - `analysisFile` 解析失败时改为记录错误、`PcloseEx` 清理并 `return false`（解析失败会破坏后续报文偏移累加，无法安全继续）。
  - `getPacketHexData` 打开失败 / 帧号未找到 / 读取失败均直接 `return false`，不再"记录后继续"；用 `find` 结果避免二次查表。
- **代表文件**：`src/tsharkManager.cpp`。

### 主题 4 — 类拆分（God Class）✅ 已完成

- **问题**：`TsharkManager`（~994 行）把抓包、离线解析、流量监控、XML→JSON 转换、tshark 命令构造、网卡枚举全混在一个类里。
- **方案（彻底拆分，不保留门面壳）**：
  - 新增共享底座 `tsharkCommand`（自由函数）：`defaultTsharkPath()` / `defaultEditcapPath()`（平台默认路径单一真源）、`tsharkFieldArgs()`（离线解析与实时抓包共用的 16 字段列表，消除重复，即原计划的 `buildTsharkArgs()`）、`listNetworkAdapters()`（原 `getNetworkAdapterInfo`，`main` 与 `FlowMonitor` 共用）。
  - 四个职责类：`PcapAnalyzer`（离线解析）、`LiveCapture`（实时抓包）、`FlowMonitor`（流量监控，`AdapterMonitorInfo` 一并迁入）、`PdmlToJsonConverter`（格式转换）。
  - 删除 `include/tsharkManager.hpp` 与 `src/tsharkManager.cpp`；`main.cpp` 与全部测试改为直接使用新类。
- **顺带清理的死代码**：追完整链路确认存储流水线端到端从未接通——离线分析从不启动 `storageThread`（队列无人消费），实时抓包线程从不调用 `processPacket`（无生产者），`sqliteUtil` 成员从未 `make_shared`；真正入库在 `main.cpp` 的局部 `SQLiteUtil`。故 `waitInsertPackets*` / `storageThread(Entry)` / `sqliteUtil` 成员一整套直接丢弃，`processPacket` 精简为仅 `allPackets.insert`。DB 入库仍由 `main.cpp` 局部 `SQLiteUtil` 承担，**运行行为不变**。
- **教学点**：单一职责原则、依赖方向（高层职责类依赖底座，底座不反向依赖）、DRY。
- **验证**：`ctest` 维持 21 passed / 3 skipped / 0 failed；离线路径 `./output/tshark_main` 端到端跑通（解析→入库→XML→JSON）。

### 主题 5 — 可测试性 ✅ 已完成

- **问题**：`parseLine`（核心行解析）为私有且**完全无测试**，只能通过依赖 tshark 的路径间接触达；测试的 setup/teardown 大量用 `system()`（`mkdir -p` / `rm -rf`）。
- **方案（已落地）**：
  - 把行解析抽成独立纯函数模块 `PacketParser`（`include/PacketParser.hpp` + `src/PacketParser.cpp`）：`bool PacketParser::parseLine(const std::string&, Packet&)`，不依赖 tshark 进程、无任何 IO、不查 IP 地理位置。`PcapAnalyzer::analysisFile` 改为调用它，删除原私有成员；顺手修正了原先过时的字段下标注释（现与 `TsharkCommand::tsharkFieldArgs()` 的 0..15 严格对齐）。
  - 新增 `tests/test_packet_parser.cpp`：6 个确定性用例（IPv4/TCP、IPv6 回退、UDP 端口、端口全空保持 0、字段不足返回 false、末尾换行剥离），**无需 pcap 文件或 tshark 进程**。
  - 测试 setup 去 shell 化：新增 `tests/test_fs_util.hpp`（`inline fileExists / makeDirs / removeTree`，全部走 POSIX `mkdir`/`opendir`/`unlink`，无 `system()`），替换掉全部 `system("mkdir -p")` / `system("rm -rf")` 及分散在各测试文件里重复的 `fileExists/createDirectory/removeDirectory`。
- **教学点**：可测试性设计、纯函数与副作用隔离、DRY（测试辅助收敛为单一 header）。
- **代表文件**：`src/PacketParser.cpp`、`tests/test_packet_parser.cpp`、`tests/test_fs_util.hpp`。
- **验证**：`ctest` 27 passed / 3 skipped / 0 failed（较主题 4 基线新增 6 个纯解析用例）。

### 主题 6 — 死代码清理 ✅ 已完成

- `tsharkManager.hpp` 中的 `MiscUtil::getRandomString`（无调用方）/ `xml_to_json_recursive`（仅自递归、私有无外部调用方）已删除；`MiscUtil` 仅保留 `getDefaultDataDir`。
- （早前）`utils.cpp` 中重复的 `translationMap2` 与 `compareMapPerformance` 已删除。

### 主题 7 — README（本地构建部署）✅ 已完成

- 已补齐架构说明（mermaid 数据流图 + 核心组件表）；项目结构补上 `processUtil` 与 `docs/`；系统要求注明当前实时抓包依赖 Linux `epoll`（跨平台见主题 1）。
- 构建步骤、依赖、运行方式原 README 已覆盖，保持不变。
- 仅面向**本地构建部署**，不引入 GitHub Actions / CI。

---

## 验证方式

- 每个主题实施后各自验证：
  - Linux：`cmake` 全量构建 + `ctest`。
  - 本机 macOS（epoll 未跨平台前）：至少 `g++ -std=c++11 -fsyntax-only` 语法检查。
- 具体代码改动在各主题实施时再单独设计与确认。

---

## 进阶落地（学习项目视角）— 主题 8~10 ✅ 已完成

> 详见 `docs/PRODUCTIZATION_PLAN.md`。以下为落成情况。

### 主题 8 — 核心库 / UI 解耦（AnalysisSession 门面）✅
- 新增 `include/AnalysisSession.hpp` + `src/AnalysisSession.cpp`：聚合 `PcapAnalyzer` /
  `SQLiteUtil` / `PdmlToJsonConverter` / `LiveCapture` / `FlowMonitor`，对外暴露面向意图接口
  （`loadPcap` / `packetCount` / `packetsSnapshot` / `getHex` / `query` / `listAdapters` /
  `startLiveCapture` / `stopLiveCapture` / `startFlowMonitor` / `flowTrendSnapshot` /
  `exportDetailJson`）。`packetsSnapshot` 等读接口加锁返回拷贝，供 UI 线程安全调用。
- `src/main.cpp` 瘦身为纯 CLI 装配：交互输入 + 调门面，文件复制/移动等辅助函数搬进门面。
- 终于给此前无消费者的 `FlowMonitor::getAdaptersFlowTrendData` 接上门面出口。

### 主题 9 — 流式解析（去全量内存）✅
- `PcapAnalyzer` 抽出私有 `streamPackets` 逐包解析核心；新增
  `analysisFile(path, std::function<void(const Packet&)>)` 回调式重载，**逐包回调、不累积**。
  原两个累积式重载改为复用同一核心，行为不变。
- 新增测试 `OfflineAnalysisTest.StreamingMatchesAccumulating`：验证流式回调次数 == 累积解析包数
  （沿用“无 test.pcap 即跳过”约定；已用手工 2 包 pcap 一次性验证真实通过）。

### 主题 10 — Dear ImGui 原生前端（GLFW + OpenGL3）✅
- vendored 依赖：`include/imgui`（Dear ImGui 1.92.9）+ `include/glfw`（GLFW 3.3-stable，
  clone 后去除 `.git` 作纯源码树），放在 `include/<名字>/`（与 rapidjson/rapidxml/ip2region 同约定），
  CMake `add_subdirectory` 随项目编译，首次后离线可构建。
- CMake 新增 `imgui` 静态库（核心 + glfw/opengl3 后端）与 `tshark_gui` 可执行目标；GUI 块用
  `if(EXISTS include/glfw)` 守卫，未 clone 时自动跳过，不影响 CLI / 测试构建。
- `src/gui/main_gui.cpp`：GLFW+OpenGL3 事件循环 + 单窗口布局。报文列表用 `BeginTable` +
  `ImGuiListClipper`（只渲染可见行）、右侧详情 + 十六进制视图、查询 Tab、抓包控制（网卡下拉 +
  开始/停止）。耗时操作（载入/停止抓包解析）走 `std::async` 后台任务，UI 线程每帧轮询不阻塞；
  尝试加载系统中文字体以正常显示归属地/概要。
- 说明：流量趋势折线图需另加 ImPlot（未 vendored），本轮先留出 `flowTrendSnapshot` 门面出口。

### 验证结果（本机 macOS，Opus）
- `cmake --build build` 全量通过：`tshark_main`（CLI）、`tshark_gui`（GUI）、`unit_tests` 均构建成功。
- `ctest`：**27 passed / 4 skipped / 0 failed**（第 4 个 skip 为新增流式测试，无 pcap 时跳过）。
- GUI 运行冒烟：启动后运行 3 秒、无任何错误输出、正常创建窗口与渲染（SIGTERM 收尾）。

---

## 主题 10 补强 — 实时抓包流式显示 + 抓包文件按时间戳留存 ✅

> 起因：GUI 点“开始抓包”后列表不动、点“停止”卡住约 110 秒后崩溃。定位到三处问题并一并修复，
> 同时把抓包的实时体验补齐、文件命名去掉每次覆盖的 `capture.pcap`。

### 修复的三个 bug（`LiveCapture`）
- **停止卡死**：`stopCapture` 原来只置 `stopFlag` 关管道，但 tshark 是往 `-w` 文件写、几乎不写
  stdout，关管道它不退出 → 工作线程 `PcloseEx` 里的 `waitpid` 永久阻塞。改为 `stopCapture`
  给 tshark 发 `SIGTERM` 令其收尾（flush 文件 + 关 stdout），读循环随之 EOF 退出。
- **二次 join 崩溃**：按钮与关窗析构会各调一次 `stopCapture`，第二次 `join` 无效线程抛
  `std::system_error` 终止。改为幂等：`captureWorkThread_` 为空即直接返回。
- **双重 waitpid**：`stopCapture` 只发信号、不 `waitpid`，回收统一交给工作线程内的 `PcloseEx`，
  避免两个线程对同一 pid 竞争 `waitpid`。`tsharkPid_` 用 `std::atomic<pid_t>` 传递，并处理
  “pid 尚未就位”的极窄启动窗口。

### 实时显示（流式抓包）
- 抓包命令改为 `tshark -i <网卡> -l -w <file> -F pcap -P -T fields -e ...`：**同时**落盘原始
  pcap 且逐行把字段打到 stdout（`-P` 令写文件时仍打印、`-l` 行缓冲即时输出）。字段列表复用
  `tsharkFieldArgs()`，顺序与 `PacketParser::parseLine` 一致，与离线路径共用解析器。
- `LiveCapture::startCapture` 增加 `PacketCallback onPacket`：工作线程逐行解析成 `Packet`，
  实时回调交给调用方（回调在抓包线程执行，调用方自行加锁）。
- `AnalysisSession::startLiveCapture` 透传回调；GUI 用带锁队列 `liveIncoming` 承接，UI 线程
  每帧 `drainLive` 取出追加到列表并自动滚到底，实现边抓边显示。停止后再离线重解析一遍得到带
  正确 `file_offset` 的权威报文集，供 hex / 查询复用。

### 抓包文件按时间戳留存（去覆盖）
- 新增 `data/pcaps/` 子目录；每次抓包/载入按触发时刻生成 `capture_<时间戳>.pcap` 与配对的
  `packets_<时间戳>.db`（时间戳含毫秒，几乎不撞名），历史全部保留、不再覆盖。
- `AnalysisSession` 路径模型从固定 `pcapPath_/dbPath_` 改为按次生成的 `currentPcapPath_/
  currentDbPath_`；载入与停止抓包共用私有 `analyzeAndStore(pcap, db)` 收尾。实时抓包让 tshark
  直接写入带时间戳路径，省去原先“写 cwd/capture.pcap 再 move”的搬运。删除随之不再使用的
  `clearDirFiles`/`moveFile` 辅助函数。

### 验证结果（本机 macOS，Opus）
- 需 BPF 抓包权限：安装 Wireshark 自带的 ChmodBPF（`/dev/bpf*` 归 `access_bpf` 组可读），
  当前用户加入该组后免 sudo 抓包（新进程即生效，无需注销）。
- `cmake --build build` 全量通过；`ctest` 0 failed。
- GUI 实抓冒烟：开始抓包报文实时滚动、停止 0.015 秒优雅结束（无卡死/崩溃），
  `data/pcaps/` 生成配对的 `capture_<ts>.pcap` + `packets_<ts>.db`。

## 主题 10 补强 — GUI 功能对齐正式版界面 ✅

> 起因：对照 `docs/image.png`（正式版 EasyTshark 界面）盘点缺失功能，按用户决策补齐。
> 用户明确：**布局保留当前 Tab 风格**（不照搬侧边栏），只在其上增加缺失的功能与显示；
> 第一期（纯前端）与第二期（需后端新增）**本轮一起做**。详见 `docs/GUI_FEATURE_PLAN.md`。

### 后端新增（`AnalysisSession` 门面 + `PcapAnalyzer`）
- **协议分层树**：`PcapAnalyzer::getPacketDetailTree(frame, DetailNode&)` 对单包跑
  `tshark -Y frame.number==N -T pdml`，用 rapidxml 把 `<proto>/<field>` 递归解析成
  `DetailNode{label,value,children}`；门面 `getDetailTree` 委托之，供详情面板逐层展开。
- **显示过滤（tshark -Y）**：`PcapAnalyzer::getFramesByDisplayFilter(filter, frames)` 只取
  命中帧号（`-T fields -e frame.number`）；门面 `queryDisplayFilter` 再从既有报文快照按帧号
  筛出子集——**不重算 file_offset**，故过滤结果仍能正确取 hex，且获得完整 tshark 过滤语法。
- **另存**：`AnalysisSession::savePcapAs(dest)` 复制当前 pcap 到用户指定路径（工具栏“保存”）。
- **传输层字段**：`Packet` 增内存态 `transport`（"TCP"/"UDP"），由 `PacketParser::parseLine`
  依据 tcp/udp 端口字段哪个非空推断。**零改动** tshark 字段列表与 SQLite schema，仅供会话视图
  区分 TCP / UDP。

### 前端补齐（`src/gui/main_gui.cpp`，沿用 Tab 布局）
- **报文页**：过滤栏（tshark 显示过滤表达式 + 查找/清除 + 协议快速分类 全部/ARP/ICMP/ICMPv6）；
  表格扩为 11 列（时间 / 源IP·Mac / 源归属地 / 源端口 / 目的IP·Mac / 目的归属地 / 目的端口 /
  协议 / 大小 / 信息）；协议列**彩色徽标**；内网/环回地址加 `[内网]` 标签；**分页**（每页
  50/100/200/500 + 上/下一页 + 共 N 条）。实时抓包时不分页、保持流式滚动。
- **详情页**：上半区协议分层树（`ImGui::TreeNode` 递归渲染 `DetailNode`，选中报文时惰性加载）；
  下半区保留经典 offset|hex|ASCII 视图。
- **通信会话页**：按五元组聚合双向会话，用 `transport`+`protocol` 分类
  全部/TCP/UDP/DNS/HTTP/SSL-TLS/SSH；列出双端点、传输层、协议集合、包数、字节数。
- **统计分析页**：IP 统计 / 协议统计 / 国家(归属地)统计，前端聚合计数并按包数降序。
  会话与统计用“报文数变化才重建”的缓存，避免每帧 O(N)。
- **状态栏**：数据包总数 / 总字节数（增量维护）/ 状态 / “关于”弹窗。
- **进程分析**：占位页，注明依赖平台特定 socket→进程 映射，暂未实现。

### 不在本轮范围
- 进程分析真实实现（socket→pid，跨平台成本高）。
- 国家旗帜位图（现以归属地文本呈现）。

### 验证结果
- `cmake --build build` 全量通过（GUI 无新增告警）；`ctest` 维持 0 failed。
- tshark 侧实测：`-Y tcp -T fields -e frame.number` 正确返回命中帧号；单包 `-T pdml`
  正确给出 frame/eth/ip/udp 等协议层，与 `DetailNode` 解析一致。
