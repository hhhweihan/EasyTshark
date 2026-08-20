# EasyTshark - 网络数据包捕获与分析工具

社区正式版由 **“轩辕之风”老师** 维护，见 [easytshark.com](https://www.easytshark.com/)。
> 早期未完成的实现（仅含后端部分，无 GUI）保存在本仓库 [`feature/V1`](../../tree/feature/V1) 分支；当前分支是用AI重构后的版本。

EasyTshark 支持实时抓包与离线 PCAP 分析、SQLite 存储、XML/JSON 格式转换，提供**命令行**、**原生图形界面**与**Web 界面**三种前端。

**无需预装 Wireshark 即可开箱即用**：项目内置自研解析引擎（libpcap 抓包 + 内置协议解析），覆盖常用协议（Ethernet/VLAN/ARP/IPv4/IPv6/ICMP/TCP/UDP/DNS/HTTP/TLS/SSH 等）与**汽车诊断协议**（DoIP / UDS / CAN / CAN FD）。安装 Wireshark 的 tshark 后可解锁**完整协议详情树、显示过滤、流量趋势**等增强能力（自动检测，无需配置）。

![图形界面](images/easytshark_gui.png)

## 功能特点

- **双模式**：实时抓包（从网卡捕获）/ 离线分析（解析已有 PCAP 文件）
- **三前端**：命令行 `tshark_main`（交互式菜单）/ 图形界面 `tshark_gui`（Dear ImGui，包列表 / 十六进制 / 协议详情树 / 显示过滤）/ Web 界面 `tshark_web`（headless 服务器上跑引擎，浏览器远程访问同一套富界面）
- **双引擎自动切换**：检测到 tshark 用其完整能力；未安装时自动降级到内置引擎（功能一致：抓包/解析/hex/详情树/常用过滤/结构化查询）
- **数据存储**：捕获的数据包存入 SQLite，支持快速查询
- **格式转换**：PCAP → tshark PDML(XML) → JSON；报文快照可导出 CSV（Web 界面有导出按钮）；离线分析支持 **pcapng**（自动识别，hex 视图正确）
- **IP 地理位置**：基于 ip2region 自动解析归属地（库文件缺失时优雅降级为空归属地，不再退出程序）
- **tshark 自动探测**：依次尝试环境变量 `EASYTSHARK_TSHARK`、平台默认路径、`PATH`、Windows 注册表；也可手动指定（无需重编译）
- **汽车诊断协议**：DoIP（ISO 13400-2，TCP/UDP 13400，含车辆识别/路由激活/诊断消息）、UDS（ISO 14229-1，SID 服务名 + 正/负响应 + NRC 解释）、CAN/CAN FD（SocketCAN DLT 227 / 原始 CAN 228 / CAN FD 229 链路类型，EFF 扩展帧、BRS/ESI 标志、ISO-TP 单帧解包），支持显示过滤 `doip` / `uds` / `can` / `can.id`
- **查询**：支持 MAC / IP / 端口 / 归属地模糊匹配（`*` 通配；字面 `%`/`_` 已转义），结果可导出 JSON
- **Web 安全**：所有 `/api/*` 需 `X-Auth-Token`（启动时生成打印，可用 `EASYTSHARK_WEB_TOKEN`/`--token` 固定）+ Origin 校验；`/api/load` 与导出限用户主目录/`data/` 下
- **大文件**：Web 报文列表分页拉取、实时缓冲有上限（长抓包丢弃最旧）；统计页带协议/IP 分布条形图

## 架构

程序以 **`AnalysisSession`（门面）** 为唯一入口，对上服务 CLI / GUI / Web 三种前端，对下装配各职责单一的模块：

| 组件 | 职责 |
|------|------|
| `AnalysisSession` | 门面：装配并协调下列模块 || `LiveCapture` | 实时抓包（tshark 子进程 + `EventPoller` 非阻塞读） |
| `PcapAnalyzer` | 离线 PCAP 解析、格式转换调度 |
| `PacketParser` | 将 tshark 的 fields 文本行解析为 `Packet` |
| `PcapFileReader` | 按偏移随机读取 PCAP 原始字节（POSIX `mmap` / `ifstream` 回退） |
| `PdmlToJsonConverter` | PDML(XML) → JSON |
| `FlowMonitor` | 各网卡流量趋势监控 |
| `TsharkCommand` | tshark 路径解析、命令参数构造、网卡枚举 |
| `SQLiteUtil` / `IP2RegionUtil` | 数据入库与查询 / IP 归属地解析 |
| `ProcessUtil` / `EventPoller` | 子进程创建回收 / I/O 多路复用抽象 |

安全要点：子进程调用统一走 `ProcessUtil::PopenEx` 的参数向量方式（`execvp`，不经 `/bin/sh`），避免 shell 注入；SQL 查询统一走 `sqlite3_bind_*` 参数化绑定，避免 SQL 注入。Web 服务默认只绑 `127.0.0.1`（远程访问走 SSH 端口转发，勿裸绑 `0.0.0.0`——该服务会驱动特权抓包）。

## 系统要求

- **平台**：macOS（已验证）、Windows（MSVC，已支持）、Linux（与 macOS 共用 `poll` 实现，理论支持，待验证）
- **tshark（可选）**：未安装时使用内置引擎（覆盖常用协议）；安装 Wireshark 可获得完整协议详情/显示过滤/流量趋势
- **libpcap**：内置引擎的实时抓包需要（macOS 系统自带；Linux 装 `libpcap-dev`；Windows 装 Npcap SDK）。未找到时编译仍通过，仅实时抓包不可用，离线解析不受影响
- SQLite3、C++11 编译器
- CMake 3.10+（若用 CMake 4.x 需加 `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`，脚本已内置）

## 依赖库

以下库以 vendored 源码形式随仓库提供（`third_party/`），首次 clone 后即可离线构建：sqlite3、loguru、rapidjson、rapidxml、ip2region、Dear ImGui + GLFW（GUI 依赖，未就位时 CMake 会自动跳过 `tshark_gui` 目标）、cpp-httplib（Web 依赖，单头文件，未就位时自动跳过 `tshark_web` 目标）。

## 安装与构建

**1. 安装依赖**

```bash
# macOS（wireshark 可选：装了解锁完整协议；不装也能用内置引擎）
brew install --cask wireshark && brew install cmake

# Linux (Debian/Ubuntu，命令待再次验证；tshark/libpcap 均为可选依赖)
sudo apt-get install -y build-essential cmake tshark libpcap-dev libsqlite3-dev

# Windows：安装 Wireshark（提供 tshark.exe）与 VS 2022 Build Tools（C++ 工作负载）
```

**2. 克隆并构建**

```bash
git clone git@github.com:hhhweihan/EasyTshark.git
cd EasyTshark
./scripts/build_unix.sh          # 默认清理构建、编译、运行测试；--help 查看更多选项
```

Windows 下在普通 `cmd`（非 Git Bash）中运行 `scripts\build_windows.bat`。

构建产物输出到 `output/`：`tshark_main`（CLI）、`tshark_gui`（GUI，依赖就位时）、`tshark_web`（Web，依赖就位时）、`unit_tests`。

## 使用方法

```bash
./output/tshark_main   # 命令行版：按提示选择实时抓包/离线分析，解析入库后可选查询
./output/tshark_gui    # 图形界面版：打开 PCAP 或启动抓包，浏览包列表/十六进制/协议树，支持显示过滤
./output/tshark_web    # Web 版：启动 HTTP 服务（默认 127.0.0.1:8080），浏览器访问同一套富界面
```

**Web 版说明**：适合把抓包/分析引擎跑在无图形界面的服务器上、从自己电脑的浏览器远程使用。

```bash
./output/tshark_web                      # 默认 http://127.0.0.1:8080
./output/tshark_web --host 127.0.0.1 --port 9000   # 自定义 host/port（也可用环境变量 EASYTSHARK_WEB_HOST/PORT）
./output/tshark_web --token mytoken      # 指定固定访问令牌（也可用环境变量 EASYTSHARK_WEB_TOKEN）
```

**访问令牌**：Web 服务所有 `/api/*` 请求必须携带 `X-Auth-Token` 头（浏览器首次打开页面时输入服务器启动时打印的令牌，保存在 localStorage；API 场景用 curl 加 `-H "X-Auth-Token: <令牌>"`）。未指定时启动自动生成并打印。浏览器请求还校验 Origin 与 Host 一致，防 DNS rebinding / 跨站请求。

远程访问请用 SSH 端口转发，**不要**把服务裸绑到 `0.0.0.0`（本服务会驱动特权抓包）：

```bash
ssh -L 8080:127.0.0.1:8080 user@server   # 本机浏览器开 http://127.0.0.1:8080 即可
```

页面上：填服务器端 PCAP 路径「载入并分析」做离线分析；或「刷新网卡 → 选网卡 → 开始抓包」做实时抓包（边抓边刷新），停止后可看协议详情/十六进制。会话与统计在前端聚合，与 GUI 口径一致。

输出文件位于 `data/`：`pcaps/capture_<时间戳>.pcap`（抓包）、`pcaps/packets_<时间戳>.db`（SQLite）、`packets.xml`（PDML）、`packets.json`。`data/` 与 `logs/` 为运行时生成目录，已 gitignore。

## 单元测试

基于 Google Test（构建时自动拉取），覆盖解析、抓包、数据库、格式转换、错误处理、IP 归属地、进程管理等场景；缺少 tshark 或测试数据的用例会自动 SKIP。

```bash
./output/unit_tests                                          # 全部测试
./output/unit_tests --gtest_filter=TsharkToolsTest.*          # 指定套件
./output/unit_tests --gtest_output=xml:test_report.xml        # 生成报告
```

## 项目结构

```
.
├── CMakeLists.txt
├── scripts/build_unix.sh / build_windows.bat
├── include/            # 第一方头文件
├── src/                # 第一方源文件（main.cpp / gui/main_gui.cpp / web/main_web.cpp 为三个入口）
├── web/                # Web 前端静态资源（index.html / app.js / style.css）
├── third_party/        # vendored 第三方库
├── tests/              # 单元测试
├── resources/          # 运行所需资源（ip2region.xdb）
└── output/             # 构建产物（gitignore；可用 -DEASYTSHARK_OUTPUT_DIR= 覆盖）
```

## 分支说明

- `main`：主线，始终可构建可用的最新版本。
- `feature/dev`：开发分支，与 `main` 保持同步（本地 merge --ff-only 推进），已包含 Web 前端、令牌认证、并发加固等新特性。
- `feature/V1`：早期未完成的实现（仅含后端部分，无 GUI），仅作历史参考，不再维护。

> 本地无权限推送时，可用 `git push origin main feature/dev` 同步远端；不建议在共享仓库上重写历史。

## 许可证

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MIT 许可证，允许自由使用、修改和分发，需保留原始版权声明。完整条款见 [LICENSE](./LICENSE)。
