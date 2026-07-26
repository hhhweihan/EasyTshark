# Windows 构建指南

EasyTshark 支持在 Windows 上原生编译（MSVC），与 Linux / macOS 共用同一套 CMake 工程。
本文档说明依赖、构建步骤与 Windows 移植的实现要点。

## 1. 依赖

| 依赖 | 说明 | 编译期 | 运行期 |
| --- | --- | :---: | :---: |
| **VS 2022 Build Tools** | 含 MSVC 编译器、Windows SDK；自带 CMake + Ninja | ✅ | — |
| **Wireshark** | 提供 `tshark.exe` / `editcap.exe` | — | ✅ |
| sqlite3 | 已 vendored（`third_party/sqlite3/`），随工程一起编译 | 内置 | 内置 |
| GLFW / Dear ImGui | 已 vendored（`third_party/glfw`、`third_party/imgui`），仅 GUI 需要 | 内置 | 内置 |

> 安装 Build Tools 时勾选「使用 C++ 的桌面开发」工作负载即可（含 MSVC 与 Windows SDK）。
> Build Tools 自带的 CMake / Ninja 位于
> `...\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\` 下，脚本会自动使用，无需另装。

## 2. 一键构建

在普通 `cmd` 中执行（**不要**用 Git Bash / MSYS，其会改写命令行里的 `/` 参数）：

```bat
scripts\build_windows.bat            :: Release，构建 CLI + GUI
scripts\build_windows.bat Debug      :: Debug
```

产物：

- `output\tshark_main.exe` —— 命令行版
- `output\tshark_gui.exe` —— 图形界面版

若 VS Build Tools 装在非默认路径，先设置环境变量：

```bat
set "VSBUILDTOOLS=D:\VS2022\BuildTools"
scripts\build_windows.bat
```

## 3. 手动构建（等价步骤）

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmake -S . -B build_win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build_win -j
```

## 4. 运行

程序启动时按以下顺序自动定位 `tshark.exe`（见 `TsharkCommand::resolveTsharkPath`）：

1. 环境变量 `EASYTSHARK_TSHARK`（手动指定，优先级最高）
2. 平台默认路径 `C:\Program Files\Wireshark\tshark.exe`
3. `PATH` 中搜索
4. 注册表 `HKLM\SOFTWARE\Wireshark`（含 `WOW6432Node`）的 `InstallDir`
5. 常见安装目录

因此标准安装的 Wireshark 无需任何配置即可被找到。若装在非常规位置，可设置环境变量覆盖，或在 GUI 顶部的「tshark 路径」输入框中指定（无需重新编译）：

```bat
set "EASYTSHARK_TSHARK=D:\Tools\Wireshark\tshark.exe"
output\tshark_gui.exe
```

未找到时，CLI 会打印提示、GUI 会显示红色告警，并给出 Wireshark 下载地址。实时抓包需以管理员身份运行，并确保已安装 Npcap（Wireshark 安装时可一并勾选）。

## 5. 移植实现要点

所有平台差异都以 `#if defined(_WIN32)` / `#else` 隔离，POSIX（Linux/macOS）代码路径
保持原样、行为不变。核心抽象：

| 关注点 | POSIX 实现 | Windows 实现 |
| --- | --- | --- |
| 进程创建 + 管道 | `fork` + `execvp` + `pipe` | `CreateProcessA` + `CreatePipe`（`src/processUtil.cpp`）|
| 进程句柄类型 | `pid_t` | `HANDLE`（`ProcessUtil::ProcHandle` 统一别名）|
| 终止进程 | `kill(SIGTERM/SIGKILL)` | `TerminateProcess` |
| 回收进程 | `waitpid` | `WaitForSingleObject` + `GetExitCodeProcess` |
| I/O 多路复用 | `poll`（`EventPollerPoll.cpp`）| `PeekNamedPipe` 轮询（`EventPollerWin.cpp`）|
| 非阻塞读管道 | `fcntl(O_NONBLOCK)` + `read`（`PipeIOPosix.cpp`）| `PeekNamedPipe` + `ReadFile`（`PipeIOWin.cpp`）|
| 文件随机读 | `mmap`（`PcapFileReader.cpp`）| `std::ifstream` 兜底 |
| 建目录 | `mkdir(path, 0755)` | `_mkdir(path)` |
| sqlite3 | 链接系统库 | vendored `sqlite3.c` 一起编译 |
| 中文字体 | `/System/...`、`wqy-zenhei` | `C:\Windows\Fonts\msyh.ttc` 等 |

### MSVC 注意事项

- 源码含中文注释，**必须** `/utf-8` 编译（否则被按 GBK/936 解析报 C4819/C2xxx）。
  已在 `CMakeLists.txt` 中对 MSVC 目标统一加上，无需手动指定。
- 项目固定 C++11；MSVC 无 `/std:c++11` 选项（C++11 为隐含基线），故不传该标志。
