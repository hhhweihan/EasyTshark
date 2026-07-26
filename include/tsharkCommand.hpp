#ifndef tsharkCommand_hpp
#define tsharkCommand_hpp

#include <string>
#include <vector>

#include "tsharkDataType.hpp"

// 低层 tshark 交互工具：平台默认路径、命令参数构造、网卡枚举。
// 各职责类（PcapAnalyzer / LiveCapture / FlowMonitor / PdmlToJsonConverter）
// 依赖此处的自由函数，此处不反向依赖任何职责类——保持依赖单向。
namespace TsharkCommand
{
// tshark / editcap 的平台默认路径（单一真源）：
//   Linux 装在 /usr/bin，macOS 由 Wireshark.app 提供，Windows 装在 Program Files。
// 如与实际安装位置不符，调用方可自行覆盖传入的路径。
std::string defaultTsharkPath();
std::string defaultEditcapPath();

// 自动定位 tshark：按 环境变量 EASYTSHARK_TSHARK → 平台默认路径 → PATH →
// (Windows)注册表 Wireshark InstallDir → 常见安装目录 的顺序，返回首个真实存在的路径；
// 全都没命中时回退到平台默认路径（让后续报错仍指向一个合理位置）。
// 目标：装了就能用；装在非默认位置也可用环境变量手动指定，无需重新编译。
// 平台差异（PATH 分隔符 / .exe 后缀 / 注册表）都封装在实现里，POSIX 行为不受影响。
std::string resolveTsharkPath();

// 自动定位 editcap：优先取"解析到的 tshark 同目录"下的 editcap（保证版本/位置一致），
// 推导不出或不存在时回退到平台默认 editcap 路径。
std::string resolveEditcapPath();

// tshark 是否存在且可读（用于给出"未检测到 Wireshark"这类友好提示，不启动子进程）。
bool tsharkAvailable(const std::string& path);

// Wireshark 官方下载页地址（未检测到 tshark 时引导用户前往下载）。
std::string wiresharkDownloadUrl();

// 离线分析与实时抓包共用的字段列表：从 "-T fields" 到最后一个 "-e _ws.col.Info"。
// 顺序与 PacketParser::parseLine 的字段下标一一对应，改动需两处同步。
std::vector<std::string> tsharkFieldArgs();

// 枚举本机网卡（执行 `tshark -D` 并解析），滤掉 sshdump 等虚拟网卡。
// 失败时抛 std::runtime_error（与原 getNetworkAdapterInfo 行为一致）。
std::vector<AdapterInfo> listNetworkAdapters(const std::string& tsharkPath);
} // namespace TsharkCommand

#endif
