#ifndef tsharkCommand_hpp
#define tsharkCommand_hpp

#include <string>
#include <vector>

#include "tsharkDataType.hpp"

// 低层 tshark 交互工具：平台默认路径、命令参数构造、网卡枚举。
// 依赖单向：各职责类依赖此处的自由函数，此处不反向依赖任何职责类。
namespace TsharkCommand
{
// tshark / editcap 的平台默认路径（单一真源）：Linux /usr/bin、macOS Wireshark.app、
// Windows Program Files。与实际安装位置不符时调用方可自行覆盖。
std::string defaultTsharkPath();
std::string defaultEditcapPath();

// 自动定位 tshark，按序返回首个真实存在的路径，全未命中则回退平台默认路径：
//   环境变量 EASYTSHARK_TSHARK → 平台默认 → PATH → (Windows)注册表 → 常见安装目录。
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
