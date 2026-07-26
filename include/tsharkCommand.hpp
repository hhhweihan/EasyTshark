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

// 离线分析与实时抓包共用的字段列表：从 "-T fields" 到最后一个 "-e _ws.col.Info"。
// 顺序与 PacketParser::parseLine 的字段下标一一对应，改动需两处同步。
std::vector<std::string> tsharkFieldArgs();

// 枚举本机网卡（执行 `tshark -D` 并解析），滤掉 sshdump 等虚拟网卡。
// 失败时抛 std::runtime_error（与原 getNetworkAdapterInfo 行为一致）。
std::vector<AdapterInfo> listNetworkAdapters(const std::string& tsharkPath);
} // namespace TsharkCommand

#endif
