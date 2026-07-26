#ifndef PacketParser_hpp
#define PacketParser_hpp

#include <string>

#include "tsharkDataType.hpp"

// 纯粹的行解析：把一行 tshark "-T fields" 制表符分隔输出解析成 Packet。
// 不依赖 tshark 进程、不做任何 IO、不查询 IP 地理位置——因此可脱离 tshark 独立单测。
// 字段顺序与 TsharkCommand::tsharkFieldArgs() 严格对应（0..15），改动需两处同步。
namespace PacketParser
{
// 解析成功返回 true；字段数不足 16 返回 false。
// 仅填充报文的协议字段，file_offset / src_location / dst_location 由调用方另行补齐。
bool parseLine(const std::string& line, Packet& packet);
} // namespace PacketParser

#endif
