#ifndef tsharkDataType_hpp
#define tsharkDataType_hpp

#include <cstdint>
#include <string>
#include <vector>

struct Packet
{
    // 类内初始化（C++11）：确保 parseLine 未显式赋值的字段（如无端口的包）
    // 不会残留未定义值被写入数据库
    int         frame_number = 0;
    double      time         = 0.0;
    uint32_t    cap_len      = 0;
    uint32_t    len          = 0;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string src_location;
    uint16_t    src_port = 0;
    std::string dst_ip;
    std::string dst_location;
    uint16_t    dst_port = 0;
    std::string protocol;
    std::string info;
    // 该报文在 pcap 文件中的字节偏移。累计值可超过 4GB，用 64 位避免大文件溢出。
    uint64_t file_offset = 0;
    // 传输层协议（"TCP"/"UDP"/""）：仅内存态、不入库，供 GUI 会话视图区分 TCP/UDP。
    std::string transport;
};

// 协议分层树节点：承载展示用文本（label/value/children），供详情面板递归展开。
struct DetailNode
{
    std::string             label; // 显示名（PDML showname，回退到 name）
    std::string             value; // 取值（PDML show，回退到 value）
    std::vector<DetailNode> children;
};

struct PcapHeader
{
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PacketHeader
{
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

struct AdapterInfo
{
    int         id;
    std::string name;
    std::string remark;
};

#endif