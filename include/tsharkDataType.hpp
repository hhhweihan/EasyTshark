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
    // CAN 帧 ID（SocketCAN/原始 CAN 链路）：去掉 EFF/RTR/ERR 标志后的 11/29 位 ID，非 CAN 帧为 0。
    // 仅内存态、不入库，供显示过滤（can.id）使用。
    uint32_t can_id = 0;
    // 是否 DoIP 帧（含携带 UDS 的诊断消息，此时 protocol 为 "UDS"）：仅内存态，供显示过滤（doip）使用。
    bool is_doip = false;
    // 实时抓包时反查到的归属进程（本机 socket→PID 映射，仅当前用户权限内可解析）：
    // 仅内存态、不入库；离线回放 pcap 时 socket 已不存在，恒为空/0。
    std::string proc_name;
    int         proc_pid = 0;
    // GUI 表格每帧都重画可见行，即使这些包的数据早已不变；显示时间戳格式化字符串懒缓存于此，
    // 首次绘制后各帧复用，不必每帧重新格式化。跟随 Packet 生命周期，无需单独失效逻辑。
    std::string display_time_cache;
};

// 协议分层树节点：承载展示用文本（label/value/children），供详情面板递归展开。
struct DetailNode
{
    std::string             label; // 显示名（PDML showname，回退到 name）
    std::string             value; // 取值（PDML show，回退到 value）
    std::vector<DetailNode> children;
    // 叶子节点的 "label: value" 拼接懒缓存：详情面板选中一个包后会持续多帧重画同一棵树，
    // 树本身在下次选中新包前不变，缓存避免每帧重新拼接。
    std::string display_text_cache;
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