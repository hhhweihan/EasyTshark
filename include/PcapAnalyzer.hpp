#ifndef PcapAnalyzer_hpp
#define PcapAnalyzer_hpp

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "PcapFileReader.hpp"
#include "tsharkDataType.hpp"

// 离线解析：读取 pcap 文件，逐行解析 tshark 字段输出为 Packet，并提供
// 报文列表 / 十六进制原始数据的访问。只负责“解析与就地存取”，不涉及抓包、
// 数据库入库或格式转换（那些是 LiveCapture / main 的 SQLiteUtil / PdmlToJsonConverter 的职责）。
class PcapAnalyzer
{
public:
    // tsharkPath 缺省用平台默认路径；ip2RegionDbPath 用于 IP 地理位置查询。
    explicit PcapAnalyzer(const std::string& tsharkPath,
                          const std::string& ip2RegionDbPath = "resources/ip2region.xdb");

    void        setIp2RegionDbPath(const std::string& path) { ip2RegionDbPath = path; }
    std::string getIp2RegionDbPath() const { return ip2RegionDbPath; }

    std::string getTsharkPath() const { return tsharkPath; }
    void        setTsharkPath(const std::string& path) { tsharkPath = path; }

    bool analysisFile(const std::string& filePath);

    bool analysisFile(const std::string& filePath, std::vector<std::shared_ptr<Packet>>& packets);

    // 流式分析：逐包解析、每解析出一个包就回调 onPacket，**不累积到 allPackets**。
    // 适合大文件“只过一遍、不常驻内存”的场景（如边解析边分批入库/统计）。
    // 注意：此重载不填充 allPackets、也不打开随机读取器，故其后 getPacketHexData 不可用。
    bool analysisFile(const std::string& filePath, const std::function<void(const Packet&)>& onPacket);

    void printAllPackets();

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 取指定报文的协议分层树（tshark -T pdml 单包解析），供详情面板展开。
    // 依赖 currentFilePath（analysisFile 成功后有效）；失败返回 false。
    bool getPacketDetailTree(uint32_t frameNumber, DetailNode& root);

    // 用 tshark 显示过滤表达式（-Y）筛选当前文件，回填匹配的帧号列表。
    // 只取帧号、不重算 file_offset，故配合已加载报文的既有 offset 可保持 hex 正确。
    // filter 为空视为“全部匹配”返回 false（调用方应据此走不过滤路径）。
    bool getFramesByDisplayFilter(const std::string&     displayFilter,
                                  std::vector<uint32_t>& frameNumbers);

private:
    // 逐包解析核心：跑 tshark 读文件、算 file_offset、补地理位置，每解析出一个
    // Packet 就回调 onPacket。本身不累积——由调用方决定“累积”还是“流式丢弃”。
    bool streamPackets(const std::string&                                       filePath,
                       const std::function<void(const std::shared_ptr<Packet>&)>& onPacket);

    // 处理每一个数据包（就地存入 allPackets）
    void processPacket(const std::shared_ptr<Packet>& packet);

private:
    std::string tsharkPath;
    std::string ip2RegionDbPath;
    std::string currentFilePath;

    // 按 offset 随机读取报文原始字节：分析完成后打开一次，getPacketHexData 复用，
    // 避免每次取包都重新 open/close 文件（POSIX 走 mmap，非 POSIX 走 ifstream）。
    PcapFileReader fileReader;

    // tshark 的 frame_number 从 1 起、稠密递增，故用 vector 按 (帧号-1) 下标直存：
    // 相比 unordered_map 省去每包一次哈希桶节点分配与哈希/取模，遍历也变成对连续内存的
    // 顺序扫描，对 CPU cache 与预取器都更友好。理论上若出现空洞，对应槽为空指针。
    std::vector<std::shared_ptr<Packet>> allPackets;
};

#endif
