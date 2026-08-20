#ifndef NativeAnalyzer_hpp
#define NativeAnalyzer_hpp

#include <memory>
#include <string>
#include <vector>

#include "NativePacketParser.hpp"
#include "PcapFileReader.hpp"
#include "tsharkDataType.hpp"

// 自研离线分析引擎：直接解析 pcap / pcapng 文件（无需 tshark）。
// 与 PcapAnalyzer 职责平行，供无 tshark 环境兜底：
//   - analyzeFile：遍历文件记录，逐包经 NativePacketParser 解析成 Packet 向量
//     （file_offset 指向 packet-data 起始，hex 可随机读）
//   - getPacketHexData / getPacketDetailTree / getFramesByDisplayFilter
// 线程约定：与 PcapAnalyzer 一致，由调用方（AnalysisSession 的 analyzerMutex_）串行化。
class NativeAnalyzer
{
public:
    NativeAnalyzer() = default;

    // 解析 pcap/pcapng 文件（自动识别格式）。out 回填全部报文。
    bool analyzeFile(const std::string& filePath, std::vector<std::shared_ptr<Packet>>& out);

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& out) const;
    bool getPacketDetailTree(uint32_t frameNumber, DetailNode& root) const;
    // 自研显示过滤子集；不支持的表达式经 err 返回原因。
    bool getFramesByDisplayFilter(const std::string& expr, std::vector<uint32_t>& frames,
                                  std::string* err = nullptr) const;

    bool isOpen() const { return reader_.isOpen(); }
    const std::string& currentPath() const { return currentPath_; }

private:
    PcapFileReader reader_;
    std::string    currentPath_;
    // 全部报文；读 hex / 详情树的字节偏移与长度直接取自 Packet 的 file_offset / cap_len，不另存平行数组。
    std::vector<std::shared_ptr<Packet>> packets_;
    // 文件链路层类型（供 getPacketDetailTree 正确重解析：Ethernet/NULL/SLL 等）。
    int  linkType_ = 1;
    bool analyzed_ = false;

    // CAN 详情查询的增量重放缓存：canReplayCache_ 已喂入帧 [1, canReplayedUpTo_]，
    // 顺序浏览时只需再喂入 1 帧而非从头重放全部历史帧。乱序往回跳时整体重置重放。
    mutable NativePacketParser::IsoTpReassembler canReplayCache_;
    mutable uint32_t                             canReplayedUpTo_ = 0;
};

#endif
