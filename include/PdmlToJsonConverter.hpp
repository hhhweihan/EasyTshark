#ifndef PdmlToJsonConverter_hpp
#define PdmlToJsonConverter_hpp

#include <string>

#include "rapidjson/document.h"
#include "rapidxml/rapidxml.hpp"

// 格式转换：pcap --(tshark -T pdml)--> XML(PDML)，再把 PDML XML 转成 JSON。
// 只负责格式转换，不涉及抓包 / 解析 / 入库。
class PdmlToJsonConverter
{
public:
    explicit PdmlToJsonConverter(const std::string& tsharkPath);
    virtual ~PdmlToJsonConverter() {}

    std::string getTsharkPath() const { return tsharkPath; }
    void        setTsharkPath(const std::string& path) { tsharkPath = path; }

    // 将PCAP文件转换为XML格式
    bool convertPcapToXml(const std::string& pcapFile, const std::string& xmlFile);

    // 将XML文件转换为JSON文件
    bool convertXmlToJson(const std::string& xmlFile, const std::string& jsonFile);

private:
    // 辅助函数：将XML节点转换为JSON节点
    void convertXmlNodeToJson(rapidxml::xml_node<>* xmlNode, rapidjson::Value& jsonNode,
                              rapidjson::Document::AllocatorType& allocator);

private:
    std::string tsharkPath;
};

#endif
