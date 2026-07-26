#include "PdmlToJsonConverter.hpp"

#include <fstream>
#include <iostream>
#include <vector>
#if !defined(_WIN32)
#include <sys/wait.h> // WIFEXITED / WEXITSTATUS（POSIX 专有）
#endif

#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidxml/rapidxml_utils.hpp"

#include "loguru/loguru.hpp"
#include "processUtil.hpp"
#include "utils.hpp"

PdmlToJsonConverter::PdmlToJsonConverter(const std::string& tsharkPath) : tsharkPath(tsharkPath) {}

// 将XML节点转换为JSON节点
void PdmlToJsonConverter::convertXmlNodeToJson(rapidxml::xml_node<>* xmlNode,
                                               rapidjson::Value&     jsonNode,
                                               rapidjson::Document::AllocatorType& allocator)
{
    for (rapidxml::xml_attribute<>* attr = xmlNode->first_attribute(); attr;
         attr                            = attr->next_attribute())
    {
        jsonNode.AddMember(rapidjson::Value(attr->name(), allocator),
                           rapidjson::Value(attr->value(), allocator), allocator);
    }

    bool hasChildNodes = false;
    for (rapidxml::xml_node<>* child = xmlNode->first_node(); child; child = child->next_sibling())
    {
        hasChildNodes = true;
        rapidjson::Value childJson(rapidjson::kObjectType);
        convertXmlNodeToJson(child, childJson, allocator);
        jsonNode.AddMember(rapidjson::Value(child->name(), allocator), childJson, allocator);
    }

    // 无子节点时，将节点文本作为字符串值
    if (!hasChildNodes && xmlNode->value_size() > 0)
    {
        jsonNode.SetString(xmlNode->value(), allocator);
    }
}

// 将PCAP文件转换为XML格式
bool PdmlToJsonConverter::convertPcapToXml(const std::string& pcapFile, const std::string& xmlFile)
{
    // 用 argv 方式执行 tshark，父进程读取 pdml 输出并写入 XML 文件，
    // 避免走 shell 和 ">" 重定向，消除文件路径注入风险
    std::vector<std::string> args = {tsharkPath, "-r", pcapFile, "-T", "pdml"};
    ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
    FILE*                    pipe      = ProcessUtil::PopenEx(args, &tsharkPid, "r");
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark for pcap->xml conversion");
        return false;
    }

    std::ofstream xmlOut(xmlFile, std::ios::binary);
    if (!xmlOut)
    {
        LOG_F(ERROR, "Failed to open XML output file: %s", xmlFile.c_str());
        ProcessUtil::PcloseEx(pipe, tsharkPid);
        return false;
    }

    char   buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0)
    {
        xmlOut.write(buf, static_cast<std::streamsize>(n));
    }
    xmlOut.close();

    int status = ProcessUtil::PcloseEx(pipe, tsharkPid);
#if defined(_WIN32)
    // Windows 下 PcloseEx 直接返回进程退出码（0 成功），无 waitpid 状态位可解析。
    return status == 0;
#else
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

// 将XML文件转换为JSON文件
bool PdmlToJsonConverter::convertXmlToJson(const std::string& xmlFile, const std::string& jsonFile)
{
    try
    {
        std::ifstream xmlFileStream(xmlFile);
        if (!xmlFileStream.is_open())
        {
            std::cerr << "无法打开XML文件: " << xmlFile << std::endl;
            return false;
        }

        std::string xmlContent((std::istreambuf_iterator<char>(xmlFileStream)),
                               std::istreambuf_iterator<char>());
        xmlFileStream.close();

        rapidxml::xml_document<> doc;
        doc.parse<0>(&xmlContent[0]);

        rapidjson::Document jsonDoc;
        jsonDoc.SetObject();
        rapidjson::Document::AllocatorType& allocator = jsonDoc.GetAllocator();

        rapidjson::Value pdmlObj(rapidjson::kObjectType);

        rapidxml::xml_node<>* pdmlNode = doc.first_node("pdml");
        if (!pdmlNode)
        {
            std::cerr << "XML文件中未找到pdml节点" << std::endl;
            return false;
        }

        // 添加pdml属性，但跳过version、creator、time和capture_file
        for (rapidxml::xml_attribute<>* attr = pdmlNode->first_attribute(); attr;
             attr                            = attr->next_attribute())
        {
            std::string attrName = attr->name();
            if (attrName != "version" && attrName != "creator" &&
                attrName != "time" && attrName != "capture_file")
            {
                pdmlObj.AddMember(rapidjson::Value(attr->name(), allocator).Move(),
                                rapidjson::Value(attr->value(), allocator).Move(), allocator);
            }
        }

        rapidjson::Value packetArray(rapidjson::kArrayType);

        for (rapidxml::xml_node<>* packetNode = pdmlNode->first_node("packet"); packetNode;
             packetNode                       = packetNode->next_sibling("packet"))
        {

            rapidjson::Value packetObj(rapidjson::kObjectType);

            for (rapidxml::xml_attribute<>* attr = packetNode->first_attribute(); attr;
                 attr                            = attr->next_attribute())
            {
                packetObj.AddMember(rapidjson::Value(attr->name(), allocator).Move(),
                                   rapidjson::Value(attr->value(), allocator).Move(), allocator);
            }

            rapidjson::Value protoArray(rapidjson::kArrayType);

            for (rapidxml::xml_node<>* protoNode = packetNode->first_node("proto"); protoNode;
                 protoNode                       = protoNode->next_sibling("proto"))
            {

                rapidjson::Value protoObj(rapidjson::kObjectType);

                for (rapidxml::xml_attribute<>* attr = protoNode->first_attribute(); attr;
                     attr                            = attr->next_attribute())
                {
                    protoObj.AddMember(rapidjson::Value(attr->name(), allocator).Move(),
                                       rapidjson::Value(attr->value(), allocator).Move(),
                                       allocator);
                }

                if (protoNode->first_node("field"))
                {
                    rapidjson::Value fieldArray(rapidjson::kArrayType);

                    for (rapidxml::xml_node<>* fieldNode = protoNode->first_node("field");
                         fieldNode; fieldNode            = fieldNode->next_sibling("field"))
                    {

                        rapidjson::Value fieldObj(rapidjson::kObjectType);

                        for (rapidxml::xml_attribute<>* attr = fieldNode->first_attribute(); attr;
                             attr                            = attr->next_attribute())
                        {
                            fieldObj.AddMember(rapidjson::Value(attr->name(), allocator).Move(),
                                               rapidjson::Value(attr->value(), allocator).Move(),
                                               allocator);
                        }

                        // 递归展开嵌套的 field 子节点
                        if (fieldNode->first_node("field"))
                        {
                            rapidjson::Value subFieldArray(rapidjson::kArrayType);

                            for (rapidxml::xml_node<>* subFieldNode =
                                     fieldNode->first_node("field");
                                 subFieldNode; subFieldNode = subFieldNode->next_sibling("field"))
                            {

                                rapidjson::Value subFieldObj(rapidjson::kObjectType);

                                for (rapidxml::xml_attribute<>* attr =
                                         subFieldNode->first_attribute();
                                     attr; attr = attr->next_attribute())
                                {
                                    subFieldObj.AddMember(
                                        rapidjson::Value(attr->name(), allocator).Move(),
                                        rapidjson::Value(attr->value(), allocator).Move(),
                                        allocator);
                                }

                                subFieldArray.PushBack(subFieldObj, allocator);
                            }

                            fieldObj.AddMember("field", subFieldArray, allocator);
                        }

                        fieldArray.PushBack(fieldObj, allocator);
                    }

                    protoObj.AddMember("field", fieldArray, allocator);
                }

                protoArray.PushBack(protoObj, allocator);
            }

            packetObj.AddMember("proto", protoArray, allocator);
            packetArray.PushBack(packetObj, allocator);
        }

        pdmlObj.AddMember("packet", packetArray, allocator);

        jsonDoc.AddMember("pdml", pdmlObj, allocator);

        // 翻译showname字段，针对所有数据包的proto字段
        if (jsonDoc.HasMember("pdml") &&
            jsonDoc["pdml"].HasMember("packet") &&
            jsonDoc["pdml"]["packet"].IsArray() &&
            jsonDoc["pdml"]["packet"].Size() > 0)
        {
            try {
                for (rapidjson::SizeType i = 0; i < jsonDoc["pdml"]["packet"].Size(); i++) {
                    if (jsonDoc["pdml"]["packet"][i].HasMember("proto") &&
                        jsonDoc["pdml"]["packet"][i]["proto"].IsArray() &&
                        jsonDoc["pdml"]["packet"][i]["proto"].Size() > 0) {
                        CommonUtil::translateShowNameFields(jsonDoc["pdml"]["packet"][i]["proto"], allocator);
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "翻译字段时发生异常: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "翻译字段时发生未知异常" << std::endl;
            }
        }

        rapidjson::StringBuffer                          jsonBuffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> jsonWriter(jsonBuffer);
        jsonDoc.Accept(jsonWriter);

        std::ofstream jsonFileStream(jsonFile);
        if (!jsonFileStream.is_open())
        {
            std::cerr << "无法创建JSON文件: " << jsonFile << std::endl;
            return false;
        }

        jsonFileStream << jsonBuffer.GetString();
        jsonFileStream.close();

        std::cout << "XML文件已成功转换为JSON文件并保存到 " << jsonFile << std::endl;
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "转换过程中发生异常: " << e.what() << std::endl;
        return false;
    }
}
