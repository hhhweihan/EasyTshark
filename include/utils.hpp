#ifndef utils_hpp
#define utils_hpp

#include <chrono>
#include <iomanip>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "rapidjson/document.h"

struct sqlite3;

#include "ip2region/xdb_search.h"
#include "tsharkDataType.hpp"

/**
 * @brief IP地理位置查询工具类
 */
class IP2RegionUtil
{
public:
    static bool init(const std::string& xdbFilePath);

    static std::string getIpLocation(const std::string& ip);

private:
    static std::shared_ptr<xdb_search_t> xdbPtr;
    static std::string                   parseLocation(const std::string& input);
};

/**
 * @brief 通用工具类，提供时间戳生成等功能
 */
class CommonUtil
{
public:
    /**
     * @return 格式：YYYYMMDDHHMMSSmmm（年月日时分秒毫秒）
     */
    static std::string get_timestamp();

    static void translateShowNameFields(rapidjson::Value&                   value,
                                        rapidjson::Document::AllocatorType& allocator);
};

/**
 * @brief SQLite数据库操作工具类
 *
 * 提供数据包的存储、查询和导出功能
 */
class SQLiteUtil
{
public:
    /**
     * @throw std::runtime_error 如果数据库连接失败
     */
    SQLiteUtil(const std::string& dbname);

    ~SQLiteUtil();

    bool createPacketTable();

    bool insertPacket(std::vector<std::shared_ptr<Packet>>& packets);

    /**
     * @param limit 最多返回的行数；<0 表示不分页、返回全部（默认，保持旧行为）
     * @param offset 跳过的行数，仅在 limit>=0 时生效
     *
     * @note limit>=0 时按 frame_number 升序返回，保证翻页结果稳定；
     *       大抓包下用分页可避免一次性把全表读进内存造成内存尖峰。
     */
    bool queryPacket(std::vector<std::shared_ptr<Packet>>& packetList, int limit = -1,
                     int offset = 0);

    /**
     * @param conditions 查询条件，支持MAC地址、IP地址、端口和地理位置
     */
    bool queryPackets(const std::map<std::string, std::string>& conditions,
                      std::string&                              jsonResult);

    bool saveQueryResultToFile(const std::string& jsonResult, const std::string& filePath);

private:
    sqlite3* db = nullptr;

    /**
     * @brief 参数化查询中的一个绑定值
     *
     * SQL 语句中用 `?` 占位，实际值放在这里，执行时通过 sqlite3_bind_* 绑定，
     * 从根本上避免把用户输入拼进 SQL 文本造成注入。
     */
    struct BindParam
    {
        enum Type
        {
            Text,
            Int
        } type;
        std::string text;     // Type == Text 时有效
        int         intValue; // Type == Int 时有效
    };

    std::string packetsToJson(std::vector<std::shared_ptr<Packet>>& packets);

    /**
     * @param params 输出参数，按 `?` 出现顺序收集需要绑定的值
     */
    std::string buildFuzzyQuery(const std::map<std::string, std::string>& conditions,
                                std::vector<BindParam>&                   params);
};

#endif