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
    /**
     * @brief 初始化IP2Region
     * @param xdbFilePath xdb文件路径
     * @return true 初始化成功
     * @return false 初始化失败
     */
    static bool init(const std::string& xdbFilePath);

    /**
     * @brief 获取IP地址的地理位置
     * @param ip IP地址
     * @return 地理位置信息
     */
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
     * @brief 获取当前时间的格式化时间戳
     * @return 格式：YYYYMMDDHHMMSSmmm（年月日时分秒毫秒）
     */
    static std::string get_timestamp();

    /**
     * @brief 翻译字段名称
     * @param value rapidjson值对象
     * @param allocator rapidjson分配器
     */
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
     * @brief 构造函数
     * @param dbname 数据库文件路径
     * @throw std::runtime_error 如果数据库连接失败
     */
    SQLiteUtil(const std::string& dbname);

    /**
     * @brief 析构函数，关闭数据库连接
     */
    ~SQLiteUtil();

    /**
     * @brief 创建数据包表
     * @return true 创建成功
     * @return false 创建失败
     */
    bool createPacketTable();

    /**
     * @brief 批量插入数据包
     * @param packets 要插入的数据包列表
     * @return true 插入成功
     * @return false 插入失败
     */
    bool insertPacket(std::vector<std::shared_ptr<Packet>>& packets);

    /**
     * @brief 查询数据包（可选分页）
     * @param packetList 用于存储查询结果的列表
     * @param limit 最多返回的行数；<0 表示不分页、返回全部（默认，保持旧行为）
     * @param offset 跳过的行数，仅在 limit>=0 时生效
     * @return true 查询成功
     * @return false 查询失败
     *
     * @note limit>=0 时按 frame_number 升序返回，保证翻页结果稳定；
     *       大抓包下用分页可避免一次性把全表读进内存造成内存尖峰。
     */
    bool queryPacket(std::vector<std::shared_ptr<Packet>>& packetList, int limit = -1,
                     int offset = 0);

    /**
     * @brief 根据条件查询数据包并返回JSON格式结果
     * @param conditions 查询条件，支持MAC地址、IP地址、端口和地理位置
     * @param jsonResult 输出参数，存储JSON格式的查询结果
     * @return true 查询成功
     * @return false 查询失败
     */
    bool queryPackets(const std::map<std::string, std::string>& conditions,
                      std::string&                              jsonResult);

    /**
     * @brief 将查询结果保存到JSON文件
     * @param jsonResult JSON格式的查询结果字符串
     * @param filePath 保存文件的路径
     * @return true 保存成功
     * @return false 保存失败
     */
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

    /**
     * @brief 将数据包列表转换为JSON格式
     * @param packets 数据包列表
     * @return JSON格式的字符串
     */
    std::string packetsToJson(std::vector<std::shared_ptr<Packet>>& packets);

    /**
     * @brief 构建参数化的模糊查询SQL语句
     * @param conditions 查询条件
     * @param params 输出参数，按 `?` 出现顺序收集需要绑定的值
     * @return 带 `?` 占位符的 SQL 查询语句
     */
    std::string buildFuzzyQuery(const std::map<std::string, std::string>& conditions,
                                std::vector<BindParam>&                   params);
};

#endif