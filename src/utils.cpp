#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iconv.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "loguru/loguru.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "ip2region/xdb_search.h"
#include "tsharkDataType.hpp"
#include "utils.hpp"
#include <sqlite3.h>


std::unordered_map<std::string, std::string> translationMap = {
    {"General information", "常规信息"},
    {"Frame Number", "帧编号"},
    {"Captured Length", "捕获长度"},
    {"Captured Time", "捕获时间"},
    {"Section number", "节号"},
    {"Interface id", "接口 id"},
    {"Interface name", "接口名称"},
    {"Encapsulation type", "封装类型"},
    {"Arrival Time", "到达时间"},
    {"UTC Arrival Time", "UTC到达时间"},
    {"Epoch Arrival Time", "纪元到达时间"},
    {"Time shift for this packet", "该数据包的时间偏移"},
    {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
    {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
    {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
    {"Frame Number", "帧编号"},
    {"Frame Length", "帧长度"},
    {"Capture Length", "捕获长度"},
    {"Frame is marked", "帧标记"},
    {"Frame is ignored", "帧忽略"},
    {"Frame", "帧"},
    {"Protocols in frame", "帧中的协议"},
    {"Ethernet II", "以太网 II"},
    {"Destination", "目的地址"},
    {"Address Resolution Protocol", "ARP地址解析地址"},
    {"Address (resolved)", "地址（解析后）"},
    {"Type", "类型"},
    {"Stream index", "流索引"},
    {"Internet Protocol Version 4", "互联网协议版本 4"},
    {"Internet Protocol Version 6", "互联网协议版本 6"},
    {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
    {"Version", "版本"},
    {"Header Length", "头部长度"},
    {"Differentiated Services Field", "差分服务字段"},
    {"Total Length", "总长度"},
    {"Identification", "标识符"},
    {"Flags", "标志"},
    {"Time to Live", "生存时间"},
    {"Transmission Control Protocol", "TCP传输控制协议"},
    {"User Datagram Protocol", "UDP用户数据包协议"},
    {"Domain Name System", "DNS域名解析系统"},
    {"Header Checksum", "头部校验和"},
    {"Header checksum status", "校验和状态"},
    {"Source Address", "源地址"},
    {"Destination Address", "目的地址"},
    {"Source Port", "源端口"},
    {"Destination Port", "目的端口"},
    {"Next Sequence Number", "下一个序列号"},
    {"Sequence Number", "序列号"},
    {"Acknowledgment Number", "确认号"},
    {"Acknowledgment number", "确认号"},
    {"TCP Segment Len", "TCP段长度"},
    {"Conversation completeness", "会话完整性"},
    {"Window size scaling factor", "窗口缩放因子"},
    {"Calculated window size", "计算窗口大小"},
    {"Window", "窗口"},
    {"Urgent Pointer", "紧急指针"},
    {"Checksum:", "校验和:"},
    {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
    {"Kind", "种类"},
    {"MSS Value", "MSS值"},
    {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
    {"Shift count", "移位计数"},
    {"Multiplier", "倍数"},
    {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
    {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
    {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
    {"Options", "选项"},
    {"TCP Option - No-Operation", "TCP选项 - 无操作"},
    {"Timestamps", "时间戳"},
    {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
    {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
    {"Protocol:", "协议:"},
    {"Source:", "源地址:"},
    {"Length:", "长度:"},
    {"Checksum status", "校验和状态"},
    {"Checksum Status", "校验和状态"},
    {"TCP payload", "TCP载荷"},
    {"UDP payload", "UDP载荷"},
    {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
    {"Transport Layer Security", "传输层安全协议TLS"}};

std::shared_ptr<xdb_search_t> IP2RegionUtil::xdbPtr;

std::string IP2RegionUtil::getIpLocation(const std::string& ip)
{
    // 取一份局部引用，避免与 init() 的发布竞争；未初始化（或初始化失败）直接返回空。
    std::shared_ptr<xdb_search_t> xdb = xdbPtr;
    if (!xdb)
    {
        return "";
    }

    // if is IPv6, return empty string
    if (ip.size() > 15)
    {
        return "";
    }

    std::string location = xdb->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos)
    {
        return parseLocation(location);
    }
    else
    {
        return "";
    }
}

std::string IP2RegionUtil::parseLocation(const std::string& input)
{
    std::vector<std::string> tokens;
    std::string              token;
    std::stringstream        ss(input);

    if (input.find("内网") != std::string::npos)
    {
        return "内网";
    }

    while (std::getline(ss, token, '|'))
    {
        tokens.push_back(token);
    }

    if (tokens.size() >= 4)
    {
        std::string result;
        if (tokens[0].compare("0") != 0)
        {
            result.append(tokens[0]);
        }
        if (tokens[2].compare("0") != 0)
        {
            result.append("-" + tokens[2]);
        }
        if (tokens[3].compare("0") != 0)
        {
            result.append("-" + tokens[3]);
        }

        return result;
    }
    else
    {
        return input;
    }
}

bool IP2RegionUtil::init(const std::string& xdbFilePath)
{
    // 只初始化一次：xdb 文件较大，且离线分析线程与抓包线程都会调用 init，
    // 用 call_once 保证仅加载一次，既避免每次分析重复加载，也消除并发重设
    // 静态 xdbPtr 的数据竞争。call_once 完成对所有调用线程建立 happens-before，
    // 之后各线程读 xdbPtr 都是安全的。加载失败时把 xdbPtr 置空并返回 false，
    // 绝不让异常沿离线分析路径冒泡到 UI 线程。
    static std::once_flag initFlag;
    std::call_once(initFlag,
                   [&xdbFilePath]()
                   {
                       try
                       {
                           std::shared_ptr<xdb_search_t> p =
                               std::make_shared<xdb_search_t>(xdbFilePath);
                           p->init_content();
                           xdbPtr = p;
                       }
                       catch (...)
                       {
                           xdbPtr = nullptr;
                       }
                   });
    return xdbPtr != nullptr;
}

std::string CommonUtil::UTF8ToANSIString(const std::string& utf8Str)
{
    if (utf8Str.empty())
        return "";

    iconv_t cd = iconv_open("ANSI", "UTF-8");
    if (cd == (iconv_t)-1)
        return "";

    size_t            inBytesLeft  = utf8Str.size();
    size_t            outBytesLeft = utf8Str.size() * 2;
    std::vector<char> outBuf(outBytesLeft);
    char*             inBuf     = const_cast<char*>(utf8Str.c_str());
    char*             outBufPtr = outBuf.data();

    if (iconv(cd, &inBuf, &inBytesLeft, &outBufPtr, &outBytesLeft) == (size_t)-1)
    {
        iconv_close(cd);
        return "";
    }

    iconv_close(cd);
    return std::string(outBuf.begin(), outBuf.begin() + (outBuf.size() - outBytesLeft));
}

std::string CommonUtil::get_timestamp()
{
    auto now      = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time), "%Y%m%d%H%M%S");
    ss << std::setfill('0') << std::setw(3) << ms.count();

    return ss.str();
}


namespace
{
// 前缀树（trie）：把翻译词典按字符逐层展开成一棵树，用于在 O(待匹配串长度) 内
// 找出 showname 的“最长匹配前缀”。
//
// 原实现对约 80 条词典逐条做 showname.find(key) == 0：
//   - find 会在整串中查找 key，实为 O(串长 × 词典大小) 的重复扫描；
//   - 遍历的是 unordered_map，命中顺序不确定，多个前缀都能匹配时结果不稳定。
// 改用 trie 后：只需顺着 showname 走一遍，且总是选中最长（最具体）的前缀，结果确定。
class TranslationTrie
{
public:
    void insert(const std::string& key, const std::string& value)
    {
        Node* cur = &root_;
        for (char ch : key)
        {
            std::unique_ptr<Node>& child = cur->children[ch];
            if (!child)
            {
                child.reset(new Node());
            }
            cur = child.get();
        }
        cur->hasValue = true;
        cur->value    = value;
    }

    // 命中时返回最长匹配前缀的译文，并通过 matchedLen 返回该前缀长度；无匹配返回 nullptr
    const std::string* matchLongestPrefix(const std::string& text, size_t& matchedLen) const
    {
        const Node*        cur  = &root_;
        const std::string* best = nullptr;
        matchedLen              = 0;
        for (size_t i = 0; i < text.size(); ++i)
        {
            auto it = cur->children.find(text[i]);
            if (it == cur->children.end())
            {
                break; // 无法继续沿树下探，停止
            }
            cur = it->second.get();
            if (cur->hasValue)
            {
                best       = &cur->value; // 记录当前更长的匹配，继续尝试更长的
                matchedLen = i + 1;
            }
        }
        return best;
    }

private:
    struct Node
    {
        std::map<char, std::unique_ptr<Node>> children;
        bool                                  hasValue = false;
        std::string                           value;
    };
    Node root_;
};

// 由 translationMap 惰性构建一次（C++11 保证 static 局部变量初始化线程安全），之后只读复用。
const TranslationTrie& translationTrie()
{
    static const TranslationTrie trie = [] {
        TranslationTrie t;
        for (const auto& pair : translationMap)
        {
            t.insert(pair.first, pair.second);
        }
        return t;
    }();
    return trie;
}

// 对 showname 做最长前缀翻译；命中则替换前缀并返回 true
bool translatePrefix(std::string& showname)
{
    size_t             matchedLen  = 0;
    const std::string* translation = translationTrie().matchLongestPrefix(showname, matchedLen);
    if (translation)
    {
        showname.replace(0, matchedLen, *translation);
        return true;
    }
    return false;
}
} // namespace

void CommonUtil::translateShowNameFields(rapidjson::Value&                   value,
                                         rapidjson::Document::AllocatorType& allocator)
{
    if (value.IsObject())
    {
        if (value.HasMember("showname") && value["showname"].IsString())
        {
            std::string showname = value["showname"].GetString();
            if (translatePrefix(showname))
            {
                value["showname"].SetString(showname.c_str(), allocator);
            }
        }
        else if (value.HasMember("show") && value["show"].IsString())
        {
            std::string showname = value["show"].GetString();
            if (translatePrefix(showname))
            {
                value["show"].SetString(showname.c_str(), allocator);
            }
        }

        // 有 "field" 字段，递归处理
        if (value.HasMember("field") && value["field"].IsArray())
        {
            rapidjson::Value& fieldArray = value["field"];
            for (auto& field : fieldArray.GetArray())
            {
                translateShowNameFields(field, allocator);
            }
        }
    }
    else if (value.IsArray())
    {
        for (auto& item : value.GetArray())
        {
            translateShowNameFields(item, allocator);
        }
    }
}

SQLiteUtil::SQLiteUtil(const std::string& dbname)
{
    // 打开数据库连接
    int rc = sqlite3_open(dbname.c_str(), &db);
    if (rc != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        throw std::runtime_error("Failed to open database");
    }
}

SQLiteUtil::~SQLiteUtil()
{
    if (db)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool SQLiteUtil::createPacketTable()
{
    // 检查表是否存在，若不存在则创建
    std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS t_packets (
            frame_number INTEGER PRIMARY KEY,
            time REAL,
            cap_len INTEGER,
            len INTEGER,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            src_location TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_location TEXT,
            dst_port INTEGER,
            protocol TEXT,
            info TEXT,
            file_offset INTEGER
        );
    )";

    if (db == nullptr)
    {
        LOG_F(ERROR, "Database connection is not initialized");
        return false;
    }

    if (sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to create table t_packets: %s", sqlite3_errmsg(db));
        return false;
    }

    return true;
}

bool SQLiteUtil::insertPacket(std::vector<std::shared_ptr<Packet>>& packets)
{
    // 实现插入数据的逻辑
    // 开启事务
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    // SQL 插入语句
    std::string insertSQL = R"(
        INSERT INTO t_packets (
            frame_number, time, cap_len, len, src_mac, dst_mac, src_ip, src_location, src_port,
            dst_ip, dst_location, dst_port, protocol, info, file_offset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertSQL.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare insert statement: %s", sqlite3_errmsg(db));
        return false;
    }

    // 遍历列表并插入数据
    bool hasError = false;
    for (const auto& packet : packets)
    {
        sqlite3_bind_int(stmt, 1, packet->frame_number);
        sqlite3_bind_double(stmt, 2, packet->time);
        sqlite3_bind_int(stmt, 3, packet->cap_len);
        sqlite3_bind_int(stmt, 4, packet->len);
        sqlite3_bind_text(stmt, 5, packet->src_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, packet->dst_mac.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, packet->src_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, packet->src_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 9, packet->src_port);
        sqlite3_bind_text(stmt, 10, packet->dst_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, packet->dst_location.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 12, packet->dst_port);
        sqlite3_bind_text(stmt, 13, packet->protocol.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 14, packet->info.c_str(), -1, SQLITE_STATIC);
        // file_offset 为累计偏移，可超过 4GB，用 64 位绑定避免截断
        sqlite3_bind_int64(stmt, 15, static_cast<sqlite3_int64>(packet->file_offset));

        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            LOG_F(ERROR, "Failed to execute insert statement: %s", sqlite3_errmsg(db));
            hasError = true;
            break;
        }

        sqlite3_reset(stmt); // 重置语句以便下一次绑定
    }

    // 释放语句
    sqlite3_finalize(stmt);

    if (!hasError)
    {
        // 结束事务
        if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to commit transaction: %s", sqlite3_errmsg(db));
            hasError = true;
        }
    }
    else
    {
        // 如果有错误，回滚事务
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }

    return !hasError;
}

namespace
{
// sqlite3_column_text 对 NULL 列返回 nullptr，直接拿来构造 std::string 是未定义行为。
// 统一经此 helper 读取文本列：NULL 一律按空串处理。
std::string columnText(sqlite3_stmt* stmt, int col)
{
    const unsigned char* text = sqlite3_column_text(stmt, col);
    return text ? reinterpret_cast<const char*>(text) : std::string();
}

// 把 t_packets 的一行读进 Packet：queryPacket / queryPackets 共用同一列序，
// 抽出来消除两处几乎重复的读列逻辑，并统一走 NULL 安全的 columnText。
std::shared_ptr<Packet> rowToPacket(sqlite3_stmt* stmt)
{
    std::shared_ptr<Packet> packet = std::make_shared<Packet>();
    packet->frame_number           = sqlite3_column_int(stmt, 0);
    packet->time                   = sqlite3_column_double(stmt, 1);
    packet->cap_len                = sqlite3_column_int(stmt, 2);
    packet->len                    = sqlite3_column_int(stmt, 3);
    packet->src_mac                = columnText(stmt, 4);
    packet->dst_mac                = columnText(stmt, 5);
    packet->src_ip                 = columnText(stmt, 6);
    packet->src_location           = columnText(stmt, 7);
    packet->src_port               = sqlite3_column_int(stmt, 8);
    packet->dst_ip                 = columnText(stmt, 9);
    packet->dst_location           = columnText(stmt, 10);
    packet->dst_port               = sqlite3_column_int(stmt, 11);
    packet->protocol               = columnText(stmt, 12);
    packet->info                   = columnText(stmt, 13);
    // file_offset 为累计偏移，可超过 4GB，用 64 位列读取
    packet->file_offset = static_cast<uint64_t>(sqlite3_column_int64(stmt, 14));
    return packet;
}
} // namespace

bool SQLiteUtil::queryPacket(std::vector<std::shared_ptr<Packet>>& packetList)
{
    sqlite3_stmt* stmt = nullptr;
    std::string   sql  = "select * from t_packets";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare statement: ");
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        packetList.push_back(rowToPacket(stmt));
    }

    sqlite3_finalize(stmt);

    return true;
}

std::string SQLiteUtil::buildFuzzyQuery(const std::map<std::string, std::string>& conditions,
                                        std::vector<BindParam>&                   params)
{
    params.clear();
    std::string sql = "SELECT * FROM t_packets WHERE 1=1";

    for (const auto& condition : conditions)
    {
        if (condition.first == "mac_address")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            // 用 ? 占位、两个源/目的字段各绑定一次，用户输入不进入 SQL 文本
            sql += " AND (src_mac LIKE ? OR dst_mac LIKE ?)";
            params.push_back({BindParam::Text, pattern, 0});
            params.push_back({BindParam::Text, pattern, 0});
        }
        else if (condition.first == "ip_address")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)";
            params.push_back({BindParam::Text, pattern, 0});
            params.push_back({BindParam::Text, pattern, 0});
        }
        else if (condition.first == "port")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            // 纯数字则按整数精确匹配，否则按文本模糊匹配（避免 stoi 抛异常）
            bool numeric = !pattern.empty() &&
                           pattern.find('%') == std::string::npos &&
                           pattern.find_first_not_of("0123456789") == std::string::npos;
            if (numeric)
            {
                int portValue = std::stoi(pattern);
                sql += " AND (src_port = ? OR dst_port = ?)";
                params.push_back({BindParam::Int, "", portValue});
                params.push_back({BindParam::Int, "", portValue});
            }
            else
            {
                sql += " AND (CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)";
                params.push_back({BindParam::Text, pattern, 0});
                params.push_back({BindParam::Text, pattern, 0});
            }
        }
        else if (condition.first == "location")
        {
            std::string pattern = condition.second;
            std::replace(pattern.begin(), pattern.end(), '*', '%');
            // 地理位置一律做任意位置的子串匹配：无条件在前后各加一个 %。
            // 即使用户输入本身已含 *（如 "湖南*长沙"→"湖南%长沙"），也要补成
            // "%湖南%长沙%" 才能匹配 "中国-湖南省-长沙市"；多余的 %% 等价单个 %，无害。
            pattern = "%" + pattern + "%";
            sql += " AND (src_location LIKE ? OR dst_location LIKE ?)";
            params.push_back({BindParam::Text, pattern, 0});
            params.push_back({BindParam::Text, pattern, 0});
        }
    }

    // sql += " ORDER BY frame_number ASC LIMIT 1000"; // 限制返回结果数量
    return sql;
}

std::string SQLiteUtil::packetsToJson(std::vector<std::shared_ptr<Packet>>& packets)
{
    rapidjson::Document document;
    document.SetObject();
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

    document.AddMember("total", rapidjson::Value((int)packets.size()), allocator);

    rapidjson::Value packetsArray(rapidjson::kArrayType);
    packetsArray.Reserve(static_cast<rapidjson::SizeType>(packets.size()), allocator);

    for (const auto& packet : packets)
    {
        rapidjson::Value packetObj(rapidjson::kObjectType);

        // 字符串字段使用StringRef引用Packet中已有的内存，避免把每个字符串再拷贝进allocator。
        // packet在本函数序列化完成前始终存活，不会悬垂。
        packetObj.AddMember("frame_number", rapidjson::Value(packet->frame_number), allocator);
        packetObj.AddMember("time", rapidjson::Value(packet->time), allocator);
        packetObj.AddMember("cap_len", rapidjson::Value(packet->cap_len), allocator);
        packetObj.AddMember("len", rapidjson::Value(packet->len), allocator);
        packetObj.AddMember("src_mac", rapidjson::StringRef(packet->src_mac.c_str()), allocator);
        packetObj.AddMember("dst_mac", rapidjson::StringRef(packet->dst_mac.c_str()), allocator);
        packetObj.AddMember("src_ip", rapidjson::StringRef(packet->src_ip.c_str()), allocator);
        packetObj.AddMember("src_location", rapidjson::StringRef(packet->src_location.c_str()),
                            allocator);
        packetObj.AddMember("src_port", rapidjson::Value(packet->src_port), allocator);
        packetObj.AddMember("dst_ip", rapidjson::StringRef(packet->dst_ip.c_str()), allocator);
        packetObj.AddMember("dst_location", rapidjson::StringRef(packet->dst_location.c_str()),
                            allocator);
        packetObj.AddMember("dst_port", rapidjson::Value(packet->dst_port), allocator);
        packetObj.AddMember("protocol", rapidjson::StringRef(packet->protocol.c_str()), allocator);
        packetObj.AddMember("info", rapidjson::StringRef(packet->info.c_str()), allocator);
        packetObj.AddMember("file_offset",
                            rapidjson::Value(static_cast<uint64_t>(packet->file_offset)), allocator);

        packetsArray.PushBack(packetObj, allocator);
    }

    document.AddMember("packets", packetsArray, allocator);

    rapidjson::StringBuffer                    buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    document.Accept(writer);

    return buffer.GetString();
}

bool SQLiteUtil::queryPackets(const std::map<std::string, std::string>& conditions,
                              std::string&                              jsonResult)
{
    std::vector<BindParam> params;
    std::string            sql = buildFuzzyQuery(conditions, params);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        LOG_F(ERROR, "Failed to prepare query statement: %s", sqlite3_errmsg(db));
        return false;
    }

    // 按顺序绑定参数（sqlite3 占位符索引从 1 开始）
    for (size_t i = 0; i < params.size(); ++i)
    {
        int idx = static_cast<int>(i) + 1;
        int rc;
        if (params[i].type == BindParam::Int)
        {
            rc = sqlite3_bind_int(stmt, idx, params[i].intValue);
        }
        else
        {
            // SQLITE_TRANSIENT：让 sqlite 复制字符串，params 生命周期结束后也安全
            rc = sqlite3_bind_text(stmt, idx, params[i].text.c_str(), -1, SQLITE_TRANSIENT);
        }
        if (rc != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to bind query parameter %d: %s", idx, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return false;
        }
    }

    std::vector<std::shared_ptr<Packet>> packets;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        packets.push_back(rowToPacket(stmt));
    }

    sqlite3_finalize(stmt);

    jsonResult = packetsToJson(packets);

    return true;
}

/**
 * @brief 将查询结果保存到JSON文件
 *
 * @param jsonResult JSON格式的查询结果字符串
 * @param filePath 保存文件的路径
 * @return true 保存成功
 * @return false 保存失败
 *
 * @note 如果目标文件已存在，将会被覆盖
 */
bool SQLiteUtil::saveQueryResultToFile(const std::string& jsonResult, const std::string& filePath)
{
    try
    {
        std::ofstream jsonFileStream(filePath);
        if (!jsonFileStream.is_open())
        {
            LOG_F(ERROR, "无法打开文件进行写入: %s", filePath.c_str());
            return false;
        }

        jsonFileStream << jsonResult;
        jsonFileStream.flush();
        if (jsonFileStream.fail())
        {
            LOG_F(ERROR, "写入文件时发生错误: %s", filePath.c_str());
            jsonFileStream.close();
            return false;
        }

        jsonFileStream.close();

        LOG_F(INFO, "查询结果已成功保存到文件: %s", filePath.c_str());
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_F(ERROR, "保存查询结果时发生错误: %s", e.what());
        return false;
    }
}