#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include "AnalysisSession.hpp"
#include "loguru/loguru.hpp"
#include "tsharkCommand.hpp"
#include "utils.hpp"

#if defined(_WIN32)
#include <windows.h> // SetConsoleOutputCP / SetConsoleCP
#endif

// main 只负责命令行交互与装配：读取用户输入、调用 AnalysisSession 门面，
// 所有抓包 / 解析 / 入库 / 查询逻辑都在门面内部，UI（此处是 CLI）不碰实现细节。

namespace
{
// 交互式采集查询条件（直接回车表示不使用该条件）
std::map<std::string, std::string> readQueryConditions()
{
    std::string macAddr, ipAddr, port, location;
    std::cout << "\n请输入查询条件（直接回车表示不使用该条件）：" << std::endl;

    std::cout << "MAC地址（支持模糊匹配，如: 00:11:22:*）: ";
    std::getline(std::cin, macAddr);
    std::cout << "IP地址（支持模糊匹配，如: 192.168.*）: ";
    std::getline(std::cin, ipAddr);
    std::cout << "端口（支持模糊匹配，如: 80*）: ";
    std::getline(std::cin, port);
    std::cout << "归属地（支持模糊匹配，如: 深圳*）: ";
    std::getline(std::cin, location);

    std::map<std::string, std::string> conditions;
    if (!macAddr.empty())
        conditions["mac_address"] = macAddr;
    if (!ipAddr.empty())
        conditions["ip_address"] = ipAddr;
    if (!port.empty())
        conditions["port"] = port;
    if (!location.empty())
        conditions["location"] = location;
    return conditions;
}

void runQueryLoop(AnalysisSession& session)
{
    char queryChoice = 0;
    std::cout << "是否要查询数据包？(y/n): ";
    std::cin >> queryChoice;
    if (queryChoice != 'y' && queryChoice != 'Y')
        return;
    std::cin.ignore(); // 丢弃行尾换行，后续用 getline 读整行

    while (true)
    {
        std::map<std::string, std::string> conditions = readQueryConditions();
        if (conditions.empty())
        {
            std::cout << "未指定任何查询条件！" << std::endl;
        }
        else
        {
            std::string jsonResult;
            if (session.query(conditions, jsonResult))
            {
                std::cout << "\n查询结果：\n" << jsonResult << std::endl;
            }
            else
            {
                std::cerr << "查询失败！" << std::endl;
            }
        }

        char continueQuery = 0;
        std::cout << "\n是否继续查询？(y/n): ";
        std::cin >> continueQuery;
        std::cin.ignore();
        if (continueQuery != 'y' && continueQuery != 'Y')
            break;
    }
}
} // namespace

int main(int argc, char* argv[])
{
#if defined(_WIN32)
    // 源码里的中文提示均为 UTF-8 字节；Windows 控制台默认按本地代码页(GBK/936)解码，
    // 会把 UTF-8 中文显示成乱码。把控制台输入/输出代码页都切到 UTF-8 即可正常显示。
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    std::string ts               = CommonUtil::get_timestamp();
    std::string capture_log_name = "logs/capture_" + ts + ".log";
    loguru::init(argc, argv);
    loguru::add_file(capture_log_name.c_str(), loguru::Append, loguru::Verbosity_MAX);

    // 自动定位 tshark：环境变量 EASYTSHARK_TSHARK → 默认路径 → PATH →（Win）注册表 → 常见目录。
    std::string     tsharkPath = TsharkCommand::resolveTsharkPath();
    AnalysisSession session(tsharkPath, "data");

    // 未检测到 tshark 时给出友好引导（本工具依赖 Wireshark 的 tshark 做抓包/解析）。
    // 这里只提示不退出：仍进入菜单，真正用到 tshark 的操作会各自报错。
    if (!TsharkCommand::tsharkAvailable(tsharkPath))
    {
        std::cerr << "警告：未检测到 tshark（已尝试路径: " << tsharkPath << "）。\n"
                  << "本工具依赖 Wireshark 提供的 tshark。请先安装 Wireshark："
                  << TsharkCommand::wiresharkDownloadUrl() << "\n"
                  << "若已安装在非默认位置，可设置环境变量 EASYTSHARK_TSHARK 指向 tshark"
#if defined(_WIN32)
                     ".exe"
#endif
                  << " 的完整路径。\n"
                  << std::endl;
    }

    int mode = 0;
    std::cout << "请选择模式：\n1. 实时抓包\n2. 离线分析\n请输入选择 (1或2): ";
    std::cin >> mode;

    if (mode == 1)
    {
        std::vector<AdapterInfo> adapters;
        try
        {
            adapters = session.listAdapters();
        }
        catch (const std::exception& e)
        {
            std::cerr << "获取网卡列表失败：" << e.what() << "\n"
                      << "请确认已安装 Wireshark（" << TsharkCommand::wiresharkDownloadUrl()
                      << "）；若装在非默认位置，可用环境变量 EASYTSHARK_TSHARK 指定 tshark 路径。"
                      << std::endl;
            return 1;
        }
        std::cout << "可用网卡列表：" << std::endl;
        for (const auto& adapter : adapters)
        {
            std::cout << adapter.id << ": " << adapter.name << " (" << adapter.remark << ")"
                      << std::endl;
        }

        std::string adapterName;
        std::cout << "请输入要监控的网卡名称: ";
        std::cin >> adapterName;

        int captureSeconds = 0;
        std::cout << "请输入抓包时间(秒): ";
        std::cin >> captureSeconds;

        std::cout << "开始抓包，持续 " << captureSeconds << " 秒..." << std::endl;
        if (!session.startLiveCapture(adapterName))
        {
            std::cerr << "启动抓包失败" << std::endl;
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::seconds(captureSeconds));

        if (!session.stopLiveCapture())
        {
            std::cerr << "停止抓包或分析失败" << std::endl;
            return 1;
        }
        std::cout << "抓包已完成并解析，共 " << session.packetCount() << " 个数据包" << std::endl;
    }
    else if (mode == 2)
    {
        std::string   srcPath;
        std::ifstream existingFile(session.pcapPath());
        if (existingFile.good())
        {
            existingFile.close();
            std::cout << "发现已存在的抓包文件: " << session.pcapPath() << std::endl;
            std::cout << "是否使用此文件？(y/n): ";
            char choice = 0;
            std::cin >> choice;
            if (choice != 'y' && choice != 'Y')
            {
                std::cout << "请输入新的PCAP文件路径: ";
                std::cin >> srcPath;
            }
        }
        else
        {
            std::cout << "请输入PCAP文件路径: ";
            std::cin >> srcPath;
        }

        if (!session.loadPcap(srcPath))
        {
            std::cerr << "载入/解析 PCAP 文件失败" << std::endl;
            return 1;
        }
        std::cout << "成功解析 PCAP 文件，共 " << session.packetCount() << " 个数据包" << std::endl;
    }
    else
    {
        std::cerr << "无效的选择，程序退出" << std::endl;
        return 1;
    }

    // 导出逐层展开的 PDML JSON（供详情浏览 / 离线保存）
    if (session.exportDetailJson("data/packets.xml", "data/packets.json"))
    {
        std::cout << "已导出详细 JSON: data/packets.json" << std::endl;
    }

    runQueryLoop(session);
    return 0;
}
