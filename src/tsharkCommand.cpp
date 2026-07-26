#include "tsharkCommand.hpp"

#include <cstdio>
#include <cstdlib>
#include <set>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h> // 注册表读取 Wireshark 安装目录
#endif

#include "processUtil.hpp"

namespace TsharkCommand
{

namespace
{
// 判断给定路径是否为可打开的现有文件。tshark/editcap 都是普通可执行文件，
// 用 fopen("rb") 做存在性探测：跨平台、无额外依赖，能打开即存在且可读。
bool fileReadable(const std::string& path)
{
    if (path.empty())
        return false;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f)
    {
        std::fclose(f);
        return true;
    }
    return false;
}

// 平台相关的 PATH 分隔符、目录分隔符与可执行名后缀（POSIX 无 .exe 后缀）。
#if defined(_WIN32)
constexpr char kPathSep   = ';';
constexpr char kDirSep    = '\\';
const char*    kExeSuffix = ".exe";
#else
constexpr char kPathSep   = ':';
constexpr char kDirSep    = '/';
const char*    kExeSuffix = "";
#endif

// 在 PATH 环境变量列出的目录里查找可执行文件，返回首个命中的完整路径；找不到返回空串。
std::string searchInPath(const std::string& exeName)
{
    const char* pathEnv = std::getenv("PATH");
    if (!pathEnv)
        return "";
    std::istringstream stream{std::string(pathEnv)};
    std::string        dir;
    while (std::getline(stream, dir, kPathSep))
    {
        if (dir.empty())
            continue;
        std::string candidate = dir;
        if (candidate.back() != kDirSep)
            candidate += kDirSep;
        candidate += exeName;
        if (fileReadable(candidate))
            return candidate;
    }
    return "";
}

#if defined(_WIN32)
// 从注册表读 Wireshark 安装目录：安装程序会写 HKLM\SOFTWARE\Wireshark 的 InstallDir，
// 64 位机上也可能落在 WOW6432Node。读到目录后拼上 tshark.exe，存在才返回。仅 Windows 编译。
std::string tsharkFromRegistry()
{
    const char* subKeys[] = {"SOFTWARE\\Wireshark", "SOFTWARE\\WOW6432Node\\Wireshark"};
    for (const char* sub : subKeys)
    {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;
        char  buf[MAX_PATH] = {0};
        DWORD len           = sizeof(buf);
        DWORD type          = 0;
        LONG  rc = RegQueryValueExA(hKey, "InstallDir", nullptr, &type, (LPBYTE)buf, &len);
        RegCloseKey(hKey);
        if (rc == ERROR_SUCCESS && type == REG_SZ && buf[0] != 0)
        {
            std::string dir(buf);
            if (dir.back() != '\\')
                dir += '\\';
            std::string candidate = dir + "tshark.exe";
            if (fileReadable(candidate))
                return candidate;
        }
    }
    return "";
}
#endif

// 各平台常见安装目录里的 tshark 候选路径。
std::vector<std::string> commonTsharkCandidates()
{
#if defined(__APPLE__)
    return {"/Applications/Wireshark.app/Contents/MacOS/tshark"};
#elif defined(_WIN32)
    return {"C:\\Program Files\\Wireshark\\tshark.exe",
            "C:\\Program Files (x86)\\Wireshark\\tshark.exe"};
#else
    return {"/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
            "/snap/bin/tshark"};
#endif
}
} // namespace

std::string defaultTsharkPath()
{
#if defined(__APPLE__)
    return "/Applications/Wireshark.app/Contents/MacOS/tshark";
#elif defined(_WIN32)
    return "C:\\Program Files\\Wireshark\\tshark.exe";
#else
    return "/usr/bin/tshark";
#endif
}

std::string defaultEditcapPath()
{
#if defined(__APPLE__)
    return "/Applications/Wireshark.app/Contents/MacOS/editcap";
#elif defined(_WIN32)
    return "C:\\Program Files\\Wireshark\\editcap.exe";
#else
    return "/usr/bin/editcap";
#endif
}

std::vector<std::string> tsharkFieldArgs()
{
    // 字段顺序与 PacketParser::parseLine 的下标严格对应（0..15），改动需两处同步。
    return {
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };
}

std::vector<AdapterInfo> listNetworkAdapters(const std::string& tsharkPath)
{
    // 需要过滤掉的虚拟网卡
    std::set<std::string>    specialInterfaces = {"sshdump", "ciscodump", "udpdump", "randdpkt"};
    std::vector<AdapterInfo> interfaces;
    char                     buffer[256] = {0};
    std::string              result;

    std::vector<std::string> cmdArgs = {tsharkPath, "-D"};
    ProcessUtil::ProcHandle tsharkPid = ProcessUtil::kInvalidProc;
    FILE*                    rawPipe   = ProcessUtil::PopenEx(cmdArgs, &tsharkPid, "r");
    if (!rawPipe)
    {
        throw std::runtime_error("Failed to run tshark command!");
    }

    while (fgets(buffer, 256, rawPipe) != nullptr)
    {
        result += buffer;
    }
    // 1.\Device\NPF_{xxxx} (网卡描述)
    std::istringstream stream(result);
    std::string        line;
    int                index = 1;
    while (std::getline(stream, line))
    {
        size_t      startPos = line.find(". ") + 2;
        size_t      endPos   = line.find(" (", startPos);
        std::string interfaceName;
        std::string remark;
        if (endPos != std::string::npos) // 如果有描述
        {
            interfaceName = line.substr(startPos, endPos - startPos);
            remark        = line.substr(endPos + 2, line.find(")", endPos) - endPos - 2);
        }
        else
        {
            interfaceName = line.substr(startPos);
        }

        // 过滤掉需要排除的虚拟网卡
        if (specialInterfaces.find(interfaceName) != specialInterfaces.end())
        {
            continue;
        }
        AdapterInfo adapterInfo;
        adapterInfo.name   = interfaceName;
        adapterInfo.id     = index++;
        adapterInfo.remark = remark;

        interfaces.push_back(adapterInfo);
    }
    ProcessUtil::PcloseEx(rawPipe, tsharkPid);
    return interfaces;
}

std::string wiresharkDownloadUrl()
{
    return "https://www.wireshark.org/download.html";
}

bool tsharkAvailable(const std::string& path)
{
    return fileReadable(path);
}

std::string resolveTsharkPath()
{
    // 解析顺序（先命中先用）：
    //   1. 环境变量 EASYTSHARK_TSHARK：用户显式覆盖，最高优先级，无需重编译。
    //   2. 平台默认路径：多数标准安装命中于此。
    //   3. PATH：tshark 在环境变量里可直接找到（Linux/macOS 常见）。
    //   4. Windows 注册表 Wireshark InstallDir（含 WOW6432Node）。
    //   5. 常见安装目录兜底。
    // 全都没命中时回退平台默认路径，让后续报错信息仍指向一个合理位置。
    if (const char* env = std::getenv("EASYTSHARK_TSHARK"))
    {
        if (env[0] != 0 && fileReadable(env))
            return env;
    }

    std::string def = defaultTsharkPath();
    if (fileReadable(def))
        return def;

    std::string inPath = searchInPath(std::string("tshark") + kExeSuffix);
    if (!inPath.empty())
        return inPath;

#if defined(_WIN32)
    std::string reg = tsharkFromRegistry();
    if (!reg.empty())
        return reg;
#endif

    for (const std::string& c : commonTsharkCandidates())
    {
        if (fileReadable(c))
            return c;
    }

    return def; // 兜底：保持报错信息里出现一个合理的默认路径
}

std::string resolveEditcapPath()
{
    // editcap 与 tshark 同目录发行：直接从解析到的 tshark 路径推导，保证两者版本/位置一致。
    // 推导不出或该文件不存在时回退平台默认 editcap 路径。
    std::string tshark = resolveTsharkPath();
    std::size_t slash  = tshark.find_last_of("/\\");
    if (slash != std::string::npos)
    {
        std::string candidate = tshark.substr(0, slash + 1) + "editcap" + kExeSuffix;
        if (fileReadable(candidate))
            return candidate;
    }
    return defaultEditcapPath();
}

} // namespace TsharkCommand
