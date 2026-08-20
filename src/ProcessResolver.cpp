#include "ProcessResolver.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "processUtil.hpp"
#include "tsharkDataType.hpp"

#if defined(__APPLE__) || defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#endif

namespace
{
constexpr auto kRefreshInterval = std::chrono::seconds(2);

inline uint32_t makeKey(bool isUdp, int port)
{
    return (isUdp ? (1u << 16) : 0u) | static_cast<uint32_t>(port);
}
} // namespace

void ProcessResolver::annotate(Packet& packet)
{
    refreshIfStale();

    bool isUdp = (packet.transport == "UDP");
    std::lock_guard<std::mutex> lk(mutex_);
    if (table_.empty())
        return;

    auto it = table_.find(makeKey(isUdp, packet.src_port));
    if (it == table_.end())
        it = table_.find(makeKey(isUdp, packet.dst_port));
    if (it == table_.end())
        return;

    packet.proc_name = it->second.first;
    packet.proc_pid  = it->second.second;
}

void ProcessResolver::refreshIfStale()
{
    std::lock_guard<std::mutex> lk(mutex_);
    auto now = std::chrono::steady_clock::now();
    if (lastRefresh_.time_since_epoch().count() != 0 && now - lastRefresh_ < kRefreshInterval)
        return;
    lastRefresh_ = now;
#if defined(__APPLE__)
    refreshMacOS();
#elif defined(__linux__)
    refreshLinux();
#endif
}

#if defined(__APPLE__)
// lsof -F 字段模式：每行以一个字母开头标识字段，process 级字段（p/c）后跟若干 file 级字段（P/n）。
// 用当前累计的 pid/command/protocol 状态机解析，命中一条 n（地址）就落一条 socket->进程 记录。
void ProcessResolver::refreshMacOS()
{
    ProcessUtil::ProcHandle proc;
    FILE* pipe = ProcessUtil::PopenEx({"lsof", "-i", "-n", "-P", "-F", "pcnP"}, &proc, "r");
    if (!pipe)
        return;

    std::unordered_map<uint32_t, std::pair<std::string, int>> fresh;
    int         curPid = 0;
    std::string curCmd;
    std::string curProto;
    char        line[512];
    while (fgets(line, sizeof(line), pipe) != nullptr)
    {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n == 0)
            continue;
        const char* val = line + 1;
        switch (line[0])
        {
        case 'p':
            curPid = atoi(val);
            break;
        case 'c':
            curCmd = val;
            break;
        case 'P':
            curProto = val;
            break;
        case 'n':
        {
            std::string addr  = val;
            size_t      arrow = addr.find("->");
            std::string local = (arrow == std::string::npos) ? addr : addr.substr(0, arrow);
            size_t      colon = local.find_last_of(':');
            if (colon == std::string::npos || curPid <= 0)
                break;
            int port = atoi(local.c_str() + colon + 1);
            if (port <= 0)
                break;
            fresh[makeKey(curProto == "UDP", port)] = std::make_pair(curCmd, curPid);
            break;
        }
        default:
            break;
        }
    }
    ProcessUtil::PcloseEx(pipe, proc);
    table_.swap(fresh);
}
#else
void ProcessResolver::refreshMacOS() {}
#endif

#if defined(__linux__)
namespace
{
// 解析 /proc/net/{tcp,udp}[6] 一张表，把 inode 映射到 (isUdp, 本地端口)。
// 格式：sl local_address rem_address st tx:rx tr:tm uid timeout inode ...
//       local_address 形如 "0100007F:1F90"（十六进制 ip:port）。
void parseProcNet(const char* path, bool isUdp,
                   std::unordered_map<unsigned long, std::pair<bool, int>>& inodeToPort)
{
    std::ifstream in(path);
    if (!in.is_open())
        return;
    std::string line;
    std::getline(in, line); // 表头
    while (std::getline(in, line))
    {
        std::istringstream iss(line);
        std::string        sl, localAddr, remAddr, st, txrx, trtm, retr, uid, timeout, inode;
        if (!(iss >> sl >> localAddr >> remAddr >> st >> txrx >> trtm >> retr >> uid >> timeout >>
              inode))
            continue;
        size_t colon = localAddr.find(':');
        if (colon == std::string::npos)
            continue;
        int         port  = static_cast<int>(strtol(localAddr.c_str() + colon + 1, nullptr, 16));
        unsigned long ino = strtoul(inode.c_str(), nullptr, 10);
        if (port > 0 && ino > 0)
            inodeToPort[ino] = std::make_pair(isUdp, port);
    }
}
} // namespace

// 无 <filesystem>（C++11）：全程走 POSIX opendir/readdir/readlink，与 processUtil.cpp 一致的手写风格。
void ProcessResolver::refreshLinux()
{
    std::unordered_map<unsigned long, std::pair<bool, int>> inodeToPort;
    parseProcNet("/proc/net/tcp", false, inodeToPort);
    parseProcNet("/proc/net/tcp6", false, inodeToPort);
    parseProcNet("/proc/net/udp", true, inodeToPort);
    parseProcNet("/proc/net/udp6", true, inodeToPort);
    if (inodeToPort.empty())
        return;

    std::unordered_map<uint32_t, std::pair<std::string, int>> fresh;

    DIR* procDir = opendir("/proc");
    if (!procDir)
        return;
    struct dirent* pidEnt;
    while ((pidEnt = readdir(procDir)) != nullptr)
    {
        const char* pidStr = pidEnt->d_name;
        if (pidStr[0] < '0' || pidStr[0] > '9')
            continue;
        int pid = atoi(pidStr);

        std::string fdDirPath = std::string("/proc/") + pidStr + "/fd";
        DIR*        fdDir     = opendir(fdDirPath.c_str());
        if (!fdDir)
            continue; // 无权限访问其他用户进程的 fd 目录，跳过即可

        std::string procName;
        struct dirent* fdEnt;
        while ((fdEnt = readdir(fdDir)) != nullptr)
        {
            if (fdEnt->d_name[0] == '.')
                continue;
            std::string fdPath = fdDirPath + "/" + fdEnt->d_name;
            char        link[64];
            ssize_t     len = readlink(fdPath.c_str(), link, sizeof(link) - 1);
            if (len <= 0)
                continue;
            link[len] = '\0';
            unsigned long inode = 0;
            if (sscanf(link, "socket:[%lu]", &inode) != 1)
                continue;
            auto it = inodeToPort.find(inode);
            if (it == inodeToPort.end())
                continue;
            if (procName.empty())
            {
                std::ifstream commFile(std::string("/proc/") + pidStr + "/comm");
                std::getline(commFile, procName);
            }
            fresh[makeKey(it->second.first, it->second.second)] = std::make_pair(procName, pid);
        }
        closedir(fdDir);
    }
    closedir(procDir);
    table_.swap(fresh);
}
#else
void ProcessResolver::refreshLinux() {}
#endif
