#include "tsharkCommand.hpp"

#include <set>
#include <sstream>
#include <stdexcept>

#include "processUtil.hpp"

namespace TsharkCommand
{

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
    pid_t tsharkPid = -1;
    FILE* rawPipe = ProcessUtil::PopenEx(cmdArgs, &tsharkPid, "r");
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

        // 滤掉特殊网卡
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

} // namespace TsharkCommand
