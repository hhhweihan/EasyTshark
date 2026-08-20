#include "NativeCapture.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

#include "NativePacketParser.hpp"
#include "loguru/loguru.hpp"

#if defined(EASYTSHARK_HAVE_LIBPCAP)
#include <pcap.h>
#endif

namespace
{
void writePcapGlobalHeader(FILE* f)
{
    // magic d4c3b2a1 + 2.4 + thiszone 0 + sigfigs 0 + snaplen 65535 + network 1(Ethernet)
    unsigned char hdr[24] = {0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    std::fwrite(hdr, 1, sizeof(hdr), f);
}

void writePcapRecord(FILE* f, uint32_t tsSec, uint32_t tsUsec, const unsigned char* data,
                     uint32_t caplen, uint32_t origlen)
{
    unsigned char rh[16];
    rh[0]  = tsSec & 0xff;
    rh[1]  = (tsSec >> 8) & 0xff;
    rh[2]  = (tsSec >> 16) & 0xff;
    rh[3]  = (tsSec >> 24) & 0xff;
    rh[4]  = tsUsec & 0xff;
    rh[5]  = (tsUsec >> 8) & 0xff;
    rh[6]  = (tsUsec >> 16) & 0xff;
    rh[7]  = (tsUsec >> 24) & 0xff;
    rh[8]  = caplen & 0xff;
    rh[9]  = (caplen >> 8) & 0xff;
    rh[10] = (caplen >> 16) & 0xff;
    rh[11] = (caplen >> 24) & 0xff;
    rh[12] = origlen & 0xff;
    rh[13] = (origlen >> 8) & 0xff;
    rh[14] = (origlen >> 16) & 0xff;
    rh[15] = (origlen >> 24) & 0xff;
    std::fwrite(rh, 1, sizeof(rh), f);
    std::fwrite(data, 1, caplen, f);
}
} // namespace

NativeCapture::NativeCapture() = default;

NativeCapture::~NativeCapture()
{
    if (thread_)
    {
        stopFlag_ = true;
        if (thread_->joinable())
            thread_->join();
        thread_.reset();
        running_ = false;
    }
}

bool NativeCapture::startCapture(const std::string& adapterName, PacketCallback onPacket,
                                 const std::string& captureFile, int durationSeconds)
{
    if (running_)
    {
        LOG_F(WARNING, "NativeCapture: 已在抓包中");
        return false;
    }
    stopFlag_ = false;
    running_  = true;
    thread_   = std::make_shared<std::thread>(&NativeCapture::workThread, this, adapterName,
                                              onPacket, captureFile, durationSeconds);
    return true;
}

bool NativeCapture::stopCapture()
{
    if (!running_ || !thread_)
        return false;
    stopFlag_ = true;
    if (thread_->joinable())
        thread_->join();
    thread_.reset();
    running_ = false;
    return true;
}

std::vector<AdapterInfo> NativeCapture::listAdapters()
{
    std::vector<AdapterInfo> out;
#if defined(EASYTSHARK_HAVE_LIBPCAP)
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) != 0)
    {
        LOG_F(WARNING, "NativeCapture: pcap_findalldevs 失败: %s", errbuf);
        return out;
    }
    int id = 1;
    for (pcap_if_t* d = alldevs; d; d = d->next)
    {
        if (!d->name)
            continue;
        AdapterInfo ai;
        ai.id    = id++;
        ai.name  = d->name;
        ai.remark = d->description ? d->description : d->name;
        out.push_back(ai);
    }
    pcap_freealldevs(alldevs);
#else
    LOG_F(WARNING, "NativeCapture: 未编译 libpcap 支持，无法枚举网卡");
#endif
    return out;
}

void NativeCapture::workThread(std::string adapterName, PacketCallback onPacket,
                               std::string captureFile, int durationSeconds)
{
#if defined(EASYTSHARK_HAVE_LIBPCAP)
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_live(adapterName.c_str(), 65535, 0 /*非混杂*/, 100 /*ms*/,
                                    errbuf);
    if (!handle)
    {
        LOG_F(ERROR, "NativeCapture: 打开网卡 %s 失败: %s", adapterName.c_str(), errbuf);
        running_ = false;
        return;
    }
    // 非阻塞读取：配合 stopFlag_ 轮询退出（避免阻塞在 pcap_next_ex 上无法停止）
    if (pcap_setnonblock(handle, 1, errbuf) != 0)
        LOG_F(WARNING, "NativeCapture: 设置非阻塞失败: %s", errbuf);

    FILE* out = nullptr;
    if (!captureFile.empty())
    {
        out = std::fopen(captureFile.c_str(), "wb");
        if (out)
            writePcapGlobalHeader(out);
        else
            LOG_F(WARNING, "NativeCapture: 无法打开落盘文件 %s（仅实时展示）", captureFile.c_str());
    }

    // 链路类型传给解析器（帧结构不同）：DLT_NULL=0, DLT_EN10MB=1；其余传 -1 让解析器自动检测。
    int linkType = -1;
    int dl       = pcap_datalink(handle);
    if (dl == DLT_NULL)
        linkType = 0;
    else if (dl == DLT_EN10MB)
        linkType = 1;

    LOG_F(INFO, "NativeCapture: 开始抓包 %s → %s（linktype=%d）", adapterName.c_str(),
          captureFile.c_str(), dl);
    auto   startTime = std::chrono::steady_clock::now();
    int    frame     = 1;
    // 跨包保留状态：实时抓包场景下同一 CAN 总线的多帧 UDS 报文也需要按到达顺序重组。
    NativePacketParser::IsoTpReassembler isoTp;
    while (!stopFlag_)
    {
        // 时长限制：到点退出（等价 tshark -a duration:N）
        if (durationSeconds > 0 &&
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() -
                                                             startTime)
                    .count() >= durationSeconds)
            break;

        struct pcap_pkthdr* hdr = nullptr;
        const unsigned char* data = nullptr;
        int rc = pcap_next_ex(handle, &hdr, &data);
        if (rc == 1 && hdr && data && hdr->caplen > 0)
        {
            if (out)
                writePcapRecord(out, hdr->ts.tv_sec, static_cast<uint32_t>(hdr->ts.tv_usec),
                                data, hdr->caplen, hdr->len);
            Packet p;
            p.frame_number = frame++;
            p.time         = static_cast<double>(hdr->ts.tv_sec) +
                             static_cast<double>(hdr->ts.tv_usec) / 1e6;
            p.cap_len = hdr->caplen;
            p.len     = hdr->len;
            NativePacketParser::parseFrame(data, hdr->caplen, p, linkType, &isoTp);
            if (onPacket)
                onPacket(std::make_shared<Packet>(std::move(p)));
        }
        else if (rc == -1)
        {
            LOG_F(ERROR, "NativeCapture: 抓包错误: %s", pcap_geterr(handle));
            break;
        }
        else
        {
            // rc == 0：非阻塞超时（100ms），继续轮询 stopFlag
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    if (out)
    {
        std::fflush(out);
        std::fclose(out);
    }
    pcap_close(handle);
    LOG_F(INFO, "NativeCapture: 抓包结束，共 %d 包", frame - 1);
#else
    LOG_F(ERROR, "NativeCapture: 未编译 libpcap 支持，无法抓包");
#endif
    running_ = false;
}
