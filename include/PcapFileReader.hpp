#ifndef PcapFileReader_hpp
#define PcapFileReader_hpp

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

// 按文件偏移随机读取 pcap 报文数据的小抽象：一次打开、多次随机读，
// 消除“每次取包都重新 open/close 文件”的系统调用开销。
//
// 两套实现按平台选择编译（见 PcapFileReader.cpp）：
//   - POSIX（Linux/macOS）：mmap 整个文件，readAt 从映射区 memcpy。
//     随机按 offset 访问免去 lseek+read 双系统调用与一次内核→用户拷贝，
//     靠缺页中断按需调页。
//   - 非 POSIX（含 Windows CreateFileMapping 落地前的兜底）：持有 std::ifstream，
//     readAt 用 clear()+seekg+read；相比原实现仍省去重复 open/close。
//
// 非拷贝语义：持有独占的文件资源（映射/句柄/流），禁用拷贝，允许移动语义
// 由使用方避免（这里直接删除拷贝，作为 PcapAnalyzer 的成员按需 open 即可）。
class PcapFileReader
{
public:
    PcapFileReader();
    ~PcapFileReader();

    // 打开文件（会先关闭之前打开的）。成功返回 true。
    bool open(const std::string& path);

    // 从 offset 读取 len 字节到 out。越界 / 未打开 / 读取失败返回 false。
    bool readAt(uint64_t offset, uint32_t len, std::vector<unsigned char>& out) const;

    // 释放底层资源（析构会自动调用）
    void close();

    bool isOpen() const;

private:
    // 禁止拷贝：底层持有 mmap 映射或文件句柄，拷贝会造成双重释放
    PcapFileReader(const PcapFileReader&);
    PcapFileReader& operator=(const PcapFileReader&);

#if defined(_WIN32)
    // 兜底实现：标准库文件流（Windows 原生 CreateFileMapping 留待主题 1 二期）
    mutable std::ifstream stream_;
    uint64_t              size_;
#else
    // POSIX：mmap 映射
    int         fd_;
    const void* mapped_; // 映射基址（MAP_FAILED / nullptr 表示未映射）
    uint64_t    size_;   // 映射长度 = 文件大小
#endif
};

#endif
