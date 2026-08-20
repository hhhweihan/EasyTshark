#ifndef PcapFileReader_hpp
#define PcapFileReader_hpp

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

// 按文件偏移随机读取 pcap 报文数据的小抽象：一次打开、多次随机读，
// 消除“每次取包都重新 open/close 文件”的开销。两套实现按平台编译：
//   - POSIX（Linux/macOS）：mmap 整个文件，readAt 从映射区 memcpy，免 lseek+read。
//   - 非 POSIX（含 Windows，暂以文件流兜底）：std::ifstream + seekg/read。
// 持有独占文件资源，故禁用拷贝。
class PcapFileReader
{
public:
    PcapFileReader();
    ~PcapFileReader();

    // 打开文件（会先关闭之前打开的）。成功返回 true。
    bool open(const std::string& path);

    // 从 offset 读取 len 字节到 out（拷贝，供调用方长期持有）。越界/未打开/失败返回 false。
    bool readAt(uint64_t offset, uint32_t len, std::vector<unsigned char>& out) const;

    // 零拷贝借出只读指针，越界/未打开返回 nullptr。用于批量顺序遍历的热路径。
    // 契约：返回指针仅在本 reader 下一次 viewAt/readAt/close 之前有效。
    //   - POSIX：直接指向 mmap 映射区，全程稳定。
    //   - 非 POSIX：指向内部复用缓冲，下次调用即失效。
    const unsigned char* viewAt(uint64_t offset, uint32_t len) const;

    // 释放底层资源（析构会自动调用）
    void close();

    bool isOpen() const;

    // 文件大小（字节）；未打开时 0。供调用方判断遍历边界，避免试探性越界读。
    uint64_t size() const { return size_; }

private:
    // 禁止拷贝：底层持有 mmap 映射或文件句柄，拷贝会造成双重释放
    PcapFileReader(const PcapFileReader&);
    PcapFileReader& operator=(const PcapFileReader&);

#if defined(_WIN32)
    // 兜底实现：标准库文件流（Windows 尚未用原生 CreateFileMapping）
    mutable std::ifstream stream_;
    uint64_t              size_;
    // viewAt 的复用缓冲：下次 viewAt/readAt 会覆盖它（见头注释契约）。
    mutable std::vector<unsigned char> viewBuf_;
#else
    // POSIX：mmap 映射
    int         fd_;
    const void* mapped_; // 映射基址（MAP_FAILED / nullptr 表示未映射）
    uint64_t    size_;   // 映射长度 = 文件大小
#endif
};

#endif
