#include "PcapFileReader.hpp"

#include <cstring>

#include "loguru/loguru.hpp"

#if defined(_WIN32)
// ============================================================================
// 非 POSIX 兜底实现：std::ifstream + seekg/read（一次打开、多次随机读，复用文件流缓冲）。
// Windows 暂未用原生内存映射（CreateFileMapping/MapViewOfFile）。
// ============================================================================

PcapFileReader::PcapFileReader() : size_(0) {}

PcapFileReader::~PcapFileReader()
{
    close();
}

bool PcapFileReader::open(const std::string& path)
{
    close();
    stream_.open(path, std::ios::binary);
    if (!stream_)
    {
        LOG_F(ERROR, "打开报文文件失败: %s", path.c_str());
        return false;
    }
    stream_.seekg(0, std::ios::end);
    size_ = static_cast<uint64_t>(stream_.tellg());
    stream_.seekg(0, std::ios::beg);
    return true;
}

bool PcapFileReader::readAt(uint64_t offset, uint32_t len, std::vector<unsigned char>& out) const
{
    if (!stream_.is_open())
    {
        return false;
    }
    if (offset > size_ || len > size_ - offset)
    {
        LOG_F(ERROR, "报文读取越界（偏移 %llu，长度 %u，文件大小 %llu）",
              static_cast<unsigned long long>(offset), len,
              static_cast<unsigned long long>(size_));
        return false;
    }
    out.resize(len);
    stream_.clear(); // 清除上次可能残留的 eof/fail 状态
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    stream_.read(reinterpret_cast<char*>(out.data()), len);
    return static_cast<bool>(stream_);
}

const unsigned char* PcapFileReader::viewAt(uint64_t offset, uint32_t len) const
{
    if (!stream_.is_open() || offset > size_ || len > size_ - offset)
    {
        return nullptr;
    }
    // 无内存映射：读入复用缓冲再借出指针（下次调用即失效，见头注释契约）。
    viewBuf_.resize(len);
    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    stream_.read(reinterpret_cast<char*>(viewBuf_.data()), len);
    if (!stream_)
    {
        return nullptr;
    }
    return viewBuf_.data();
}

void PcapFileReader::close()
{
    if (stream_.is_open())
    {
        stream_.close();
    }
    size_ = 0;
}

bool PcapFileReader::isOpen() const
{
    return stream_.is_open();
}

#else
// ============================================================================
// POSIX 实现：mmap 整个文件后按 offset 直接切片（随机访问免 lseek+read 与内核拷贝）。
// 页面靠缺页按需调入；MAP_PRIVATE + PROT_READ 只读映射，不影响原文件。
// ============================================================================

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

PcapFileReader::PcapFileReader() : fd_(-1), mapped_(nullptr), size_(0) {}

PcapFileReader::~PcapFileReader()
{
    close();
}

bool PcapFileReader::open(const std::string& path)
{
    close();

    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        LOG_F(ERROR, "打开报文文件失败: %s", path.c_str());
        return false;
    }

    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_size <= 0)
    {
        LOG_F(ERROR, "获取文件大小失败或文件为空: %s", path.c_str());
        ::close(fd);
        return false;
    }

    void* addr = ::mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
    {
        LOG_F(ERROR, "mmap 映射文件失败: %s", path.c_str());
        ::close(fd);
        return false;
    }

    // 主路径是 analyzeFile 对整份文件的一次顺序 viewAt 扫描（readAt 随机访问只在
    // hex/详情树按需查询时偶发），MADV_SEQUENTIAL 让内核预读跟上顺序访问，减少缺页次数。
    // 提示失败不影响正确性（退回默认策略），忽略返回值。
    ::posix_madvise(addr, static_cast<size_t>(st.st_size), POSIX_MADV_SEQUENTIAL);

    fd_     = fd;
    mapped_ = addr;
    size_   = static_cast<uint64_t>(st.st_size);
    return true;
}

bool PcapFileReader::readAt(uint64_t offset, uint32_t len, std::vector<unsigned char>& out) const
{
    if (mapped_ == nullptr)
    {
        return false;
    }
    if (offset > size_ || len > size_ - offset)
    {
        LOG_F(ERROR, "报文读取越界（偏移 %llu，长度 %u，文件大小 %llu）",
              static_cast<unsigned long long>(offset), len,
              static_cast<unsigned long long>(size_));
        return false;
    }
    out.resize(len);
    std::memcpy(out.data(), static_cast<const unsigned char*>(mapped_) + offset, len);
    return true;
}

const unsigned char* PcapFileReader::viewAt(uint64_t offset, uint32_t len) const
{
    if (mapped_ == nullptr || offset > size_ || len > size_ - offset)
    {
        return nullptr;
    }
    // 直接指向映射区：零拷贝、零分配，指针在 reader 存活期间全程有效。
    return static_cast<const unsigned char*>(mapped_) + offset;
}

void PcapFileReader::close()
{
    if (mapped_ != nullptr)
    {
        ::munmap(const_cast<void*>(mapped_), static_cast<size_t>(size_));
        mapped_ = nullptr;
    }
    if (fd_ >= 0)
    {
        ::close(fd_);
        fd_ = -1;
    }
    size_ = 0;
}

bool PcapFileReader::isOpen() const
{
    return mapped_ != nullptr;
}

#endif
