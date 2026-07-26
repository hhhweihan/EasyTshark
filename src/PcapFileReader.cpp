#include "PcapFileReader.hpp"

#include <cstring>

#include "loguru/loguru.hpp"

#if defined(_WIN32)
// ============================================================================
// 非 POSIX 兜底实现：std::ifstream + seekg/read
// 相比“每次取包都重新打开文件”的原实现，这里一次打开、多次随机读，
// 省去重复的 open()/close() 系统调用，并复用文件流缓冲。
// Windows 原生内存映射（CreateFileMapping/MapViewOfFile）留待主题 1 二期。
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
    // 越界检查：避免读到文件尾之外的未定义内容
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
// POSIX 实现：mmap 整个文件后按 offset 直接切片
// 学习点：随机访问免去 lseek+read 双系统调用与一次内核→用户拷贝，
// 页面靠缺页中断按需调入；MAP_PRIVATE + PROT_READ 只读映射，不影响原文件。
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
    // 越界检查：offset 与 offset+len 都必须落在映射范围内
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
