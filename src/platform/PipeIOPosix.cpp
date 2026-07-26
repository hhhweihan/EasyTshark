// PipeIO 的 POSIX 实现（Linux / macOS 共用）：用 fcntl(O_NONBLOCK) 将管道设为非阻塞读取。

#include "platform/PipeIO.hpp"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace platform
{
void setPipeNonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1)
    {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

long pipeRead(int fd, char* buf, std::size_t len)
{
    ssize_t n = ::read(fd, buf, len);
    if (n > 0)
    {
        return static_cast<long>(n);
    }
    if (n == 0)
    {
        return -1; // EOF：对端关闭
    }
    // n < 0
    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        return 0; // 暂无数据，管道仍打开
    }
    return -1; // 其它错误按关闭处理
}
} // namespace platform
