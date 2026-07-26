// PipeIO 的 Windows 实现。
// Windows 匿名管道不支持 fd 级非阻塞，故用 PeekNamedPipe 先探测可读字节数，
// 只在确有数据时 ReadFile 相应数量，从而不阻塞。fd 是 _open_osfhandle 封装出的
// CRT 描述符，用 _get_osfhandle 取回底层管道 HANDLE。

#include "platform/PipeIO.hpp"

#include <io.h> // _get_osfhandle
#include <windows.h>

namespace platform
{
void setPipeNonblocking(int /*fd*/)
{
    // Windows 无需预设非阻塞：pipeRead 内部用 PeekNamedPipe 保证不阻塞。
}

long pipeRead(int fd, char* buf, std::size_t len)
{
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    DWORD avail = 0;
    // PeekNamedPipe 只探测、不消费；失败通常意味着对端已关闭（ERROR_BROKEN_PIPE）。
    if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr))
    {
        return -1;
    }
    if (avail == 0)
    {
        return 0; // 暂无数据，管道仍打开
    }

    DWORD toRead = (avail < len) ? avail : static_cast<DWORD>(len);
    DWORD got    = 0;
    if (!ReadFile(h, buf, toRead, &got, nullptr))
    {
        return -1;
    }
    if (got == 0)
    {
        return -1; // EOF
    }
    return static_cast<long>(got);
}
} // namespace platform
