// EventPoller 的 poll() 实现：Linux 与 macOS 共用。
//
// poll() 是 POSIX 标准，在所有类 Unix 系统上可用，且支持管道 fd，
// 因此一份代码即可覆盖 Linux + macOS，无需为 mac 单独写 kqueue。
// Windows 无法用它多路复用匿名管道（WSAPoll 仅限 socket），
// 届时另建 src/platform/EventPollerWin.cpp 实现同一套接口。

#include "platform/EventPoller.hpp"

#include <algorithm>
#include <cerrno>
#include <poll.h>

EventPoller::EventPoller() {}

EventPoller::~EventPoller() {}

bool EventPoller::add(int fd)
{
    if (fd < 0)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    if (std::find(fds_.begin(), fds_.end(), fd) == fds_.end())
    {
        fds_.push_back(fd);
    }
    return true;
}

void EventPoller::remove(int fd)
{
    std::lock_guard<std::mutex> lock(mtx_);
    fds_.erase(std::remove(fds_.begin(), fds_.end(), fd), fds_.end());
}

void EventPoller::clear()
{
    std::lock_guard<std::mutex> lock(mtx_);
    fds_.clear();
}

std::size_t EventPoller::size() const
{
    std::lock_guard<std::mutex> lock(mtx_);
    return fds_.size();
}

std::vector<int> EventPoller::wait(int timeoutMs)
{
    std::vector<int> ready;

    // 持锁拷贝 fd 快照后立即释放锁，避免阻塞的 poll() 挡住其它线程的 add/remove
    std::vector<struct pollfd> pfds;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        pfds.reserve(fds_.size());
        for (std::size_t i = 0; i < fds_.size(); ++i)
        {
            struct pollfd pfd;
            pfd.fd      = fds_[i];
            pfd.events  = POLLIN;
            pfd.revents = 0;
            pfds.push_back(pfd);
        }
    }

    if (pfds.empty())
    {
        return ready;
    }

    int ret;
    do
    {
        ret = ::poll(&pfds[0], static_cast<nfds_t>(pfds.size()), timeoutMs);
    } while (ret < 0 && errno == EINTR); // 被信号打断则重试

    if (ret <= 0)
    {
        // ret == 0 超时；ret < 0 出错。两种情况都返回空列表，
        // 由调用方结合超时逻辑（如检查停止标志）继续处理。
        return ready;
    }

    ready.reserve(static_cast<std::size_t>(ret));
    for (std::size_t i = 0; i < pfds.size(); ++i)
    {
        // 可读、对端关闭、出错都交给调用方去 read() 后判断
        if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR))
        {
            ready.push_back(pfds[i].fd);
        }
    }
    return ready;
}
