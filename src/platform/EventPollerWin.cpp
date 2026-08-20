// EventPoller 的 Windows 实现。
// 为什么不用 WSAPoll：它只支持套接字，而这里多路复用的是 tshark 子进程的匿名管道。
// 故改用轮询式探测：对每个 fd 用 PeekNamedPipe 查可读数据/对端关闭，语义与 poll 版一致。
// 取舍：PeekNamedPipe 不能阻塞，wait() 用“小步睡眠 + 轮询”逼近 timeoutMs（低频数据可接受）。

#include "platform/EventPoller.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

#include <io.h> // _get_osfhandle
#include <windows.h>

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

namespace
{
// 探测单个 fd：有可读数据或对端关闭/出错 → true（交调用方 read 后判断）。
bool fdReady(int fd)
{
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE)
    {
        return true; // 无效句柄：当作“就绪”，让调用方 read 得到错误并清理
    }
    DWORD avail = 0;
    if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr))
    {
        return true; // 对端关闭（ERROR_BROKEN_PIPE 等）：报可读，调用方 read 得 EOF
    }
    return avail > 0;
}
} // namespace

std::vector<int> EventPoller::wait(int timeoutMs)
{
    // 轮询步长：10ms。与 poll 版不同，这里靠“睡眠 + 重扫”逼近超时，
    // 直到有 fd 就绪或耗尽 timeoutMs。timeoutMs<0 视为长等待（按步长持续轮询）。
    const int stepMs = 10;
    int       waited = 0;

    for (;;)
    {
        std::vector<int> snapshot;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            snapshot = fds_; // 持锁拷贝快照，避免长时间占锁挡住 add/remove
        }

        std::vector<int> ready;
        for (std::size_t i = 0; i < snapshot.size(); ++i)
        {
            if (fdReady(snapshot[i]))
            {
                ready.push_back(snapshot[i]);
            }
        }
        if (!ready.empty())
        {
            return ready;
        }

        if (snapshot.empty())
        {
            return ready; // 无 fd 可等，直接返回空（与 poll 版一致）
        }
        if (timeoutMs >= 0 && waited >= timeoutMs)
        {
            return ready; // 超时，返回空列表
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(stepMs));
        waited += stepMs;
    }
}
