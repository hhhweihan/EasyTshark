#ifndef platform_EventPoller_hpp
#define platform_EventPoller_hpp

#include <cstddef>
#include <mutex>
#include <vector>

// 事件轮询抽象：屏蔽不同平台的 I/O 多路复用机制。
//
// 背景：项目最初在 Linux 上用 epoll 实现，但 epoll 是 Linux 专有的，
// macOS/BSD 没有。这里改用 POSIX 标准的 poll()——语义与 epoll 一一对应，
// 且 Linux 与 macOS 可以共用同一份实现（见 src/platform/EventPollerPoll.cpp）。
//
// 设计要点：头文件不引入 <poll.h>，成员只保存原始 fd，具体的 pollfd
// 数组在 .cpp 内临时构造，从而让业务代码（tsharkManager）完全不感知底层机制。
class EventPoller
{
public:
    EventPoller();
    ~EventPoller();

    // 注册一个 fd 的可读事件。已存在则忽略，返回是否成功（fd 合法即成功）。
    bool add(int fd);

    // 注销一个 fd。不存在则忽略。
    void remove(int fd);

    // 清空所有已注册的 fd。
    void clear();

    // 当前注册的 fd 数量。
    std::size_t size() const;

    // 等待事件，最多阻塞 timeoutMs 毫秒（-1 表示无限等待，0 表示立即返回）。
    // 返回本次变为可读的 fd 列表；超时则返回空 vector。
    // 对端关闭（POLLHUP）或出错（POLLERR）也会并入返回，
    // 由调用方通过 read() 得到 EOF 或错误码后自行处理。
    //
    // 线程安全：本类的所有方法都可跨线程调用（原 epoll 允许在一个线程
    // epoll_wait 的同时另一线程 epoll_ctl，这里保持同样语义）。实现上
    // wait() 在持锁时拷贝 fd 快照后即释放锁再执行 poll()，因此一次阻塞的
    // wait 不会挡住另一线程的 add/remove。
    std::vector<int> wait(int timeoutMs);

private:
    std::vector<int>   fds_; // 已注册的 fd 列表
    mutable std::mutex mtx_; // 保护 fds_，支持跨线程访问
};

#endif
