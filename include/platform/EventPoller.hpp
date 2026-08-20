#ifndef platform_EventPoller_hpp
#define platform_EventPoller_hpp

#include <cstddef>
#include <mutex>
#include <vector>

// 事件轮询抽象：屏蔽不同平台的 I/O 多路复用机制。
// 用 POSIX 标准 poll()（Linux/macOS 共用，见 EventPollerPoll.cpp），Windows 另有实现。
// 头文件不引入 <poll.h>，成员只存原始 fd，pollfd 数组在 .cpp 内临时构造。
class EventPoller
{
public:
    EventPoller();
    ~EventPoller();

    // 注册一个 fd 的可读事件。已存在则忽略，返回是否成功（fd 合法即成功）。
    bool add(int fd);

    // 注销一个 fd。不存在则忽略。
    void remove(int fd);

    void clear();

    std::size_t size() const;

    // 等待事件，最多阻塞 timeoutMs 毫秒（-1 无限等待，0 立即返回）。返回本次可读的 fd 列表，
    // 超时则为空。对端关闭（POLLHUP）/出错（POLLERR）也并入，由调用方 read() 后自行处理。
    // 线程安全：所有方法可跨线程调用；wait() 持锁拷贝 fd 快照后即释放锁再 poll()，
    // 故阻塞的 wait 不挡住其它线程的 add/remove。
    std::vector<int> wait(int timeoutMs);

private:
    std::vector<int>   fds_; // 已注册的 fd 列表
    mutable std::mutex mtx_; // 保护 fds_，支持跨线程访问
};

#endif
