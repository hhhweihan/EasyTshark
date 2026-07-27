#ifndef platform_PipeIO_hpp
#define platform_PipeIO_hpp

#include <cstddef>

// 管道非阻塞读取的跨平台小抽象。
//
// 背景：FlowMonitor 为每块网卡开一个 tshark 子进程，用 EventPoller 汇聚可读事件后，
// 需要以“有多少读多少、绝不阻塞”的方式把数据抽干。POSIX 用 fcntl(O_NONBLOCK)+read，
// Windows 匿名管道不支持 fd 级非阻塞，需先 PeekNamedPipe 探测再 ReadFile。此处把这点
// 差异收敛到两个函数里，业务代码（FlowMonitor）保持平台无关。
namespace platform
{
// 把源自 popen 管道的 CRT fd 设为非阻塞。
//   POSIX：fcntl 置 O_NONBLOCK。
//   Windows：空操作（读前用 PeekNamedPipe 判断可读量，天然非阻塞）。
void setPipeNonblocking(int fd);

// 返回值语义（三态）：
//   >0 : 实际读取的字节数；
//    0 : 当前无数据可读（相当于 POSIX 的 EAGAIN），管道仍打开；
//   -1 : 对端已关闭(EOF) 或发生错误。
long pipeRead(int fd, char* buf, std::size_t len);
} // namespace platform

#endif
