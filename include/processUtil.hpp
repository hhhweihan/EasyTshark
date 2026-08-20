#ifndef processUtil_hpp
#define processUtil_hpp

#include <cstdio>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/types.h> // pid_t
#endif

/**
 * @brief 进程操作工具类（跨平台：POSIX 走 fork/execvp，Windows 走 CreateProcess）
 */
class ProcessUtil {
public:
#if defined(_WIN32)
    // Windows：子进程用 HANDLE 标识。头文件用 void* 承载，避免把 <windows.h> 传染给包含者。
    using ProcHandle = void*;
#else
    // POSIX：子进程用 pid_t 标识。
    using ProcHandle = pid_t;
#endif

    /// 无效句柄哨兵：Windows 为 nullptr，POSIX 为 (pid_t)-1。
    static const ProcHandle kInvalidProc;

    /// 句柄是否指向一个已成功创建、尚未回收的子进程。
    static bool ValidProc(ProcHandle h);

    // @warning 该重载通过 shell（POSIX: /bin/sh -c，Windows: cmd.exe /c）执行，
    // 命令中的元字符会被解释，存在注入风险。传入不可信输入时请改用 argv 向量重载。
    static bool Exec(const char* command);

    static bool Exec(const std::vector<std::string>& argv);

    // @warning 经由 shell 执行，存在注入风险；不可信输入请改用 argv 向量重载。
    static FILE* PopenEx(const char* command, ProcHandle* pid, const char* type = "r");

    static FILE* PopenEx(const std::vector<std::string>& argv, ProcHandle* pid,
                         const char* type = "r", bool mergeStderr = false);

    // POSIX 发 SIGTERM 后 waitpid 回收；Windows 用 TerminateProcess 后 CloseHandle。
    static bool Kill(ProcHandle pid);

    // 只请求终止、不回收（不 waitpid / 不 CloseHandle）：供“发信号收尾 + 由配套 PcloseEx
    // 单点回收”的场景使用，避免与 PcloseEx 争抢回收造成双重 waitpid / CloseHandle。
    static bool Signal(ProcHandle pid);

    static int PcloseEx(FILE* pipe, ProcHandle pid);
};

#endif
