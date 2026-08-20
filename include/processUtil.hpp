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

    /**
     * @brief 执行命令并等待完成
     * @warning 该重载通过 shell（POSIX: /bin/sh -c，Windows: cmd.exe /c）执行，
     *          命令中的元字符会被解释，存在注入风险。传入不可信输入时请改用 argv 向量重载。
     */
    static bool Exec(const char* command);

    /**
     * @brief 执行命令并等待完成（安全版：不经过 shell）
     * @param argv 参数向量，argv[0] 为可执行程序，其余为参数；不会被 shell 解释
     * @return true 子进程正常退出且返回 0
     */
    static bool Exec(const std::vector<std::string>& argv);

    /**
     * @brief 扩展的 popen，返回子进程句柄
     * @param pid 输出参数，存储子进程句柄（POSIX: pid_t，Windows: 进程 HANDLE）
     * @param type 打开模式 ("r" 或 "w")，默认 "r"
     * @return FILE* 管道文件指针，失败返回 nullptr
     * @warning 经由 shell 执行，存在注入风险；不可信输入请改用 argv 向量重载。
     */
    static FILE* PopenEx(const char* command, ProcHandle* pid, const char* type = "r");

    /**
     * @brief 扩展的 popen（安全版：不经过 shell）
     * @param argv 参数向量，argv[0] 为可执行程序名，其余为参数；不会被 shell 解释
     * @param pid 输出参数，存储子进程句柄
     * @param type 打开模式 ("r" 或 "w")，默认 "r"
     * @return FILE* 管道文件指针，失败返回 nullptr
     */
    static FILE* PopenEx(const std::vector<std::string>& argv, ProcHandle* pid,
                         const char* type = "r", bool mergeStderr = false);

    /**
     * @brief 终止指定子进程并回收
     * @param pid 子进程句柄
     * @note POSIX 发 SIGTERM 后 waitpid 回收；Windows 用 TerminateProcess 后 CloseHandle。
     */
    static bool Kill(ProcHandle pid);

    /**
     * @brief 请求子进程终止，但**不回收**（不 waitpid / 不 CloseHandle）
     * @param pid 子进程句柄
     * @note 供“发信号收尾 + 由配套 PcloseEx 单点回收”的场景使用，避免与 PcloseEx 争抢回收
     *       造成双重 waitpid / CloseHandle。POSIX 发 SIGTERM；Windows 用 TerminateProcess。
     */
    static bool Signal(ProcHandle pid);

    /**
     * @brief 关闭 PopenEx 返回的管道并回收子进程
     * @param pipe PopenEx 返回的 FILE*
     * @param pid  PopenEx 输出的子进程句柄
     * @return 子进程退出状态；pipe 为空时返回 -1
     */
    static int PcloseEx(FILE* pipe, ProcHandle pid);
};

#endif
