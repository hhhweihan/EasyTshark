#ifndef processUtil_hpp
#define processUtil_hpp

#include <cstdio>
#include <string>
#include <sys/types.h>
#include <vector>

/**
 * @brief 进程操作工具类
 */
class ProcessUtil {
public:
    /**
     * @brief 执行命令并等待完成
     * @param command 要执行的命令
     * @return true 执行成功
     * @return false 执行失败
     * @warning 该重载通过 /bin/sh -c 执行，命令中的 shell 元字符会被解释，
     *          存在注入风险。传入不可信输入时请改用 argv 向量重载。
     */
    static bool Exec(const char* command);

    /**
     * @brief 执行命令并等待完成（安全版：不经过 shell）
     * @param argv 参数向量，argv[0] 为可执行程序，其余为参数；不会被 shell 解释
     * @return true 子进程正常退出且返回 0
     * @return false 失败
     */
    static bool Exec(const std::vector<std::string>& argv);

    /**
     * @brief 扩展的 popen 函数，返回进程 ID
     * @param command 要执行的命令
     * @param pid 输出参数，存储子进程的 PID
     * @param type 打开模式 ("r" 或 "w")，默认为 "r"
     * @return FILE* 管道文件指针
     * @warning 该重载通过 /bin/sh -c 执行，存在 shell 注入风险。
     *          传入不可信输入（如用户提供的网卡名、文件路径）时请改用 argv 向量重载。
     */
    static FILE* PopenEx(const char* command, pid_t* pid, const char* type = "r");

    /**
     * @brief 扩展的 popen（安全版：不经过 shell，用 execvp 执行）
     * @param argv 参数向量，argv[0] 为可执行程序名，其余为参数；不会被 shell 解释
     * @param pid 输出参数，存储子进程的 PID
     * @param type 打开模式 ("r" 或 "w")，默认为 "r"
     * @return FILE* 管道文件指针，失败返回 nullptr
     */
    static FILE* PopenEx(const std::vector<std::string>& argv, pid_t* pid,
                         const char* type = "r");

    /**
     * @brief 终止指定 PID 的进程
     * @param pid 进程 ID
     * @return true 终止成功
     * @return false 终止失败
     */
    static bool Kill(pid_t pid);

    /**
     * @brief 关闭 PopenEx 返回的管道并回收子进程
     * @param pipe PopenEx 返回的 FILE*
     * @param pid PopenEx 输出的子进程 PID
     * @return 子进程的退出状态（waitpid 的 status）；pipe 为空时返回 -1
     * @note 与 argv 版 PopenEx 配套使用，替代 pclose（pclose 只适用于 popen）
     */
    static int PcloseEx(FILE* pipe, pid_t pid);
};

#endif 