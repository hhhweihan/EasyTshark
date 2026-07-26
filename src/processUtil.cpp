#include "processUtil.hpp"
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

bool ProcessUtil::Exec(const char* command)
{
    int result = system(command);
    return result == 0;
}

bool ProcessUtil::Exec(const std::vector<std::string>& argv)
{
    if (argv.empty())
        return false;

    // 在 fork 之前构建 argv 数组：多线程程序里 fork 之后、exec 之前只能调用
    // async-signal-safe 函数，若此刻别的线程正持有 malloc 锁，子进程再分配就会死锁。
    // cargv 里的指针指向 argv 各字符串的缓冲，父进程持续存活、子进程经 COW 共享，均有效。
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& arg : argv)
        cargv.push_back(const_cast<char*>(arg.c_str()));
    cargv.push_back(nullptr);

    pid_t childpid = fork();
    if (childpid < 0)
        return false;

    if (childpid == 0)
    { // 子进程：用 execvp 直接执行，不经过 shell，避免元字符被解释
        execvp(cargv[0], cargv.data());
        _exit(127); // execvp 失败才会执行到这里
    }

    int status;
    if (waitpid(childpid, &status, 0) != childpid)
        return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// @warning 该 const char* 版经由 /bin/sh -c 执行命令，存在两点代价：
//   1) 多派生一层 shell 进程（fork+exec(sh)，sh 再 fork+exec 目标程序）；
//   2) 命令中的 ; | $() ` 等元字符会被 shell 解释，拼接用户输入会造成注入。
// 因此仅供测试等可信、固定命令场景使用。业务热路径（抓包/解析/监控）一律用下方
// 接收 argv 向量的重载，走 execvp 直接替换地址空间，既省一层进程也无注入面。
FILE* ProcessUtil::PopenEx(const char* command, pid_t* pid, const char* type)
{
    int pipefd[2];
    pid_t childpid;

    if (pipe(pipefd) < 0)
        return nullptr;

    childpid = fork();

    if (childpid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return nullptr;
    }

    if (childpid == 0)
    { // 子进程
        if (type[0] == 'r')
        {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
        }
        else
        {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
        }

        execl("/bin/sh", "sh", "-c", command, nullptr);
        _exit(127);
    }

    // 父进程
    if (pid)
        *pid = childpid;

    if (type[0] == 'r')
    {
        close(pipefd[1]);
        return fdopen(pipefd[0], "r");
    }
    else
    {
        close(pipefd[0]);
        return fdopen(pipefd[1], "w");
    }
}

FILE* ProcessUtil::PopenEx(const std::vector<std::string>& argv, pid_t* pid, const char* type)
{
    if (argv.empty())
        return nullptr;

    // 在 fork 之前构建 argv（同 Exec：规避 fork 后子进程堆分配的 malloc-锁死锁）。
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& arg : argv)
        cargv.push_back(const_cast<char*>(arg.c_str()));
    cargv.push_back(nullptr);

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return nullptr;

    // 两端立即置 FD_CLOEXEC：多线程下同时有多个网卡管道时，若不设置，后 fork 的子进程
    // 会继承前面管道的描述符，导致前一个管道在其对应 tshark 退出后仍收不到 EOF。子进程
    // dup2 到 stdio 的那一端由 dup2 清除 CLOEXEC 而在 exec 后存活，原始描述符则于 exec 时
    // 自动关闭。pipe()→fcntl 之间仍有极窄竞态窗口（macOS 无 pipe2 无法原子设置），可接受。
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    pid_t childpid = fork();
    if (childpid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return nullptr;
    }

    if (childpid == 0)
    { // 子进程：只调用 async-signal-safe 的 close/dup2/execvp/_exit，不做任何堆分配
        if (type[0] == 'r')
        {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
        }
        else
        {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
        }

        // 用 execvp 直接执行程序，不经过 /bin/sh，参数不会被 shell 解释
        execvp(cargv[0], cargv.data());
        _exit(127);
    }

    // 父进程
    if (pid)
        *pid = childpid;

    if (type[0] == 'r')
    {
        close(pipefd[1]);
        return fdopen(pipefd[0], "r");
    }
    else
    {
        close(pipefd[0]);
        return fdopen(pipefd[1], "w");
    }
}

bool ProcessUtil::Kill(pid_t pid)
{
    if (pid <= 0)
        return false;

    // 即便进程可能已自行退出（kill 返回 -1，如 EOF 后的僵尸），仍要 waitpid 回收其残留，
    // 否则会漏掉一个僵尸进程。故不因 kill 失败提前返回。
    bool signaled = (kill(pid, SIGTERM) == 0);

    int  status;
    bool reaped = (waitpid(pid, &status, 0) == pid);

    return signaled && reaped;
}

int ProcessUtil::PcloseEx(FILE* pipe, pid_t pid)
{
    if (!pipe)
        return -1;

    fclose(pipe);

    int status = 0;
    if (pid > 0)
        waitpid(pid, &status, 0); // 回收子进程，避免僵尸进程

    return status;
} 