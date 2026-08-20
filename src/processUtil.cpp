#include "processUtil.hpp"

#if defined(_WIN32)
// ============================================================================
// Windows 实现：CreateProcess + 匿名管道（CreatePipe）
// 句柄继承：给子进程的管道端须可继承，父进程自留端用 SetHandleInformation 去掉继承标志，
// 否则子进程退出后父端收不到 EOF。TerminateProcess 等价 SIGKILL，非优雅收尾。
// ============================================================================

#include <cstdint>
#include <cstring>
#include <fcntl.h> // _O_RDONLY / _O_WRONLY
#include <io.h>    // _open_osfhandle / _close
#include <windows.h>

namespace
{
// 按 CommandLineToArgvW 规则给参数加引号转义：含空白/引号才加外层引号，反斜杠仅紧邻引号时成对转义。
std::string quoteArg(const std::string& arg)
{
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos)
    {
        return arg; // 无需引号
    }

    std::string out = "\"";
    for (std::string::const_iterator it = arg.begin();; ++it)
    {
        unsigned backslashes = 0;
        while (it != arg.end() && *it == '\\')
        {
            ++it;
            ++backslashes;
        }

        if (it == arg.end())
        {
            // 结尾的反斜杠：全部翻倍，使其不转义后面将要补上的收尾引号
            out.append(backslashes * 2, '\\');
            break;
        }
        else if (*it == '"')
        {
            // 引号前的反斜杠翻倍，再加一个反斜杠转义该引号
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
        }
        else
        {
            out.append(backslashes, '\\');
            out.push_back(*it);
        }
    }
    out.push_back('"');
    return out;
}

// 把 argv 向量拼成 CreateProcess 需要的单条命令行字符串。
std::string argvToCommandLine(const std::vector<std::string>& argv)
{
    std::string cmd;
    for (std::size_t i = 0; i < argv.size(); ++i)
    {
        if (i != 0)
            cmd.push_back(' ');
        cmd += quoteArg(argv[i]);
    }
    return cmd;
}

// 创建子进程并把其 stdout(读)/stdin(写) 接到匿名管道，父端封装成 FILE* 返回；pidOut 收子进程 HANDLE。
FILE* spawnWithPipe(const std::string& cmdline, ProcessUtil::ProcHandle* pidOut, bool readMode,
                          bool mergeStderr)
{
    SECURITY_ATTRIBUTES sa;
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE; // CreatePipe 出来的句柄默认可继承
    sa.lpSecurityDescriptor = nullptr;

    HANDLE pipeRead = nullptr, pipeWrite = nullptr;
    if (!CreatePipe(&pipeRead, &pipeWrite, &sa, 0))
    {
        return nullptr;
    }

    // 父进程自留端：读模式留读端、写模式留写端；去掉继承标志，确保子进程退出后能收到 EOF。
    HANDLE parentEnd = readMode ? pipeRead : pipeWrite;
    HANDLE childEnd  = readMode ? pipeWrite : pipeRead;
    SetHandleInformation(parentEnd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb      = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    if (readMode)
    {
        si.hStdOutput = childEnd; // 子进程 stdout → 管道写端
        // mergeStderr：stderr 一并写入管道（如 tshark 的 -Y 错误信息），否则透传父进程
        si.hStdError  = mergeStderr ? childEnd : GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    }
    else
    {
        si.hStdInput  = childEnd; // 子进程 stdin ← 管道读端
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // CreateProcessA 会写入命令行缓冲，必须传可写副本。
    std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back('\0');

    // CREATE_NEW_PROCESS_GROUP：为将来 GenerateConsoleCtrlEvent 优雅停止预留。
    // CREATE_NO_WINDOW：GUI 父进程下不为控制台程序 tshark 弹出黑框（只经管道读 stdout，不受影响）。
    BOOL ok = CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr,
                             TRUE, // 继承句柄（含上面可继承的 childEnd）
                             CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, nullptr, nullptr, &si,
                             &pi);

    // 无论成败，父进程都不再需要子进程那一端。
    CloseHandle(childEnd);

    if (!ok)
    {
        CloseHandle(parentEnd);
        return nullptr;
    }
    CloseHandle(pi.hThread); // 主线程句柄用不上

    if (pidOut)
        *pidOut = pi.hProcess; // 交出进程 HANDLE（由 PcloseEx/Kill 负责 CloseHandle）

    // 父端 HANDLE 交给 CRT：_open_osfhandle 成功后归 fd 所有，关闭 fd 即关句柄，不可再 CloseHandle。
    int osFlags = readMode ? _O_RDONLY : _O_WRONLY;
    int fd      = _open_osfhandle(reinterpret_cast<intptr_t>(parentEnd), osFlags);
    if (fd == -1)
    {
        CloseHandle(parentEnd);
        return nullptr;
    }

    FILE* fp = _fdopen(fd, readMode ? "r" : "w");
    if (!fp)
    {
        _close(fd);
        return nullptr;
    }
    return fp;
}
} // namespace

const ProcessUtil::ProcHandle ProcessUtil::kInvalidProc = nullptr;

bool ProcessUtil::ValidProc(ProcHandle h)
{
    return h != nullptr;
}

bool ProcessUtil::Exec(const char* command)
{
    // Windows 上 system() 走 cmd.exe /c；与 POSIX 版一样仅供可信、固定命令场景。
    return command != nullptr && system(command) == 0;
}

bool ProcessUtil::Exec(const std::vector<std::string>& argv)
{
    if (argv.empty())
        return false;

    std::string cmdline = argvToCommandLine(argv);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::vector<char> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back('\0');

    // CREATE_NO_WINDOW：同上，避免同步启动的控制台子进程在 GUI 下弹出黑框。
    if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
    {
        return false;
    }
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

FILE* ProcessUtil::PopenEx(const char* command, ProcHandle* pid, const char* type)
{
    if (!command)
        return nullptr;
    // 经 cmd.exe /c 执行，等价 POSIX 的 /bin/sh -c（存在注入风险，仅测试等可信场景用）。
    std::string shellCmd = std::string("cmd.exe /c ") + command;
    return spawnWithPipe(shellCmd, pid, type[0] == 'r');
}

FILE* ProcessUtil::PopenEx(const std::vector<std::string>& argv, ProcHandle* pid,
                            const char* type, bool mergeStderr)
{
    if (argv.empty())
        return nullptr;
    return spawnWithPipe(argvToCommandLine(argv), pid, type[0] == 'r', mergeStderr);
}

bool ProcessUtil::Kill(ProcHandle pid)
{
    if (!ValidProc(pid))
        return false;

    HANDLE hProc = static_cast<HANDLE>(pid);
    // 注意：TerminateProcess 等价 SIGKILL，tshark 不会 flush -w 文件即被杀。
    // 若需优雅收尾可对进程组发 GenerateConsoleCtrlEvent，此处从简。
    BOOL terminated = TerminateProcess(hProc, 1);
    WaitForSingleObject(hProc, INFINITE); // 回收，避免句柄悬挂
    CloseHandle(hProc);
    return terminated != FALSE;
}

bool ProcessUtil::Signal(ProcHandle pid)
{
    if (!ValidProc(pid))
        return false;
    // 只请求终止，回收留给配套的 PcloseEx；同 Kill：无法让 tshark flush -w 文件。
    return TerminateProcess(static_cast<HANDLE>(pid), 1) != FALSE;
}

int ProcessUtil::PcloseEx(FILE* pipe, ProcHandle pid)
{
    if (!pipe)
        return -1;

    fclose(pipe);

    DWORD exitCode = 0;
    if (ValidProc(pid))
    {
        HANDLE hProc = static_cast<HANDLE>(pid);
        WaitForSingleObject(hProc, INFINITE);
        GetExitCodeProcess(hProc, &exitCode);
        CloseHandle(hProc);
    }
    return static_cast<int>(exitCode);
}

#else
// ============================================================================
// POSIX 实现：fork + execvp + pipe + waitpid（Linux / macOS）
// ============================================================================

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

const ProcessUtil::ProcHandle ProcessUtil::kInvalidProc = static_cast<pid_t>(-1);

bool ProcessUtil::ValidProc(ProcHandle h)
{
    return h > 0;
}

bool ProcessUtil::Exec(const char* command)
{
    int result = system(command);
    return result == 0;
}

bool ProcessUtil::Exec(const std::vector<std::string>& argv)
{
    if (argv.empty())
        return false;

    // fork 前构建 argv：fork 后 exec 前只能调 async-signal-safe 函数，此刻别的线程持 malloc 锁会死锁。
    // cargv 指针指向 argv 缓冲，父进程存活、子进程 COW 共享，均有效。
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

// @warning 该 const char* 版经 /bin/sh -c 执行：多一层 shell 进程，且 ; | $() ` 等元字符会被
// shell 解释，拼接用户输入会注入。仅供测试等可信、固定命令场景；业务热路径一律用下方 argv 重载。
FILE* ProcessUtil::PopenEx(const char* command, ProcHandle* pid, const char* type)
{
    int   pipefd[2];
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

FILE* ProcessUtil::PopenEx(const std::vector<std::string>& argv, ProcHandle* pid,
                            const char* type, bool mergeStderr)
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

    // 两端立即置 FD_CLOEXEC：多网卡管道并发时若不设，后 fork 的子进程会继承前面管道的 fd，
    // 导致前一个管道在其 tshark 退出后收不到 EOF。dup2 到 stdio 的端会清除 CLOEXEC 而存活。
    // pipe()→fcntl 间有极窄竞态（macOS 无 pipe2 无法原子设置），可接受。
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
            if (mergeStderr)
                dup2(pipefd[1], STDERR_FILENO); // stderr 合并进管道（错误信息可读）
        }
        else
        {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
        }

        // 同 Exec：execvp 不经 shell，规避元字符注入
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

bool ProcessUtil::Kill(ProcHandle pid)
{
    if (pid <= 0)
        return false;

    // 即便进程已自行退出（kill 返回 -1），仍要 waitpid 回收残留避免僵尸，故不因 kill 失败提前返回。
    bool signaled = (kill(pid, SIGTERM) == 0);

    int  status;
    bool reaped = (waitpid(pid, &status, 0) == pid);

    return signaled && reaped;
}

bool ProcessUtil::Signal(ProcHandle pid)
{
    if (pid <= 0)
        return false;
    // 只发信号，不 waitpid：回收留给配套的 PcloseEx，避免双重 waitpid。
    return kill(pid, SIGTERM) == 0;
}

int ProcessUtil::PcloseEx(FILE* pipe, ProcHandle pid)
{
    if (!pipe)
        return -1;

    fclose(pipe);

    int status = 0;
    if (pid > 0)
        waitpid(pid, &status, 0); // 回收子进程，避免僵尸进程

    return status;
}

#endif
