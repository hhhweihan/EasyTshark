#ifndef TEST_FS_UTIL_HPP
#define TEST_FS_UTIL_HPP

// 测试专用的文件系统辅助函数：全部走程序内系统调用，不再拼命令交给 /bin/sh，
// 从而避免测试 setup/teardown 依赖 shell（system("mkdir -p") / system("rm -rf")）。
// 函数声明为 inline，可安全被多个测试翻译单元包含而不违反 ODR。
//
// 平台差异以 #if defined(_WIN32) / #else 隔离：POSIX（Linux/macOS）路径保持原样、
// 行为不变；Windows 用 Win32 API（_mkdir / GetFileAttributes / FindFirstFile）等价实现。

#include <cerrno>
#include <string>

#if defined(_WIN32)
#include <direct.h>  // _mkdir / _rmdir
#include <windows.h> // GetFileAttributes / FindFirstFile / DeleteFile / RemoveDirectory
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace testfs
{
#if defined(_WIN32)
// 文件（或目录）是否存在
inline bool fileExists(const std::string& path)
{
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 递归创建多级目录，等价于 mkdir -p；已存在视为成功
inline bool makeDirs(const std::string& path)
{
    if (path.empty())
    {
        return false;
    }

    std::string current;
    for (size_t pos = 0; pos <= path.size(); ++pos)
    {
        // Windows 同时接受 '/' 与 '\\' 作为分隔符
        if (pos == path.size() || path[pos] == '/' || path[pos] == '\\')
        {
            if (!current.empty())
            {
                // 跳过盘符本身（如 "C:"）
                bool isDrive = current.size() == 2 && current[1] == ':';
                if (!isDrive && _mkdir(current.c_str()) != 0 && errno != EEXIST)
                {
                    return false;
                }
            }
            if (pos < path.size())
            {
                current += path[pos];
            }
        }
        else
        {
            current += path[pos];
        }
    }
    return true;
}

// 递归删除目录及其内容，等价于 rm -rf；目标不存在也视为成功
inline void removeTree(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        return; // 不存在，无需删除
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
    {
        WIN32_FIND_DATAA findData;
        std::string      pattern = path + "\\*";
        HANDLE           hFind   = FindFirstFileA(pattern.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                std::string name = findData.cFileName;
                if (name == "." || name == "..")
                {
                    continue;
                }
                removeTree(path + "\\" + name);
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
        RemoveDirectoryA(path.c_str());
    }
    else
    {
        DeleteFileA(path.c_str());
    }
}
#else
// 文件（或目录）是否存在
inline bool fileExists(const std::string& path)
{
    struct stat buffer;
    return stat(path.c_str(), &buffer) == 0;
}

// 递归创建多级目录，等价于 mkdir -p；已存在视为成功
inline bool makeDirs(const std::string& path)
{
    if (path.empty())
    {
        return false;
    }

    std::string current;
    size_t      pos = 0;
    // 保留可能的前导 '/'，逐段创建
    if (path[0] == '/')
    {
        current = "/";
        pos     = 1;
    }

    while (pos <= path.size())
    {
        size_t slash = path.find('/', pos);
        if (slash == std::string::npos)
        {
            slash = path.size();
        }
        std::string segment = path.substr(pos, slash - pos);
        if (!segment.empty())
        {
            if (current.empty() || current == "/")
            {
                current += segment;
            }
            else
            {
                current += "/" + segment;
            }
            if (mkdir(current.c_str(), 0755) != 0 && errno != EEXIST)
            {
                return false;
            }
        }
        pos = slash + 1;
    }
    return true;
}

// 递归删除目录及其内容，等价于 rm -rf；目标不存在也视为成功
inline void removeTree(const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
    {
        return; // 不存在，无需删除
    }

    if (S_ISDIR(st.st_mode))
    {
        DIR* dir = opendir(path.c_str());
        if (dir)
        {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr)
            {
                std::string name = entry->d_name;
                if (name == "." || name == "..")
                {
                    continue;
                }
                removeTree(path + "/" + name);
            }
            closedir(dir);
        }
        rmdir(path.c_str());
    }
    else
    {
        unlink(path.c_str());
    }
}
#endif // _WIN32
} // namespace testfs

#endif
