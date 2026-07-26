#ifndef TEST_FS_UTIL_HPP
#define TEST_FS_UTIL_HPP

// 测试专用的文件系统辅助函数：全部走程序内 POSIX 调用，不再拼命令交给 /bin/sh，
// 从而避免测试 setup/teardown 依赖 shell（system("mkdir -p") / system("rm -rf")）。
// 函数声明为 inline，可安全被多个测试翻译单元包含而不违反 ODR。

#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace testfs
{
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
} // namespace testfs

#endif
