cmake_minimum_required(VERSION 3.10)

# 启用编译缓存（仅当系统装有 ccache 时；macOS 等环境未必安装，避免直接报错）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

project(EasyTshark_xuanyuan VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
# 关闭编译器 GNU 扩展：用严格 -std=c++11 而非 -std=gnu++11，真正锁死 C++11 目标
# （本项目刻意固定 C++11，贴合保守工具链），让误用的 GNU/更高标准构造在本机就暴露。
set(CMAKE_CXX_EXTENSIONS OFF)

# 单 config 生成器（Makefile/Ninja）在未指定 CMAKE_BUILD_TYPE 时，编译标志为空
# ——即 -O0 无优化。解析引擎是纯计算热点，-O0→-O2 通常有数倍差距，故给个默认值。
# 多 config 生成器（Visual Studio / Xcode）由 --config 决定，带 CMAKE_CONFIGURATION_TYPES，
# 此处不覆盖它们。用户仍可用 -DCMAKE_BUILD_TYPE=Debug 显式改回。
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型（默认 Release）" FORCE)
endif()
# 产物输出目录：默认 output/（源码树内，脚本/README 的约定路径）；
# 需要 out-of-source 干净构建时可 -DEASYTSHARK_OUTPUT_DIR=/path 覆盖。
set(EASYTSHARK_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/output" CACHE PATH
    "构建产物输出目录（默认源码树内 output/）")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${EASYTSHARK_OUTPUT_DIR}")

file(COPY ${CMAKE_SOURCE_DIR}/resources DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Web 前端的静态资源（HTML/JS/CSS）随产物一起放到 output/web，供 tshark_web 托管。
# 仅当 web/ 目录存在时复制，避免裁剪掉前端时报错。
if(EXISTS "${CMAKE_SOURCE_DIR}/web")
    file(COPY ${CMAKE_SOURCE_DIR}/web DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
endif()

# 启用测试
enable_testing()

# 第一方头文件放 include/；vendored 第三方库统一放 third_party/，两者都加入搜索路径。
# 这样 #include "loguru/..." / "rapidjson/..." / "ip2region/..." 无需改动即可解析，
# 同时从目录结构上一眼区分“自己的代码”与“外部依赖”。
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party)

set(LIB_SOURCES
    third_party/loguru/loguru.cpp
    src/utils.cpp
    src/tsharkCommand.cpp
    src/PacketParser.cpp
    src/PcapFileReader.cpp
    src/PcapAnalyzer.cpp
    src/AnalysisSession.cpp
    src/LiveCapture.cpp
    src/FlowMonitor.cpp
    src/PdmlToJsonConverter.cpp
    src/NativePacketParser.cpp
    src/NativeAnalyzer.cpp
    src/NativeCapture.cpp
    src/xdb_search.cc
    src/processUtil.cpp
    src/ProcessResolver.cpp
    src/web/WebServer.cpp
)

# I/O 多路复用 + 非阻塞管道读取：按平台二选一，接口一致，业务代码平台无关。
#   - 非 Windows(Linux/macOS)：poll + fcntl(O_NONBLOCK)+read（原实现，逐字节等价抽出）
#   - Windows：PeekNamedPipe 轮询 + ReadFile（匿名管道不支持套接字 poll / fd 级非阻塞）
if(WIN32)
    list(APPEND LIB_SOURCES
        src/platform/EventPollerWin.cpp
        src/platform/PipeIOWin.cpp
    )
else()
    list(APPEND LIB_SOURCES
        src/platform/EventPollerPoll.cpp
        src/platform/PipeIOPosix.cpp
    )
endif()

# Windows 无系统 sqlite3：并入 vendored amalgamation（third_party/sqlite3/sqlite3.c）一起编译。
# macOS / Linux 继续链接系统 sqlite3，行为不变。
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/third_party/sqlite3/sqlite3.c")
    enable_language(C) # 项目本体是 CXX-only；sqlite3.c 需要 C 编译器（仅 Windows 触发）
    list(APPEND LIB_SOURCES third_party/sqlite3/sqlite3.c)
endif()

add_library(tshark_lib STATIC ${LIB_SOURCES})

# 中文注释源码：MSVC 默认按本地代码页(GBK/936)解析，会把 UTF-8 中文误读导致 C4819/C2xxx。
# 强制 /utf-8 让 MSVC 按 UTF-8 读源码。GCC/Clang 默认即 UTF-8，无需处理。
if(MSVC)
    target_compile_options(tshark_lib PRIVATE /utf-8)
    # vendored sqlite3.c 的头文件位置
    target_include_directories(tshark_lib PRIVATE ${CMAKE_SOURCE_DIR}/third_party/sqlite3)
endif()

# 平台相关链接库：
#   - macOS: dlopen 在 libSystem 内，无独立 libdl；字符集转换需 libiconv
#   - Linux: libdl 提供 dlopen（loguru 需要），无需 iconv
#   - Windows: 无 pthread/dl；sqlite3 非系统库需自带；套接字用 ws2_32
if(APPLE)
    # iconv 依赖随死代码 UTF8ToANSIString 一并移除；macOS 仅需 pthread + 系统 sqlite3。
    target_link_libraries(tshark_lib pthread sqlite3)
elseif(WIN32)
    # Windows：sqlite3 以 vendored 源码(third_party/sqlite3/sqlite3.c)并入编译，无需外链；
    # 套接字用 ws2_32；pthread/dl 在 MSVC 下不存在（std::thread 走 CRT），无需链接。
    target_link_libraries(tshark_lib ws2_32)
else()
    target_link_libraries(tshark_lib pthread dl sqlite3)
endif()

# 自研引擎的实时抓包依赖 libpcap（BSD 许可）：macOS 系统自带；Linux 需 libpcap-dev；
# Windows 需 Npcap SDK。找不到时编译仍通过——NativeCapture 退化为“无法抓包”，
# 离线解析（NativeAnalyzer）不依赖 libpcap，始终可用。
find_library(PCAP_LIBRARY NAMES pcap)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
    target_compile_definitions(tshark_lib PUBLIC EASYTSHARK_HAVE_LIBPCAP=1)
    target_include_directories(tshark_lib PUBLIC ${PCAP_INCLUDE_DIR})
    # 注意：tshark_lib 已用 plain signature 链接过系统库，这里保持 plain（不写 PUBLIC 关键字）
    target_link_libraries(tshark_lib ${PCAP_LIBRARY})
    message(STATUS "libpcap 已找到：${PCAP_LIBRARY}（自研实时抓包可用）")
else()
    message(STATUS "libpcap 未找到：实时抓包仅 tshark 路径可用；离线解析不受影响")
endif()

# 主可执行文件
add_executable(tshark_main src/main.cpp)
target_link_libraries(tshark_main tshark_lib)
if(MSVC)
    target_compile_options(tshark_main PRIVATE /utf-8) # main.cpp 含中文注释
endif()

# ---- ImGui 原生前端（主题 10）----
# GLFW 与 Dear ImGui 以 vendored 源码形式放在 third_party/ 下（与 rapidjson / rapidxml /
# ip2region 相同约定：第三方库放 third_party/<名字>/），随项目一起编译，首次 clone 后即可
# 离线构建。若 third_party/glfw 未就位（未 clone），跳过 GUI 目标，保证 CLI / 测试仍可独立构建。
set(EASYTSHARK_GLFW_DIR "${CMAKE_SOURCE_DIR}/third_party/glfw")
set(EASYTSHARK_IMGUI_DIR "${CMAKE_SOURCE_DIR}/third_party/imgui")
if(EXISTS "${EASYTSHARK_GLFW_DIR}/CMakeLists.txt" AND EXISTS "${EASYTSHARK_IMGUI_DIR}/imgui.cpp")
    # 只编 GLFW 库本身，关掉它的文档 / 测试 / 示例
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(${EASYTSHARK_GLFW_DIR} ${CMAKE_BINARY_DIR}/glfw-build EXCLUDE_FROM_ALL)

    # Dear ImGui + GLFW/OpenGL3 后端编成一个静态库
    add_library(imgui STATIC
        ${EASYTSHARK_IMGUI_DIR}/imgui.cpp
        ${EASYTSHARK_IMGUI_DIR}/imgui_draw.cpp
        ${EASYTSHARK_IMGUI_DIR}/imgui_tables.cpp
        ${EASYTSHARK_IMGUI_DIR}/imgui_widgets.cpp
        ${EASYTSHARK_IMGUI_DIR}/imgui_demo.cpp
        ${EASYTSHARK_IMGUI_DIR}/backends/imgui_impl_glfw.cpp
        ${EASYTSHARK_IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    )
    target_include_directories(imgui PUBLIC
        ${EASYTSHARK_IMGUI_DIR}
        ${EASYTSHARK_IMGUI_DIR}/backends
    )
    target_link_libraries(imgui PUBLIC glfw)
    if(APPLE)
        # macOS 的 OpenGL 已标记弃用（转向 Metal），仍可用；静默弃用告警。
        target_compile_definitions(imgui PUBLIC GL_SILENCE_DEPRECATION)
        target_link_libraries(imgui PUBLIC "-framework OpenGL")
    else()
        find_package(OpenGL REQUIRED)
        target_link_libraries(imgui PUBLIC OpenGL::GL)
    endif()

    add_executable(tshark_gui src/gui/main_gui.cpp)
    target_link_libraries(tshark_gui tshark_lib imgui)
    if(MSVC)
        target_compile_options(tshark_gui PRIVATE /utf-8)
        # GUI 程序默认属"控制台子系统"，启动时会额外弹出一个黑色命令行窗口。改成 Windows
        # 子系统即可隐藏它；用 /ENTRY:mainCRTStartup 保留标准 int main() 入口，无需改写成
        # WinMain。仅 MSVC/Windows 生效，不影响 macOS/Linux 的 GUI 目标。
        set_target_properties(tshark_gui PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
    elseif(MINGW)
        # MinGW 下用 -mwindows 达到同样效果（不弹控制台窗口）。
        set_target_properties(tshark_gui PROPERTIES LINK_FLAGS "-mwindows")
    endif()
else()
    message(STATUS "third_party/glfw 或 third_party/imgui 未就位，跳过 GUI 目标 tshark_gui")
endif()

# ---- Web 前端（第三个前端：headless 服务器 + 浏览器远程访问）----
# 以 cpp-httplib（vendored 单头文件 third_party/httplib/httplib.h）实现一个 HTTP 服务：
# 对外暴露 REST/JSON API + 托管 web/ 静态前端。核心逻辑仍全在 AnalysisSession 门面里，
# 本目标只是第三个薄入口（与 CLI/GUI 并列）。httplib 未就位时跳过，保证其余目标可独立构建。
# httplib 依赖：posix 需 pthread、Windows 需 ws2_32——两者都已在 tshark_lib 链接，无需重复。
set(EASYTSHARK_HTTPLIB "${CMAKE_SOURCE_DIR}/third_party/httplib/httplib.h")
if(EXISTS "${EASYTSHARK_HTTPLIB}")
    add_executable(tshark_web src/web/main_web.cpp)
    target_link_libraries(tshark_web tshark_lib)
    if(MSVC)
        target_compile_options(tshark_web PRIVATE /utf-8) # main_web.cpp 含中文注释
    endif()
else()
    message(STATUS "third_party/httplib 未就位，跳过 Web 目标 tshark_web")
endif()

# 添加测试子目录
add_subdirectory(tests)