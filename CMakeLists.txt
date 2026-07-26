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
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/output")

file(COPY ${CMAKE_SOURCE_DIR}/resources DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# 启用测试
enable_testing()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(LIB_SOURCES
    include/loguru/loguru.cpp
    src/utils.cpp
    src/tsharkCommand.cpp
    src/PacketParser.cpp
    src/PcapFileReader.cpp
    src/PcapAnalyzer.cpp
    src/AnalysisSession.cpp
    src/LiveCapture.cpp
    src/FlowMonitor.cpp
    src/PdmlToJsonConverter.cpp
    src/xdb_bench.cc
    src/xdb_search.cc
    src/processUtil.cpp
    src/platform/EventPollerPoll.cpp
)

add_library(tshark_lib STATIC ${LIB_SOURCES})

# 平台相关链接库：
#   - macOS: dlopen 在 libSystem 内，无独立 libdl；字符集转换需 libiconv
#   - Linux: libdl 提供 dlopen（loguru 需要），无需 iconv
#   - Windows: 无 pthread/dl；sqlite3 非系统库需自带；套接字用 ws2_32
if(APPLE)
    target_link_libraries(tshark_lib pthread sqlite3 iconv)
elseif(WIN32)
    # TODO(Windows 移植 / 主题 1 二期)：以下为占位，尚未在 Windows 上验证。
    #   1. sqlite3 在 Windows 非系统库——需 vendored 一份（sqlite amalgamation）后再链接；
    #   2. WSAPoll / 套接字 需 ws2_32；进程创建改 CreateProcess（见 processUtil.cpp）；
    #   3. pthread / dl 在 MSVC 下不存在，已从链接列表移除（std::thread 走 CRT）。
    target_link_libraries(tshark_lib ws2_32)
    message(WARNING "Windows 平台链接配置为占位，sqlite3 等依赖尚未就绪，暂不保证可构建")
else()
    target_link_libraries(tshark_lib pthread dl sqlite3)
endif()

# 主可执行文件
add_executable(tshark_main src/main.cpp)
target_link_libraries(tshark_main tshark_lib)

# ---- ImGui 原生前端（主题 10）----
# GLFW 与 Dear ImGui 以 vendored 源码形式放在 include/ 下（与 rapidjson / rapidxml /
# ip2region 相同约定：第三方库放 include/<名字>/），随项目一起编译，首次 clone 后即可
# 离线构建。若 include/glfw 未就位（未 clone），跳过 GUI 目标，保证 CLI / 测试仍可独立构建。
set(EASYTSHARK_GLFW_DIR "${CMAKE_SOURCE_DIR}/include/glfw")
set(EASYTSHARK_IMGUI_DIR "${CMAKE_SOURCE_DIR}/include/imgui")
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
else()
    message(STATUS "include/glfw 或 include/imgui 未就位，跳过 GUI 目标 tshark_gui")
endif()

# 添加测试子目录
add_subdirectory(tests)