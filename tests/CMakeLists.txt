set(TEST_SOURCES
    test_tsharkManager.cpp
    test_utils.cpp
    test_data_conversion.cpp
    test_error_handling.cpp
    test_performance.cpp
    test_offline_analysis.cpp
    test_packet_parser.cpp
)

# 下载并包含GoogleTest源码
set(GOOGLETEST_ROOT ${CMAKE_CURRENT_BINARY_DIR}/googletest-src)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt.in
    ${CMAKE_CURRENT_BINARY_DIR}/googletest-download/CMakeLists.txt
)
execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download
)
execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download
)

# 添加GoogleTest作为子目录
# MSVC：googletest 默认用静态 CRT(/MT)，而本工程用动态 CRT(/MD)，两者混链会触发
# LNK2038(RuntimeLibrary 不匹配)。强制 googletest 也用动态 CRT 以对齐。该变量仅 MSVC
# 生效，POSIX(Linux/macOS)无 CRT 之分，行为不变。
if(MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()
add_subdirectory(
    ${GOOGLETEST_ROOT}
    ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
    EXCLUDE_FROM_ALL
)

# 添加测试可执行文件
add_executable(unit_tests ${TEST_SOURCES})

# 包含GoogleTest头文件
target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${GOOGLETEST_ROOT}/googletest/include
    ${GOOGLETEST_ROOT}/googlemock/include
)

# 链接GoogleTest和项目库
target_link_libraries(unit_tests
    gtest
    gtest_main
    gmock
    gmock_main
    tshark_lib
)

# 平台相关链接（与顶层 CMakeLists.txt 保持一致）：
#   - macOS: pthread（dlopen 在 libSystem 内，无独立 libdl）
#   - Linux: pthread + dl
#   - Windows: 无 pthread/dl（std::thread 走 CRT）；套接字用 ws2_32，随 tshark_lib 传递
if(APPLE)
    target_link_libraries(unit_tests pthread)
elseif(WIN32)
    # Windows 下无需 pthread/dl；ws2_32 已由 tshark_lib 传递链接
else()
    target_link_libraries(unit_tests pthread dl)
endif()

# 中文注释源码：MSVC 需 /utf-8，否则按 GBK/936 解析报 C4819/C2xxx（与顶层一致）
if(MSVC)
    target_compile_options(unit_tests PRIVATE /utf-8)
endif()

# 添加测试
add_test(NAME unit_tests COMMAND unit_tests) 