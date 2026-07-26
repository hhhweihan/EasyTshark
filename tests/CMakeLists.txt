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
    pthread
)
# libdl 仅 Linux 需要（macOS 的 dlopen 在 libSystem 内，无独立 libdl）
if(NOT APPLE)
    target_link_libraries(unit_tests dl)
endif()

# 添加测试
add_test(NAME unit_tests COMMAND unit_tests) 