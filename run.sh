#!/bin/bash

# 设置项目目录和构建目录
PROJECT_DIR=$(dirname "$(realpath $0)")
BUILD_DIR="${PROJECT_DIR}/build"
OUTPUT_DIR="${PROJECT_DIR}/output"

# 解析命令行参数 - 默认运行测试并忽略失败
RUN_TESTS=true
CLEAN_BUILD=true
IGNORE_TEST_FAILURES=true
SPECIFIC_TEST=""
SKIP_TESTS=false

# 处理命令行参数
for arg in "$@"
do
    case $arg in
        --no-clean)
        CLEAN_BUILD=false
        shift
        ;;
        --no-test)
        RUN_TESTS=false
        shift
        ;;
        --strict-test)
        IGNORE_TEST_FAILURES=false
        shift
        ;;
        --test=*)
        SPECIFIC_TEST="${arg#*=}"
        shift
        ;;
        --help)
        echo "用法: $0 [选项]"
        echo "选项:"
        echo "  --no-clean      不清理构建目录"
        echo "  --no-test       不运行测试"
        echo "  --strict-test   不忽略测试失败（失败时退出）"
        echo "  --test=<测试名称> 只运行指定的测试"
        echo "  --help          显示此帮助信息"
        echo ""
        echo "默认行为: 清理构建目录，运行所有测试，忽略测试失败"
        exit 0
        ;;
    esac
done

# 清理构建目录
if [ "$CLEAN_BUILD" = true ]; then
    echo "clean build..."
    rm -rf "${BUILD_DIR}"/*
fi

# 创建构建目录
echo "create build dir..."
mkdir -p "${BUILD_DIR}"

# 进入构建目录并执行CMake和Make
cd "${BUILD_DIR}"
echo "configure project..."
# CMake ≥ 4.0 会拒绝 vendored GLFW / googletest 里低于 3.5 的 cmake_minimum_required，
# 加 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 兼容之；旧版 CMake 忽略该变量，无副作用。
cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.5

echo "compile project..."
make

# 检查编译是否成功
if [ $? -ne 0 ]; then
    echo "compile failed, exit..."
    exit 1
fi

echo "compile success!"

# 如果指定了运行测试
if [ "$RUN_TESTS" = true ]; then
    echo "run unit tests..."
    cd "${PROJECT_DIR}"
    
    if [ -f "${OUTPUT_DIR}/unit_tests" ]; then
        # 准备测试命令
        TEST_CMD="${OUTPUT_DIR}/unit_tests"
        
        # 如果指定了特定测试，添加过滤参数
        if [ -n "$SPECIFIC_TEST" ]; then
            TEST_CMD="${TEST_CMD} --gtest_filter=${SPECIFIC_TEST}"
            echo "run specific test: ${SPECIFIC_TEST}"
        fi
        
        # 创建临时文件保存测试输出
        TEST_OUTPUT_FILE=$(mktemp)
        
        # 运行测试并保存输出
        ${TEST_CMD} | tee ${TEST_OUTPUT_FILE}
        TEST_RESULT=$?
        
        # 分析测试结果
        PASSED_TESTS=$(grep -o "\[  PASSED  \] [0-9]* test" ${TEST_OUTPUT_FILE} | grep -o "[0-9]*")
        FAILED_TESTS=$(grep -o "\[  FAILED  \] [0-9]* test" ${TEST_OUTPUT_FILE} | grep -o "[0-9]*")
        DISABLED_TESTS=$(grep -o "YOU HAVE [0-9]* DISABLED TESTS" ${TEST_OUTPUT_FILE} | grep -o "[0-9]*")
        
        # 如果没有找到数字，设置为0
        PASSED_TESTS=${PASSED_TESTS:-0}
        FAILED_TESTS=${FAILED_TESTS:-0}
        DISABLED_TESTS=${DISABLED_TESTS:-0}
        
        echo ""
        echo "test result summary:"
        echo "   passed: ${PASSED_TESTS} tests"
        echo "   failed: ${FAILED_TESTS} tests"
        if [ -n "$DISABLED_TESTS" ] && [ "$DISABLED_TESTS" -gt 0 ]; then
            echo "   disabled: ${DISABLED_TESTS} tests"
        fi
        
        # 清理临时文件
        rm -f ${TEST_OUTPUT_FILE}
        
        # 检查测试是否成功
        if [ $TEST_RESULT -ne 0 ]; then
            if [ "$IGNORE_TEST_FAILURES" = true ]; then
                echo "warning: some tests failed, but ignore test failure option is set, continue..."
            else
                echo "error: unit tests failed!"
                exit 1
            fi
        else
            echo "unit tests all passed!"
        fi
    else
        echo "warning: unit tests executable file not found, skip tests"
    fi
else
    echo "skip tests (use --no-test option)"
fi

echo "build success!"
exit 0
