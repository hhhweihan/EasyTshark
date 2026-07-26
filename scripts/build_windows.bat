@echo off
REM ============================================================================
REM EasyTshark Windows 构建脚本（MSVC + Ninja）
REM
REM 前置依赖：
REM   1. Visual Studio 2022 Build Tools（含 C++ 工作负载与 Windows SDK）
REM      默认路径：C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
REM      Build Tools 自带 CMake 与 Ninja，无需单独安装。
REM   2. Wireshark（提供 tshark.exe / editcap.exe），默认装在 C:\Program Files\Wireshark
REM      —— 仅运行时需要，编译不需要。
REM
REM 用法（在普通 cmd 或资源管理器双击均可）：
REM   scripts\build_windows.bat            构建 CLI + GUI（Release）
REM   scripts\build_windows.bat Debug      指定 Debug
REM
REM 产物输出到 output\tshark_main.exe 与 output\tshark_gui.exe
REM ============================================================================
setlocal

set "BUILD_TYPE=%~1"
if "%BUILD_TYPE%"=="" set "BUILD_TYPE=Release"

REM 允许通过环境变量覆盖 VS 安装路径（如装在非默认盘符）
if "%VSBUILDTOOLS%"=="" set "VSBUILDTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

set "VCVARS=%VSBUILDTOOLS%\VC\Auxiliary\Build\vcvars64.bat"
set "CMAKE=%VSBUILDTOOLS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJADIR=%VSBUILDTOOLS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"

if not exist "%VCVARS%" (
    echo [错误] 未找到 vcvars64.bat：%VCVARS%
    echo         请安装 VS 2022 Build Tools，或设置环境变量 VSBUILDTOOLS 指向其根目录。
    exit /b 1
)

echo [1/3] 初始化 MSVC 环境 ...
call "%VCVARS%" || exit /b 1
set "PATH=%NINJADIR%;%PATH%"

echo [2/3] CMake 配置（%BUILD_TYPE%）...
"%CMAKE%" -S "%~dp0.." -B "%~dp0..\build_win" -G Ninja ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_MAKE_PROGRAM="%NINJADIR%\ninja.exe" || exit /b 1

echo [3/3] 编译 ...
"%CMAKE%" --build "%~dp0..\build_win" -j || exit /b 1

echo.
echo 构建完成：output\tshark_main.exe / output\tshark_gui.exe
