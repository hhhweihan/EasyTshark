# EasyTshark - 网络数据包捕获与分析工具

- EasyTshark是一个基于tshark的网络数据包分析工具，提供实时抓包和离线分析功能，支持数据包的SQLite存储和XML/JSON格式转换。
- 糟糕，蹭了一波风哥流量；本项目是在风哥指导下完成的，目前是未完成版本；感兴趣的伙伴可以关注：[轩辕的编程宇宙](https://b23.tv/ANtGJ84)
- 觉得项目写的好的兄弟们，留下一个star作为鼓励~
- 告诉兄弟们一个好消息~ EasyTshark社区今天终于出来啦！
- ![朋友圈截图](images/X.jpg)
- 下载官网：https://www.easytshark.com/

## 功能特点

- **双模式操作**：
  - 实时抓包模式：直接从网络接口捕获数据包
  - 离线分析模式：分析已有的PCAP文件

- **数据存储**：
  - 将捕获的数据包存储到SQLite数据库
  - 支持数据包的快速查询和检索

- **格式转换**：
  - 将PCAP文件转换为XML格式
  - 将XML文件转换为JSON格式，便于前端展示

- **IP地理位置**：
  - 自动解析数据包中的IP地址地理位置信息

### 查询功能
- 支持Mac地址、IP地址、端口、归属地四类条件查询
- 支持将查询结果保存为JSON文件

## 系统要求

- Linux操作系统
- tshark (Wireshark命令行工具)
- SQLite3
- C++11兼容的编译器
- CMake 3.10+

## 依赖库

- sqlite3：数据存储
- loguru：日志记录
- rapidjson：JSON处理
- rapidxml：XML处理
- ip2region：IP地理位置解析

## 安装

1. 安装必要的依赖：

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake wireshark-dev libsqlite3-dev tshark ccache clang-format
```

2. 克隆仓库：

```bash
git clone git@github.com:hhhweihan/EasyTshark.git
cd EasyTshark
```

3. 编译项目：
- 脚本构建
```bash
# 默认构建（清理构建目录，编译项目，运行测试并忽略测试失败）
./run.sh

# 不清理构建目录
./run.sh --no-clean

# 不运行测试
./run.sh --no-test

# 严格测试模式（测试失败时退出）
./run.sh --strict-test

# 运行特定测试
./run.sh --test=TsharkManagerTest.ConvertXmlToJson

# 查看帮助信息
./run.sh --help
```

- 手动构建

```bash
mkdir -p build && cd build
cmake ..
make
```

## 使用方法

运行编译好的可执行文件：

```bash
./output/tshark_main
```

### 操作流程

1. 选择操作模式：
   - 输入`1`选择实时抓包模式
   - 输入`2`选择离线分析模式

2. 实时抓包模式：
   - 选择要监控的网卡
   - 设置抓包时间（秒）
   - 等待抓包完成

3. 离线分析模式：
   - 输入PCAP文件的完整路径
   - 系统会复制该文件到工作目录

4. 数据处理（自动进行）：
   - 创建SQLite数据库并存储数据包信息
   - 将PCAP文件转换为XML格式
   - 将XML文件转换为JSON格式

5. 输出文件位于`data`目录：
   - `capture.pcap`：捕获的数据包文件
   - `packets.db`：SQLite数据库文件
   - `packets.xml`：XML格式的数据包信息
   - `packets.json`：JSON格式的数据包信息

## 单元测试

项目使用Google Test框架进行单元测试，测试覆盖了核心功能和边缘情况。

### 测试套件

1. **TsharkManagerTest**：测试数据包管理器的基本功能
   - 构造函数测试
   - 网卡列表获取测试
   - XML/JSON转换测试
   - 离线分析功能测试
   - 文件格式转换测试

2. **SQLiteUtilTest**：测试SQLite数据库操作
   - 数据库创建测试
   - 数据包插入测试
   - 数据包查询测试

3. **CommonUtilTest**：测试通用工具函数
   - 时间戳生成测试
   - 字符串处理测试

4. **ProcessUtilTest**：测试进程操作工具
   - 进程执行测试
   - 管道通信测试
   - 进程终止测试

5. **DataConversionTest**：测试数据格式转换
   - PCAP到XML转换测试
   - XML到JSON转换测试
   - 节点转换测试

6. **ErrorHandlingTest**：测试错误处理机制
   - 无效文件处理测试
   - 格式错误处理测试
   - 权限问题处理测试

7. **IP2RegionUtilTest**：测试IP地理位置解析
   - 公网IP解析测试
   - 内网IP解析测试
   - 无效IP处理测试

8. **IntegrationTest**：集成测试
   - 完整离线分析工作流测试

### 运行测试

可以通过以下方式运行测试：

```bash
# 运行所有测试
./output/unit_tests

# 运行特定测试套件
./output/unit_tests --gtest_filter=TsharkManagerTest.*

# 运行特定测试
./output/unit_tests --gtest_filter=TsharkManagerTest.ConvertXmlToJson

# 生成XML格式的测试报告
./output/unit_tests --gtest_output=xml:test_report.xml
```

### 添加测试数据

某些测试需要测试数据才能运行，可以通过以下方式准备：

1. 创建测试数据目录：
```bash
mkdir -p test_data
```

2. 添加测试PCAP文件：
```bash
# 可以使用tshark生成测试PCAP文件
tshark -c 10 -w test_data/test.pcap
```

3. 确保IP2Region数据库文件可用：
```bash
# 默认路径为resources/ip2region.xdb
# 如果没有，测试会自动跳过相关测试
```

## 项目结构

```
.
├── CMakeLists.txt # CMake构建配置
├── .clang-format # 代码格式化规范
├── LICENSE # MIT许可证
├── run.sh # 构建和测试脚本
├── .vscode/ # VSCode配置文件
│ └── c_cpp_properties.json # C/C++扩展配置
├── include/ # 头文件目录
│ ├── tsharkDataType.hpp # 数据类型定义
│ ├── tsharkManager.hpp # 数据包管理器
│ └── utils.hpp # 工具函数
├── src/ # 源文件目录
│ ├── main.cpp # 主程序入口
│ ├── tsharkManager.cpp # 数据包管理器实现
│ └── utils.cpp # 工具函数实现
├── tests/ # 单元测试目录
│ ├── CMakeLists.txt # 测试构建配置
│ ├── test_tsharkManager.cpp # 基本功能测试
│ ├── test_data_conversion.cpp # 数据转换测试
│ ├── test_error_handling.cpp # 错误处理测试
│ ├── test_performance.cpp # 性能测试
│ ├── test_offline_analysis.cpp # 离线分析测试
│ └── test_utils.cpp # 工具函数测试
├── data/ # 数据输出目录
│ ├── packets.xml # XML格式的数据包
│ └── packets.json # JSON格式的数据包
└── logs/ # 日志目录
```

## 许可证

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

本项目采用MIT开源许可证，允许自由使用、修改和分发代码。使用本项目的代码时需满足：
- 在副本中保留原始版权声明
- 不得使用项目作者的名义进行背书

完整条款请参见[LICENSE文件](./LICENSE)。
