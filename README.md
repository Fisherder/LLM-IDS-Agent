# LLM-IDS-Agent: 基于大型语言模型智能体的网络入侵检测与自适应防御

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)

本项目是论文《基于Agent智能体的网络入侵检测与自适应防御》的官方代码实现。我们提出并实现了一种基于大型语言模型（LLM）的智能体（Agent）框架，旨在实现网络入侵检测的自动化与自适应防御。

---

## 📖 项目概述

随着网络攻击手法的日益复杂化与自动化，传统的网络入侵检测系统（IDS）和入侵防御系统（IPS）在响应速度、决策精度与可扩展性方面面临着前所未有的挑战。传统方法主要依赖静态的签名库和固定阈值，难以应对高级持续性威胁（APT）和零日攻击，且其僵化的决策逻辑易导致高误报率或漏报率。

为解决此问题，我们设计了`LLM-IDS-Agent`。本框架的核心是一种创新的**混合与联动分析（Hybrid and Correlated Analysis）**模型，它将LLM的强大推理能力与传统的网络流量分析技术相结合。Agent通过一个两阶段的智能研判流程来应对威胁：首先，在本地对网络流量进行高效的启发式分析以快速筛选；然后，针对可疑事件，通过调用工具主动关联主机层面的日志，实现多源异构情报的交叉验证。这种方法极大地提升了检测的准确性和对复杂、隐蔽攻击的发现能力。

## ✨ 核心特色

- **LLM驱动的智能决策**: 告别僵化的规则和阈值，利用大型语言模型的上下文理解和逻辑推理能力，对安全事件进行动态、智能的研判。
- **混合分析模型**: 将本地高效的启发式流量分析与LLM的深度分析相结合，兼顾了响应速度与决策精度。
- **联动分析机制**: 独创的“网络初筛 -> 主机详查”工作流程，能够关联网络层和主机层的异构数据源，精准识别在单一维度下难以发现的复杂攻击。
- **模块化与可扩展架构**: 系统由感知、决策、行动三大模块组成，易于扩展新的工具和检测能力。

## 🏛️ 系统架构

本系统在逻辑上是一个基于主机的、由云端智能驱动的自适应安全框架。核心的Agent程序部署在需要保护的主机上，负责执行“感知-决策-行动”的完整循环。

- **感知**: Agent通过`Scapy`实时监听本地网络接口，捕获流量并进行预处理和启发式分析。
- **决策**: 当发现潜在威胁时，Agent通过安全的API将结构化的上下文信息提交给远程的LLM服务（如DeepSeek）。
- **行动**: LLM进行深度推理后，将决策指令返回给Agent。Agent解析指令，并调用操作系统本地的工具（如UFW防火墙、日志读取器）来执行具体的防御动作或进行更深入的调查。

## 🚀 安装指南

### 1. 克隆仓库

```bash
git clone [https://github.com/your-username/LLM-IDS-Agent.git](https://github.com/your-username/LLM-IDS-Agent.git)
cd LLM-IDS-Agent
```

### 2. 创建并激活虚拟环境 (推荐)

```bash
python3 -m venv venv
source venv/bin/activate  # 在 Windows 上使用 `venv\Scripts\activate`
```

### 3. 安装依赖

本项目依赖于以下Python库。我们提供了一个`requirements.txt`文件以便快速安装。

```bash
pip install -r requirements.txt
```

`requirements.txt` 文件内容:

```

openai
scapy
netifaces
argparse

```

### 4. 配置API密钥

为了让Agent能够与大型语言模型交互，您需要配置API密钥。请将您的DeepSeek API密钥设置为环境变量。

在Linux或macOS上:

```bash
export DEEPSEEK_API_KEY="your_deepseek_api_key_here"
```

在Windows上:

```bash
set DEEPSEEK_API_KEY="your_deepseek_api_key_here"
```

**重要提示**: 请勿将您的API密钥硬编码到任何脚本中。

## 🛠️ 使用方法

我们提供了两种模式来运行和测试Agent。

### 模式一：离线分析 (使用数据集进行测试)

此模式用于分析`.pcap`流量文件，是复现我们论文档案和评估结果的主要方式。

1. **准备模拟日志**: 为了测试“联动分析”功能，您需要根据`.pcap`文件中的攻击场景，手动创建一个名为`simulated_auth.log`的模拟日志文件。例如，如果pcap中包含针对IP `192.168.1.100`的SSH攻击，您应在此文件中添加相应的失败登录记录。

2. **运行分析脚本**: 使用以下命令启动分析。

    ```bash
    python agent_v7_pcap_tester.py --file <pcap文件名> --ip <被保护主机的IP地址>
    ```

    **示例**:

    ```bash
    # 分析来自Maple-IDS数据集的DDoS攻击流量
    python agent_v7_pcap_tester.py --file ddos_tcp_udp_icmp_recoil_slowloic.pcap --ip 10.0.0.5
    ```

### 模式二：实时检测 (在真实环境中部署)

此模式将直接监听您主机的网络接口，进行实时入侵检测。

**警告**: 此模式会真实调用`sudo ufw`命令来修改防火墙规则，请在受控的测试环境中谨慎使用。

```bash
# 需要sudo权限以监听网络接口和修改防火墙
sudo python agent_v6_hybrid_analyst.py
```

您可能需要根据您的网络环境，修改`agent_v6_hybrid_analyst.py`脚本中的网络接口名称（默认为`ens33`）。

## 🔬 工作原理

本Agent的核心是其**混合与联动分析**工作流，该流程被编码在一个复杂的、多阶段的Prompt中，以指导LLM进行决策。

1. **混合分析 (Hybrid Analysis)**:
    - **感知模块**捕获流量后，不直接上报，而是先在本地进行高效的**启发式分析**，计算如`SYN/FIN比率`、`平均包大小`等关键指标。
    - 这些指标连同原始统计数据，被打包成一份结构化的**事件报告**。
    - **决策模块**将此报告提交给LLM，LLM能够结合原始数据和行为层面的启发式指标进行首次判断。这远比传统IPS依赖单一、僵化阈值的决策方式更为智能和精确。

2. **联动分析 (Correlated Analysis)**:
    - 当LLM在第一阶段判断情况**可疑但证据不足**时（例如，连接频率中等，但连接模式异常），它不会草率决策。
    - 此时，Prompt会引导LLM进入第二阶段，通过Function Calling请求调用`check_authentication_logs`工具。
    - **行动模块**执行该工具，从主机操作系统层面获取**认证失败日志**这一全新维度的情报。
    - 该情报被反馈给LLM，LLM在获得了网络和主机两个维度的证据后，进行最终的**交叉验证和综合裁决**，从而做出高置信度的决策。

## 🎓 如何引用

如果您在您的研究中使用了本项目的代码或思想，请引用我们的论文!

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源许可证。

## 🙏 致谢

- 本项目使用了 [DeepSeek](https://www.deepseek.com/) 提供的LLM API服务。
- 我们的量化评估实验方案基于 [Maple-IDS](https://maple.nefu.edu.cn/) 数据集进行设计，特此感谢其贡献者。

## 🔭 未来工作

我们计划从以下几个方面继续完善和扩展本项目：

- **增强感知能力**: 扩展对DNS、ICMP以及加密流量的检测能力。
- **引入长期记忆**: 利用向量数据库和RAG技术，使Agent能够从历史事件中学习。
- **发展多Agent协同**: 设计一个分布式的、由多个专长Agent协同工作的防御网络。
- **构建Web控制台**: 开发一个可视化的人机交互界面，以供管理员监控、审计和干预。

欢迎对本项目提出宝贵的意见和建议！
