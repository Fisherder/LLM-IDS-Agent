# agent_hybrid_analyst.py
import os
import json
import time
import subprocess
from openai import OpenAI
from scapy.all import sniff, IP, TCP
from scapy.layers.http import HTTPRequest
from collections import defaultdict
import netifaces # 用于获取本机IP

# --- 0. 全局变量定义 ---
PVM_IP_ADDRESS = None # 将在主程序中初始化

# --- 1. DeepSeek API客户端初始化 ---
# DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_KEY = "sk-*******************************" # 仅为测试，请替换为环境变量或更安全的方式
if not DEEPSEEK_API_KEY:
    raise ValueError("请设置 DEEPSEEK_API_KEY 环境变量。")

client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com",
)
MODEL_NAME = "deepseek-chat"

# --- 2. 工具定义 (供LLM使用) ---
tools = [
    {
        "type": "function",
        "function": {
            "name": "block_ip_address",
            "description": "通过本地防火墙 (UFW) 封禁给定的IP地址。这是一个关键操作，仅在高度确信存在恶意行为时调用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "需要封禁的IP地址。"},
                    "reason": {"type": "string", "description": "封禁此IP地址的原因。"},
                },
                "required": ["ip_address", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "prepare_admin_notification",
            "description": "准备一条通知给管理员，内容包括可疑活动、源IP、相关详情以及LLM的评估。",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "需要通知管理员的可疑IP地址。"},
                    "event_details": {"type": "object", "description": "观察到的攻击活动的摘要。"},
                    "llm_recommendation": {"type": "string", "description": "LLM对管理员的简短建议或评估。"},
                },
                "required": ["ip_address", "event_details", "llm_recommendation"],
            },
        },
    }
]

# --- 3. 工具的本地Python实现 ---
def block_ip_address_impl(ip_address: str, reason: str = "Malicious activity detected by Agent"):
    """使用UFW封禁给定的IP地址，并将规则插入到最前面。"""
    try:
        print(f"[AGENT ACTION] 尝试封禁 IP: {ip_address}，原因: {reason}")
        subprocess.run(["sudo", "ufw", "insert", "1", "deny", "from", ip_address, "to", "any"], check=True)
        log_message = f"成功封禁 IP: {ip_address}. 原因: {reason}"
        print(log_message)
        return json.dumps({"status": "success", "action_taken": "ip_blocked", "ip_address": ip_address, "message": log_message})
    except subprocess.CalledProcessError as e:
        error_message = f"封禁 IP: {ip_address} 失败. UFW命令错误: {e}"
        print(error_message)
        return json.dumps({"status": "error", "action_taken": "ip_block_failed", "ip_address": ip_address, "message": error_message})
    except Exception as e:
        error_message = f"封禁 IP: {ip_address} 时发生意外错误: {e}"
        print(error_message)
        return json.dumps({"status": "error", "action_taken": "ip_block_failed", "ip_address": ip_address, "message": error_message})

def prepare_admin_notification_impl(ip_address: str, event_details: dict, llm_recommendation: str):
    """准备管理员通知并记录到文件。"""
    notification_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip_address,
        "event_details": event_details,
        "llm_recommendation": llm_recommendation,
        "status_for_console": "pending_admin_review"
    }
    print(f"[AGENT ACTION] [管理员通知已准备] IP: {ip_address}, 详情: {json.dumps(event_details)}, LLM建议: {llm_recommendation}")
    try:
        with open("pending_reviews.json", "a") as f:
            f.write(json.dumps(notification_data) + "\n")
        print("[AGENT ACTION] 通知已记录到 pending_reviews.json")
    except Exception as e:
        print(f"[AGENT ACTION] 记录通知到文件失败: {e}")
    return json.dumps({"status": "success", "action_taken": "admin_notification_prepared", "data": notification_data})

available_tool_implementations = {
    "block_ip_address": block_ip_address_impl,
    "prepare_admin_notification": prepare_admin_notification_impl,
}

# --- 4. LLM交互逻辑 ---
def execute_tool_call(tool_call):
    """执行LLM请求的工具调用"""
    function_name = tool_call.function.name
    function_args_str = tool_call.function.arguments
    try:
        function_args = json.loads(function_args_str)
    except json.JSONDecodeError:
        error_msg = f"工具 {function_name} 的参数不是有效的JSON: {function_args_str}"
        print(f"[AGENT ERROR] {error_msg}")
        return json.dumps({"status": "error", "message": error_msg})

    if function_name in available_tool_implementations:
        tool_implementation = available_tool_implementations[function_name]
        print(f"[AGENT] 即将执行工具: {function_name}，参数: {function_args}")
        try:
            result_str = tool_implementation(**function_args)
            return result_str if isinstance(result_str, str) else json.dumps(result_str)
        except TypeError as te:
            error_msg = f"调用工具 {function_name} 时参数不匹配: {te}. 提供的参数: {function_args}"
            print(f"[AGENT ERROR] {error_msg}")
            return json.dumps({"status": "error", "message": error_msg})
        except Exception as e:
            error_msg = f"执行工具 {function_name} 时发生错误: {e}"
            print(f"[AGENT ERROR] {error_msg}")
            return json.dumps({"status": "error", "message": error_msg})
    else:
        error_msg = f"请求了未知的工具: {function_name}"
        print(f"[AGENT ERROR] {error_msg}")
        return json.dumps({"status": "error", "message": error_msg})

def handle_llm_interaction(initial_prompt_content: str):
    """管理与LLM的多轮对话，处理工具调用"""
    messages = [{"role": "user", "content": initial_prompt_content}]
    
    print(f"\n--- LLM交互开始 ---")
    # 为了简洁，只打印部分Prompt
    print(f"用户 (初始Prompt)>\t{initial_prompt_content[:300].replace(os.linesep, ' ')}...")

    MAX_TURNS = 5 
    for turn in range(MAX_TURNS):
        print(f"\n[LLM Turn {turn + 1}]")
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                tools=tools,
                tool_choice="auto" 
            )
            response_message = response.choices[0].message
            messages.append(response_message)

            if response_message.tool_calls:
                print(f"LLM (请求工具调用)>\t{[tc.function.name for tc in response_message.tool_calls]}")
                
                tool_messages_for_next_turn = []
                for tool_call in response_message.tool_calls:
                    tool_execution_result_str = execute_tool_call(tool_call)
                    print(f"Agent (工具执行结果)>\t{tool_call.function.name} result: {tool_execution_result_str[:200]}...")
                    tool_messages_for_next_turn.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_call.function.name,
                        "content": tool_execution_result_str
                    })
                
                messages.extend(tool_messages_for_next_turn)
            else:
                print(f"LLM (最终回复)>\t{response_message.content}")
                break 
        except Exception as e:
            print(f"[LLM交互错误] 发生错误: {e}")
            break 
    print("--- LLM交互结束 ---")

# --- 5. 感知层与Prompt编写 ---

ssh_observation_windows = {} 
SSH_OBSERVATION_PERIOD = 30  # 秒, 固定观察窗口时长

def generate_waf_prompt(source_ip, http_request_details_dict):
    """为Web攻击分析场景生成特定的Prompt。"""
    details_str = json.dumps(http_request_details_dict, indent=2)
    prompt = f"""
# 角色扮演
你是一名经验丰富的网络安全专家，尤其擅长Web应用防火墙（WAF）的分析。你的任务是分析以下HTTP请求的关键信息，判断它是否包含恶意攻击的企图。

# 上下文信息
- 攻击源IP: {source_ip}
- 捕获到的HTTP请求详情:
{details_str}

# 决策树与指令
请分析该请求信息（特别是'path_and_query'和'user_agent'字段）是否存在SQL注入、XSS、命令注入、路径遍历等攻击特征，或User-Agent是否异常。
根据你的分析，做出决策：
- 如果你**高度确信**这是一个恶意攻击请求，请调用 `block_ip_address` 工具来立即阻止该源IP。
- 如果你**怀疑**这是一个潜在的威胁，但不确定，请调用 `prepare_admin_notification` 工具，让管理员审核。
- 如果你认为这是一个**正常的、安全的**请求，则无需调用任何工具，直接以自然语言回复你的结论即可。
"""
    return prompt

def generate_ssh_activity_summary_prompt(remote_ip, event_summary):
    """为SSH活动固定观察窗口总结生成Prompt（混合分析版）"""
    summary_str = json.dumps(event_summary, indent=2)
    syn_attempts = event_summary.get("incoming_syn_to_pvm_ssh", 0)
    
    urgency_statement = ""
    if syn_attempts >= 10:
        urgency_statement = "警告：在本观察窗口内检测到极高频率的SSH连接尝试，强烈疑似自动化暴力破解攻击。"

    return f"""
# 角色扮演
你是一名高级网络安全AI分析师。你的搭档（一个自动化的流量探针）已经完成了一轮初步的流量嗅探和启发式分析。你的任务是基于探针提供的硬数据和你的安全知识，做出最终的决策。

# 流量探针的事件报告
- 来源IP: {remote_ip}
- **本轮 {SSH_OBSERVATION_PERIOD} 秒观察窗口的统计数据**:
{summary_str}

# 探针提供的启发式分析解读 (Heuristic Analysis Insights)
- `heuristic_syn_fin_ratio` (SYN/FIN比率): 这个值衡量了连接建立尝试（SYN）与正常连接关闭（FIN）的比例。一个**远大于1.0**的比率（例如 > 5.0）强烈暗示着大量的连接请求未能正常完成，这是暴力破解的典型特征。
- `heuristic_avg_packet_size_bytes` (平均包大小): 自动化攻击工具通常使用大小一致的小数据包来发起连接。一个**持续较低**的平均包大小（例如 < 100字节）可能是一个辅助判断的指标。

{urgency_statement}

# 行动指令 (Action Directives)
请你结合**原始数据**（如 `incoming_syn_to_pvm_ssh`）和**启发式分析指标**（如 `heuristic_syn_fin_ratio`），进行综合判断：

1.  如果 `incoming_syn_to_pvm_ssh` 计数**超过 10 次** 并且 `heuristic_syn_fin_ratio` **显著地高**（例如 > 5.0），这提供了**极强的证据**表明正在发生暴力破解攻击。在这种情况下：
    a. **首要行动**: 调用 `block_ip_address` 工具，原因为 "检测到高强度SSH暴力破解活动（高SYN计数和高SYN/FIN比率）"。
    b. **次要行动**: 在调用 `block_ip_address` 后，再调用 `prepare_admin_notification` 工具，报告已执行的封禁和事件详情。

2.  如果计数或比率未达到上述极端水平，但组合起来仍然可疑（例如，SYN计数在5-9次之间，且SYN/FIN比率 > 2.0），则认为这是潜在威胁，需要人工审核。在这种情况下：
    a. 调用 `prepare_admin_notification` 工具，并在建议中**明确指出你的判断依据**（例如，“中等频率的SYN尝试，且连接未正常关闭，SYN/FIN比率较高”）。

3.  如果数据看起来正常（例如，低SYN计数，SYN/FIN比率接近1），则以自然语言回复你的良性判断，无需调用工具。

请基于上述综合分析，果断采取行动。"""

def process_packet(packet):
    """总调度函数，根据数据包类型分发给不同的处理逻辑。"""
    global ssh_observation_windows, PVM_IP_ADDRESS 
    current_time = time.time()

    # --- 首先处理已到期的SSH观察窗口 ---
    expired_ips = []
    for ip, data in list(ssh_observation_windows.items()): 
        if current_time - data['start_time'] >= SSH_OBSERVATION_PERIOD:
            print(f"\n[SSH OBSERVE END] IP {ip} 的 {SSH_OBSERVATION_PERIOD}秒观察窗口结束。正在汇总信息...")
            
            # 创建基础的事件摘要
            event_summary = {
                "type": "SSH Activity Summary",
                "observation_period_seconds": SSH_OBSERVATION_PERIOD,
                "total_ssh_packets_observed": data['total_packets'],
                "incoming_syn_to_pvm_ssh": data['syn_to_pvm_ssh'],
                "fin_packets_observed": data['fin_observed'],
                "rst_packets_observed": data['rst_observed'],
            }
            
            total_packets = data['total_packets']
            total_bytes = data['total_bytes']
            syn_count = data['syn_to_pvm_ssh']
            fin_count = data['fin_observed']

            # 启发式指标1: SYN/FIN 比率
            syn_fin_ratio = syn_count / (fin_count + 1e-6) # 加一个极小值避免除以零

            # 启发式指标2: 平均包大小
            avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

            # 将计算出的启发式指标添加到摘要中
            event_summary['heuristic_syn_fin_ratio'] = round(syn_fin_ratio, 2)
            event_summary['heuristic_avg_packet_size_bytes'] = round(avg_packet_size, 2)
            
            print(f"[SSH SUMMARY] Remote IP {ip}: {json.dumps(event_summary)}")

            # 使用增强后的摘要生成Prompt
            prompt = generate_ssh_activity_summary_prompt(ip, event_summary)
            handle_llm_interaction(prompt)
            expired_ips.append(ip)

    for ip in expired_ips:
        if ip in ssh_observation_windows:
            del ssh_observation_windows[ip]

    # --- HTTP Web攻击检测逻辑 ---
    if packet.haslayer(HTTPRequest) and packet.getlayer(TCP) and \
       (packet.getlayer(TCP).dport == 80 or packet.getlayer(TCP).sport == 80):
        try:
            http_layer = packet[HTTPRequest]
            src_ip = packet[IP].src
            
            if PVM_IP_ADDRESS and src_ip == PVM_IP_ADDRESS: 
                return

            method = http_layer.Method.decode() if http_layer.Method else "N/A"
            host = http_layer.Host.decode() if http_layer.Host else "N/A"
            path = http_layer.Path.decode() if http_layer.Path else "N/A"
            user_agent = "N/A"
            if http_layer.User_Agent:
                try:
                    user_agent = http_layer.User_Agent.decode()
                except UnicodeDecodeError:
                    user_agent = str(http_layer.User_Agent) 

            http_request_details = {
                "method": method,
                "host": host,
                "path_and_query": path,
                "user_agent": user_agent
            }
            
            print(f"\n[HTTP DETECT] 捕获到来自 {src_ip} 的HTTP请求: {json.dumps(http_request_details)}")
            initial_prompt = generate_waf_prompt(src_ip, http_request_details) 
            handle_llm_interaction(initial_prompt)
            return 
        except Exception as e:
            print(f"[HTTP PARSE ERROR] {e}")

    # --- SSH 活动数据收集逻辑 ---
    if TCP in packet and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
        packet_src_ip = packet[IP].src
        packet_dst_ip = packet[IP].dst

        if not PVM_IP_ADDRESS:
            return

        remote_ip_for_tracking = None
        is_incoming_syn_to_pvm = False

        if packet_dst_ip == PVM_IP_ADDRESS and packet[TCP].dport == 22:
            remote_ip_for_tracking = packet_src_ip
            if packet[TCP].flags.S and not packet[TCP].flags.A: 
                is_incoming_syn_to_pvm = True
        elif packet_src_ip == PVM_IP_ADDRESS and packet[TCP].sport == 22:
            remote_ip_for_tracking = packet_dst_ip
        else:
            return

        if remote_ip_for_tracking == PVM_IP_ADDRESS: 
            return
        
        if not remote_ip_for_tracking: 
            return

        # 对该 remote_ip_for_tracking 初始化或更新观察窗口
        if remote_ip_for_tracking not in ssh_observation_windows:
            print(f"\n[SSH OBSERVE START] Tracking SSH for remote IP: {remote_ip_for_tracking} (PVM:{PVM_IP_ADDRESS}), starting {SSH_OBSERVATION_PERIOD}s window.")
            # <<< MODIFIED: 初始化字典结构 >>>
            ssh_observation_windows[remote_ip_for_tracking] = {
                'start_time': current_time,
                'total_packets': 0,
                'total_bytes': 0, # 新增
                'syn_to_pvm_ssh': 0,
                'fin_observed': 0,
                'rst_observed': 0
            }
        
        # 确保只更新当前活动窗口内的数据
        window_data = ssh_observation_windows[remote_ip_for_tracking]
        if current_time - window_data['start_time'] < SSH_OBSERVATION_PERIOD:
            # <<< MODIFIED: 累加数据包大小 >>>
            window_data['total_packets'] += 1
            window_data['total_bytes'] += len(packet) # 新增
            
            if is_incoming_syn_to_pvm:
                window_data['syn_to_pvm_ssh'] += 1
                print(f"[DEBUG SSH SYN] Incoming SYN from {remote_ip_for_tracking} to PVM:22. Current SYN count for this IP ({remote_ip_for_tracking}): {window_data['syn_to_pvm_ssh']}")
            
            flags = packet[TCP].flags
            if flags.F and packet[IP].src == remote_ip_for_tracking: 
                window_data['fin_observed'] += 1
            if flags.R: 
                window_data['rst_observed'] += 1
        return 

# --- 辅助函数：获取本机IP ---
def get_interface_ip(interface_name):
    try:
        addrs = netifaces.ifaddresses(interface_name)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
        else:
            print(f"CRITICAL: 接口 {interface_name} 没有配置IPv4地址。")
            return None
    except ValueError:
        print(f"CRITICAL: 接口 {interface_name} 不存在或无法访问。")
        return None
    except Exception as e:
        print(f"CRITICAL: 获取接口 {interface_name} 的IP地址时发生未知错误: {e}")
        return None

# --- 6. 主程序流程 ---
if __name__ == "__main__":
    # 请根据你的虚拟机环境修改网络接口名称
    pvm_interface = "ens33" 
    
    PVM_IP_ADDRESS = get_interface_ip(pvm_interface)
    if not PVM_IP_ADDRESS:
        print(f"错误：未能获取到接口 {pvm_interface} 的IP地址，Agent无法准确工作。程序退出。")
        exit(1) 
    print(f"PVM 本机IP地址 ({pvm_interface}): {PVM_IP_ADDRESS}")
    
    listen_filter = "tcp port 80 or tcp port 22"
    
    print(f"启动混合分析威胁检测Agent (WAF + SSH Heuristic Analysis)...")
    print(f"监听网络接口: {pvm_interface}, 过滤器: '{listen_filter}'")
    print(f"SSH活动观察窗口时长: {SSH_OBSERVATION_PERIOD} 秒")
    print("请确保 DEEPSEEK_API_KEY 已正确配置。")
    print("请确保已安装 scapy-http 和 netifaces: pip install scapy-http netifaces")
    print("运行此脚本通常需要 sudo 权限。")
    
    try:
        sniff(iface=pvm_interface, prn=process_packet, store=0, filter=listen_filter)
    except PermissionError:
        print("权限错误：请使用sudo或以root用户运行此脚本以捕获网络流量。")
    except OSError as oe:
        if "No such device" in str(oe) or "evice not found" in str(oe).lower() : 
            print(f"错误：网络接口 '{pvm_interface}' 未找到或不可用。请使用 'ip addr' 或 'ifconfig' 命令检查接口名称并更新脚本。")
        else:
            print(f"捕获网络流量时发生操作系统错误: {oe}")
    except Exception as e:
        print(f"发生意外错误: {e}")
