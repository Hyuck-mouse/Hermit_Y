import asyncio
import json
import logging
from typing import Dict, Any, Optional
from .llm_client import LLMClient, LLMBreakerError
from .context import ContextManager
from .tools import ToolDispatcher
from .anti_loop import AntiLoopDetector
import re

logger = logging.getLogger(__name__)


class LoopController:
    def __init__(
        self,
        llm_client: LLMClient,
        context_manager: ContextManager,
        tool_dispatcher: ToolDispatcher,
        anti_loop_detector: AntiLoopDetector,
        mode: str = "pentest"
    ):
        self.llm_client = llm_client
        self.context_manager = context_manager
        self.tool_dispatcher = tool_dispatcher
        self.anti_loop_detector = anti_loop_detector
        self.max_iterations = 100
        self.max_no_tool_calls = 3
        self.mode = mode

    def _repair_json_arguments(self, raw_str: str, tool_name: str) -> dict:
        """尝试修复DeepSeek API返回的非法JSON参数字符串
        
        常见问题:
        1. Python风格布尔值/None: False/True/None 应为 false/true/null
        2. 代码中的双引号未转义（与JSON字符串引号冲突）
        3. 代码中的换行符是真实换行而非\\n
        4. 代码中的反斜杠未转义
        """
        import re
        
        raw_str = raw_str.strip()
        if not raw_str:
            return {}
        
        # 策略0: 修复Python风格字面量 -> JSON风格
        # DeepSeek经常输出 False/True/None 而非 false/true/null
        # 只替换值位置(冒号后)的字面量，避免影响字符串内容
        try:
            fixed = raw_str
            # 匹配 : False / : True / : None (冒号后可选空白，然后字面量，后面是逗号/}/空白)
            fixed = re.sub(r'(:\s*)\bFalse\b', r'\1false', fixed)
            fixed = re.sub(r'(:\s*)\bTrue\b', r'\1true', fixed)
            fixed = re.sub(r'(:\s*)\bNone\b', r'\1null', fixed)
            if fixed != raw_str:
                result = json.loads(fixed)
                logger.debug(f"JSON修复成功(Python字面量): False→false/True→true/None→null")
                return result
        except json.JSONDecodeError:
            pass  # 继续尝试其他修复策略
        
        # 策略1: 尝试用正则提取已知的参数模式
        # 对于 execute_python: 提取 code 参数
        # 对于 execute_bash: 提取 command 参数
        # 对于 http_get/http_post: 提取 url 参数
        code_params = {
            "execute_python": "code",
            "execute_bash": "command",
        }
        
        if tool_name in code_params:
            param_name = code_params[tool_name]
            # 尝试提取 {"param_name": "..."} 格式
            # 匹配 {"code": " 后面到结尾的 "}
            pattern = rf'\{{\s*"{param_name}"\s*:\s*"'
            match = re.search(pattern, raw_str)
            if match:
                # 从匹配位置之后开始，取到最后一个未转义的引号
                start = match.end()
                # 从后往前找最后一个引号（可能是 ")
                # 但要排除转义的引号
                remaining = raw_str[start:]
                # 去掉末尾的 } 和空白
                remaining = remaining.rstrip()
                if remaining.endswith('}'):
                    remaining = remaining[:-1].rstrip()
                if remaining.endswith('"'):
                    remaining = remaining[:-1]
                
                # 此时 remaining 是代码内容，但可能包含转义的引号
                # 反转义: \" -> ", \\ -> \, \n -> 换行, \t -> tab
                code = remaining.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')
                
                logger.debug(f"JSON修复成功({tool_name}): 提取{param_name}长度={len(code)}")
                return {param_name: code}
        
        # 策略2: 通用修复 - 尝试修复常见的JSON格式问题
        try:
            # 修复: 将真实换行符替换为\\n（在字符串值内部）
            # 这个比较tricky，因为JSON本身的结构性换行不能动
            # 简单方案: 如果整个字符串看起来是 {"key": "value with
            # newlines"}，尝试用正则提取
            # 提取所有 "key": "value" 对
            pairs = {}
            # 匹配 "key": "value" 但value中可能包含未转义的引号和换行
            # 用贪心匹配到最后一个引号
            pattern = r'"(\w+)"\s*:\s*"(.*)"\s*\}?\s*$'
            match = re.match(pattern, raw_str, re.DOTALL)
            if match:
                key = match.group(1)
                value = match.group(2)
                # 反转义
                value = value.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')
                pairs[key] = value
                logger.debug(f"JSON修复成功(通用): 提取{key}长度={len(value)}")
                return pairs
        except Exception:
            pass
        
        # 策略3: 尝试逐步修复
        try:
            fixed = raw_str
            # 修复Python字面量(兜底)
            fixed = re.sub(r'(:\s*)\bFalse\b', r'\1false', fixed)
            fixed = re.sub(r'(:\s*)\bTrue\b', r'\1true', fixed)
            fixed = re.sub(r'(:\s*)\bNone\b', r'\1null', fixed)
            # 如果字符串以 { 开头，尝试补全 }
            if fixed.startswith('{') and not fixed.endswith('}'):
                fixed += '}'
            # 尝试解析
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        
        return {}

    def _get_last_tool_results_summary(self, max_items: int = 3) -> str:
        """获取最近几次工具执行结果的摘要，用于空响应时帮助AI恢复上下文"""
        try:
            recent = self.context_manager.get_recent_history(limit=10)
            tool_msgs = []
            for entry in reversed(recent):
                if entry["role"] == "user":
                    content = entry["content"]
                    if isinstance(content, str) and "工具执行结果" in content:
                        tool_msgs.append(content[:500])
                        if len(tool_msgs) >= max_items:
                            break
            if tool_msgs:
                return "\n---\n".join(reversed(tool_msgs))
            return ""
        except Exception:
            return ""

    def _compress_history(self, keep_recent: int = 6):
        """压缩历史：保留最近几条消息，压缩更早的消息为摘要
        
        策略：保留最近 keep_recent 条消息完整，更早的消息按role合并为简短摘要
        """
        try:
            history = self.context_manager.history
            if len(history) <= keep_recent:
                return
            
            old_history = history[:-keep_recent]
            recent_history = history[-keep_recent:]
            
            # 从旧历史中提取关键信息
            key_points = []
            for entry in old_history:
                role = entry["role"]
                content = entry["content"]
                if isinstance(content, str):
                    # 提取AI的关键分析内容（非空、含关键词的）
                    if role == "assistant" and content:
                        # 只保留含关键词的句子
                        keywords = ["flag", "Access Denied", "local man", "VULN", "漏洞", "发现", "成功", "失败", "401", "403", "200", "500", "base64", "php://", "file=", "upload", "shell", "RCE", "SQL", "SSTI", "反序列化"]
                        lines = content.split("\n")
                        key_lines = [l.strip() for l in lines if any(k in l for k in keywords) and len(l) < 200]
                        if key_lines:
                            key_points.extend(key_lines[:3])  # 每条消息最多保留3行
            
            # 构建压缩摘要
            summary = "历史对话已压缩。关键发现：\n" + "\n".join(f"- {p}" for p in key_points[:20]) if key_points else "历史对话已压缩。"
            
            # 重置历史，保留摘要+最近消息
            self.context_manager.history = [
                {"role": "user", "content": summary, "timestamp": old_history[0].get("timestamp", "")}
            ] + recent_history
            
            logger.info(f"历史压缩: {len(old_history)}条 -> 1条摘要 + {len(recent_history)}条最近消息")
        except Exception as e:
            logger.warning(f"历史压缩失败: {e}")

    def _truncate_long_history_messages(self, max_length: int = 1500):
        """截断历史中过长的单条消息，减少LLM输入token
        
        特别针对：工具返回的base64源码、长HTML页面等
        """
        try:
            history = self.context_manager.history
            truncated_count = 0
            
            for i, entry in enumerate(history):
                content = entry.get("content", "")
                if isinstance(content, str) and len(content) > max_length:
                    # 保留开头和结尾，截断中间
                    truncated = content[:max_length//2] + f"\n...(已省略{len(content)-max_length}字符)...\n" + content[-max_length//4:]
                    history[i]["content"] = truncated
                    truncated_count += 1
                    logger.debug(f"截断历史消息[{i}]: {len(content)} -> {len(truncated)}字符")
            
            if truncated_count > 0:
                logger.info(f"截断{truncated_count}条过长历史消息(>{max_length}字符)")
            else:
                logger.info("没有需要截断的过长历史消息")
        except Exception as e:
            logger.warning(f"截断历史消息失败: {e}")

    def _build_key_findings_summary(self) -> str:
        """从context和历史中构建关键发现摘要"""
        try:
            findings = []
            
            # 从context中提取关键工具结果
            for key, value in self.context_manager.context.items():
                if key.startswith("last_tool_"):
                    val_str = str(value)
                    # 只保留含关键信息的简短摘要
                    if any(k in val_str for k in ["flag", "Access Denied", "local man", "VULN", "401", "403", "200", "base64"]):
                        # 提取body字段
                        if "'body':" in val_str:
                            body_match = re.search(r"'body': '([^']{0,200})", val_str)
                            if body_match:
                                findings.append(f"{key}: body={body_match.group(1)[:100]}")
            
            return "\n".join(findings[:10]) if findings else ""
        except Exception:
            return ""

    async def run(self, prompt: str) -> str:
        self.context_manager.add_history("user", prompt)
        no_tool_call_count = 0
        
        if self.mode == "ctf":
            max_iterations = self.max_iterations
            max_no_tool_calls = self.max_no_tool_calls
        else:
            max_iterations = self.max_iterations
            max_no_tool_calls = self.max_no_tool_calls
        
        # 循环检测状态
        loop_detected = False
        loop_warning_count = 0
        auth_reminder_scenarios = set()  # 记录已提醒过的场景
        
        for iteration in range(max_iterations):
            # 主动检查：是否遇到认证保护但还没尝试注册/默认凭据
            auth_reminder = self.anti_loop_detector.check_auth_and_credentials(
                self.context_manager.get_recent_history()
            )
            if auth_reminder:
                # 提取场景编号（SCENARIO_1, SCENARIO_2等）
                scenario_match = re.match(r'\*\*(SCENARIO_\d+)\*\*', auth_reminder)
                scenario = scenario_match.group(1) if scenario_match else auth_reminder[:30]
                
                if scenario not in auth_reminder_scenarios:
                    logger.warning(f"主动注入认证提醒({scenario}): {auth_reminder[:100]}...")
                    self.context_manager.add_history("user", auth_reminder)
                    auth_reminder_scenarios.add(scenario)
                    continue

            if self.anti_loop_detector.detect_loop(self.context_manager.get_recent_history()):
                loop_warning_count += 1
                if loop_warning_count >= 2:
                    # 连续2次检测到循环才终止
                    suggestion = self.anti_loop_detector.get_strategy_suggestion(
                        self.context_manager.get_recent_history()
                    )
                    if suggestion:
                        return f"[ERROR] 检测到策略锁定(2次)，已终止执行。\n\n策略建议:\n{suggestion}"
                    return "[ERROR] 检测到死循环(2次)，已终止执行"
                else:
                    # 第一次检测到循环，注入策略建议，让AI转向
                    suggestion = self.anti_loop_detector.get_strategy_suggestion(
                        self.context_manager.get_recent_history()
                    )
                    warning_msg = f"[WARNING] 检测到策略锁定！请立即转向其他方向！\n\n{suggestion}\n\n不要继续在当前方向上浪费迭代！"
                    logger.warning(warning_msg)
                    # 将警告注入到上下文中，强制AI注意
                    self.context_manager.add_history("user", warning_msg)
                    continue

            messages = self._build_messages()
            tools = self.tool_dispatcher.get_tools_json()
            
            logger.debug(f"迭代 {iteration+1}: 准备调用LLM...")
            logger.debug(f"消息数: {len(messages)}, 工具数: {len(tools)}")
            
            try:
                response = await asyncio.wait_for(
                    self.llm_client.tool_call_completion(messages, tools),
                    timeout=60
                )
                logger.debug(f"LLM调用成功，响应内容长度: {len(response.get('content', ''))}, 工具调用数: {len(response.get('tool_calls', []))}")
                
                # 检测空响应：根据finish_reason采取不同策略
                finish_reason = response.get("finish_reason", "")
                usage = response.get("usage")
                prompt_tokens = usage.get("prompt_tokens", 0) if usage else 0
                completion_tokens = usage.get("completion_tokens", 0) if usage else 0
                
                if not response.get("content") and not response.get("tool_calls"):
                    # 空响应：根据原因采取不同策略
                    if finish_reason == "length":
                        # 输出被截断：LLM的思考过程+工具调用参数太长
                        # 策略：截断历史中过长的单条消息（如base64源码），减少LLM需要处理的内容
                        logger.warning(f"空响应(finish_reason=length, completion_tokens={completion_tokens}/{self.settings.max_tokens}), 截断历史中过长消息")
                        self._truncate_long_history_messages()
                        # 避免死循环：只处理一次
                        if not getattr(self, '_length_truncated', False):
                            self._length_truncated = True
                            continue
                        else:
                            logger.warning("已截断过一次但仍length截断，继续执行其他逻辑")
                            self._length_truncated = False
                    elif prompt_tokens > 50000:
                        # 输入确实过长：压缩历史
                        logger.warning(f"空响应+输入过长(prompt_tokens={prompt_tokens}), 触发历史压缩")
                        self._compress_history()
                        # 避免重复注入摘要
                        if not getattr(self, '_compress_done', False):
                            self._compress_done = True
                            summary = self._build_key_findings_summary()
                            if summary:
                                self.context_manager.add_history("user", f"[历史压缩] 关键发现摘要：\n{summary}")
                            continue
                        else:
                            logger.warning("已压缩过一次但仍过长，跳过压缩")
                            self._compress_done = False
            except asyncio.TimeoutError:
                logger.warning(f"迭代 {iteration+1}: LLM调用超时，等待3秒后重试...")
                await asyncio.sleep(3)
                continue
            except LLMBreakerError as e:
                # 熔断:同一坏消息序列重试必再失败,直接终止,不 sleep/continue。
                # 注意:进程退出码仍为 0,worker 靠解析返回文本中的 [ERROR] 识别失败。
                logger.error(f"迭代 {iteration+1}: LLM熔断,任务终止: {e}")
                return (
                    f"[ERROR] LLM连续{e.consecutive_failures}次协议错误触发熔断,任务终止。\n"
                    f"原因: {e.reason}\n"
                    f"原始错误: {e.original_error}\n"
                    f"此类错误重试无效(消息序列问题),请检查会话历史后重开任务。"
                )
            except Exception as e:
                error_str = str(e)
                logger.warning(f"迭代 {iteration+1}: LLM调用失败: {error_str[:200]}")
                # 网络连接错误：等待后重试，不终止程序
                if any(kw in error_str.lower() for kw in ['connect', 'connection', 'timeout', 'network', 'unreachable', 'refused']):
                    retry_wait = min(5 * (iteration % 3 + 1), 15)  # 5s, 10s, 15s 循环
                    logger.warning(f"网络错误，等待{retry_wait}秒后重试...")
                    await asyncio.sleep(retry_wait)
                    continue
                # 其他错误：也重试，不直接终止
                logger.warning(f"LLM错误，等待3秒后重试...")
                await asyncio.sleep(3)
                continue
            
            if response["content"]:
                logger.info(f"\n[AI] {response['content']}\n")
                
                if "[COMPLETE]" in response["content"]:
                    return response["content"]
                
                if "[FLAG]" in response["content"]:
                    return response["content"]
                
                # [VULN] 仅是状态标记，表示发现漏洞，不终止也不注入提醒
                # AI会自然继续利用以获取flag

            if response["tool_calls"]:
                no_tool_call_count = 0
                
                async def execute_tool(tool_call):
                    try:
                        tool_name = tool_call.function.name
                        tool_args_str = tool_call.function.arguments if tool_call.function.arguments else "{}"
                        
                        try:
                            tool_args = json.loads(tool_args_str)
                        except json.JSONDecodeError:
                            logger.debug(f"JSON解析失败(原始): {tool_args_str[:200]}")
                            # 尝试修复常见的JSON格式问题
                            tool_args = self._repair_json_arguments(tool_args_str, tool_name)
                            if not tool_args:
                                logger.debug(f"JSON修复失败，参数为空")
                                tool_args = {}
                        
                        logger.debug(f"调用工具: {tool_name}, 参数: {tool_args}")
                        
                        tool_info = self.tool_dispatcher.get_tool(tool_name)
                        if tool_info:
                            required_params = tool_info.get("required_params", list(tool_info["parameters"].keys()))
                            missing_params = [p for p in required_params if p not in tool_args]
                            if missing_params:
                                error_msg = f"缺少必要参数: {', '.join(missing_params)}"
                                logger.debug(f"{error_msg}")
                                return f"{tool_name}: ERROR - {error_msg}"
                        
                        result = await asyncio.wait_for(
                            self.tool_dispatcher.call_tool(tool_name, **tool_args),
                            timeout=30
                        )
                        logger.debug(f"工具返回: {str(result)[:300]}")
                        
                        self.context_manager.set(f"last_tool_{tool_name}", result)
                        return f"{tool_name}({tool_args}): {str(result)[:8000]}"
                    except asyncio.TimeoutError:
                        logger.debug(f"工具调用超时: {tool_name}")
                        return f"{tool_name}: ERROR - 调用超时"
                    except Exception as e:
                        logger.debug(f"工具调用失败: {str(e)}")
                        return f"{tool_name}: ERROR - {str(e)}"
                
                tasks = [execute_tool(tc) for tc in response["tool_calls"]]
                tool_results = await asyncio.gather(*tasks)
                
                logger.info(f"\n[工具执行结果]")
                for result in tool_results:
                    logger.info(f"  {result[:200]}")
                
                self.context_manager.add_history("assistant", response["content"] or "")
                
                # 分类检测execute_bash使用是否合理
                # 允许：下载文件+本地分析(如 curl -o file && file file && python3 -c...)
                # 不允许：纯HTTP请求获取网页内容(应用http_raw)，或for循环批量curl(应用payload_gen+http_raw)
                bash_abuse = False
                for tc in response["tool_calls"]:
                    if tc.function.name == "execute_bash":
                        args_str = tc.function.arguments or ""
                        # 提取command参数
                        cmd = ""
                        try:
                            cmd = json.loads(args_str).get("command", "")
                        except Exception:
                            cmd = args_str
                        
                        # 判定滥用：命令过长(>200字符) 或 for循环+curl 组合
                        has_curl = bool(re.search(r'curl\s|wget\s', cmd))
                        has_for_loop = bool(re.search(r'\bfor\s+\w+\s+in\s', cmd))
                        has_local_analysis = bool(re.search(r'\bfile\s+\S|python3\s+-c|od\s+-c|\bstrings\s+|xxd\s+|\bconvert\s+|\bidentify\s+', cmd))
                        is_too_long = len(cmd) > 200
                        
                        # 滥用条件：纯HTTP(无本地分析) 或 for循环批量curl 或 命令过长
                        if has_curl and (has_for_loop or is_too_long or not has_local_analysis):
                            bash_abuse = True
                            break
                
                if bash_abuse:
                    self._bash_http_abuse_count = getattr(self, '_bash_http_abuse_count', 0) + 1
                    if self._bash_http_abuse_count <= 2:
                        abuse_msg = (
                            "[系统提醒] 检测到不规范的 execute_bash 使用。建议：\n"
                            "- **纯HTTP请求**(GET/POST获取网页内容) → 用 `http_raw`，参数结构化不会截断\n"
                            "- **批量测试payload** → 用 `payload_gen(category='xxx')` 获取列表后逐个 http_raw 测试\n"
                            "- **下载文件+本地分析**(如图片隐写检测) → 允许 execute_bash，但命令尽量简短(<200字符)\n"
                            "原因：bash命令过长会被LLM输出截断，导致JSON解析失败/语法错误。\n"
                            "示例：http_raw(url='http://target/path', headers='User-Agent: test')"
                        )
                        self.context_manager.add_history("user", abuse_msg)
                        logger.warning(f"检测到execute_bash不规范使用(第{self._bash_http_abuse_count}次)，注入纠正提醒")
                        no_tool_call_count = 0  # 重置，让AI有机会纠正
                        continue  # 跳过本次结果注入，让AI先纠正
                
                # 截断过长工具结果：防base64源码等长内容污染历史；按_kind选上限
                # structured(nmap/sqlmap等结构化输出)=4000，html/text=2000（未标注默认text）
                truncated_results = []
                for result in tool_results:
                    kind_m = re.search(r"['\"]_kind['\"]:\s*['\"](\w+)['\"]", result)
                    kind = kind_m.group(1) if kind_m else "text"
                    cap = {"structured": 4000, "html": 2000, "text": 2000}.get(kind, 2000)
                    if len(result) > cap:
                        truncated_results.append(
                            result[:1000]
                            + f"\n[已截断] 原始{len(result)}字符，中间{len(result) - 1500}字符未显示。"
                            + "补全方式：http_raw 的结果用 body_offset/body_limit 分段获取（如 body_offset=2000 续取）；"
                            + "其他工具优先用自带参数缩小输出。不要改用 execute_python/urllib 绕路。\n"
                            + result[-500:]
                        )
                    else:
                        truncated_results.append(result)
                
                tool_result_msg = "\n\n工具执行结果:\n" + "\n".join(truncated_results)
                self.context_manager.add_history("user", tool_result_msg)
            else:
                no_tool_call_count += 1
                self.context_manager.add_history("assistant", response["content"] or "")
                
                if response["content"] and ("[COMPLETE]" in response["content"] or "[FLAG]" in response["content"]):
                    return response["content"]
                
                # 空响应处理：注入提醒而非直接终止
                if not response["content"]:
                    # 获取最近工具结果摘要，帮助AI恢复上下文
                    last_results = self._get_last_tool_results_summary(max_items=3)
                    last_result_hint = f"\n\n最近工具执行结果摘要：\n{last_results}" if last_results else ""

                    if no_tool_call_count == 1:
                        nudge = f"请继续分析并调用工具。当前任务尚未完成，需要继续执行。{last_result_hint}"
                        self.context_manager.add_history("user", nudge)
                        logger.warning("AI返回空响应，注入继续提醒")
                    elif no_tool_call_count == 2:
                        nudge = (
                            f"你已经连续2次没有输出内容和调用工具。请回顾之前的分析进度，"
                            f"选择一个方向并调用工具继续执行。如果当前方向受阻，请尝试其他方法。{last_result_hint}\n"
                            f"可用工具：http_raw(自定义HTTP请求), http_get, http_post, execute_python, "
                            f"directory_brute, knowledge_search, sqlmap_scan, file_upload_auto, payload_gen 等。"
                        )
                        self.context_manager.add_history("user", nudge)
                        logger.warning("AI返回空响应(第2次)，注入工具提醒")
                else:
                    # 有文本但无工具调用(如只输出[思考]/[行动]描述而未真正调用):
                    # 追加 user 推进消息,避免消息序列以 assistant 结尾
                    # (DeepSeek 思考模式会校验结尾 assistant 的 reasoning_content,缺失即 400)。
                    nudge = (
                        "请继续:根据上面的分析立即调用对应工具执行下一步"
                        "(仅用文字描述[行动]不等于执行,必须发出真实工具调用);"
                        "若题目已完成,直接输出 [FLAG] 或 [COMPLETE]。"
                    )
                    self.context_manager.add_history("user", nudge)
                    logger.warning(f"AI有文本但无工具调用(第{no_tool_call_count}次)，注入推进消息")
                
                if no_tool_call_count >= max_no_tool_calls:
                    logger.debug(f"连续{no_tool_call_count}次未调用工具，已终止")
                    return response["content"] or "[ERROR] 达到最大连续无工具调用次数"

        return "[ERROR] 达到最大迭代次数"

    def _build_messages(self) -> list:
        messages = [
            {"role": "system", "content": self._get_system_prompt()}
        ]
        
        # 限制历史长度，避免上下文过长导致LLM空响应
        # 30条消息 * 平均2000字符/条 ≈ 60000字符 ≈ 15000-20000 tokens
        # 加上system prompt和tools定义，总token可能超过DeepSeek限制
        history_limit = 20  # 从30降到20，减少上下文压力
        for entry in self.context_manager.get_recent_history(limit=history_limit):
            role = entry["role"]
            content = entry["content"]
            
            # 截断过长的工具结果，减少token消耗
            if isinstance(content, str) and len(content) > 3000:
                # 保留开头和结尾
                content = content[:1500] + "\n...(中间内容已省略)...\n" + content[-1000:]
            
            if isinstance(content, dict):
                content = json.dumps(content, ensure_ascii=False)
            elif isinstance(content, list):
                content = json.dumps(content, ensure_ascii=False)
            
            messages.append({"role": role, "content": content})
        
        return messages

    def _get_system_prompt(self) -> str:
        tools_desc = self.tool_dispatcher.get_tools_description()
        context_summary = self.context_manager.get_context_summary()
        tool_names = ", ".join(self.tool_dispatcher.get_tool_names())
        
        if self.mode == "ctf":
            return self._get_ctf_prompt(tools_desc, context_summary, tool_names)
        else:
            return self._get_pentest_prompt(tools_desc, context_summary, tool_names)

    @staticmethod
    def _get_kb_rules() -> str:
        """主循环知识库规则(CTF/渗透两种模式共用)。

        与 core.py._build_system_prompt 中的"知识库规则"各自独立,
        规则变更时需同步两处。
        """
        return (
            "**知识库规则（必须遵守）**：\n"
            "1. 涉及具体漏洞名、框架名(如若依/Nacos/Shiro/SpringBoot)、工具名或课程内容时，"
            "**必须先调用 `knowledge_search` 检索本地知识库**，拿到结果后再结合推理，禁止直接凭记忆展开利用细节。\n"
            "2. 拿到检索结果后，必须结合检索内容推理，并在回答中引用来源(source 字段)；"
            "检索内容与自身判断冲突时，以课程笔记为准并说明。\n"
            "3. 返回 results 为空或 degraded=true 时，标注\"未命中知识库\"，"
            "再基于自身知识回答并明确说明不确定性，禁止编造具体漏洞路径、参数或 payload。"
        )

    def _get_pentest_prompt(self, tools_desc: str, context_summary: str, tool_names: str) -> str:
        return f"""
你是专业渗透测试工程师。目标：发现漏洞、评估风险、提供修复建议。

**硬约束（必须遵守）**：
1. 你**只能**调用以下已注册工具：{tool_names}。
2. 如果流程中提到的专用工具不在列表中，**禁止虚构调用**，必须改用 `execute_python` 或 `execute_bash` 手写脚本实现。
3. 工具参数必须是有效JSON，且必填参数不能缺。
4. **禁止死磕**：同一工具对同一目标失败2次后，必须换攻击路径。
5. **仔细核对上下文**：每次行动前，确认目标端口和URL，不要混淆不同端口的响应。

{self._get_kb_rules()}

**约束**：仅测试授权目标，不破坏系统，遵守法律法规。

**上下文**：{context_summary}

**工具详情**：{tools_desc}

**工具用途说明**：
- `log4j_scan`：只做检测，判断端口是否是log4j服务。返回会包含suggestion字段指导下一步。
- `log4j_exploit`：CVE-2021-44228(Log4Shell)的JNDI注入利用，发送JNDI字符串payload。
- `ysoserial_generate`：生成Java反序列化payload（用于CVE-2017-5645等反序列化漏洞）。
- `ysoserial_test`：将ysoserial生成的payload发送到目标端口。
- `ysoserial_list`：列出所有可用的gadget链。
- `file_upload`：上传自定义文件到目标URL，支持自定义文件名、内容、Content-Type和额外表单字段。
- `file_upload_webshell`：上传预置webshell（支持php/php_gif/php_jpg/jsp/asp/phtml/htaccess类型）。
- `file_upload_bypass`：自动尝试多种扩展名绕过（.php/.php5/.phtml/.PHP等）上传PHP webshell。
- `flask_session_decode`：解码Flask session cookie（调用flask-session-cookie-manager工具），可选secret_key验证签名。
- `flask_session_encode`：使用secret_key伪造Flask session cookie，data参数为Python dict字符串如{{'user':'admin'}}。
- `flask_session_brute`：爆破Flask session的secret_key，支持自定义字典。
- `php_deserialize_generate`：生成PHP反序列化payload，支持rce/wakeup/phar/tostring类型。
- `php_deserialize_pop`：根据POP链信息生成PHP反序列化payload，chain参数为JSON格式。
- `python_pickle_generate`：生成Python pickle反序列化payload执行系统命令。
- `python_pickle_reverse_shell`：生成Python pickle反弹shell payload。
- `crypto_detect`：加密算法识别(从明密文对推断XOR/RC4/AES)。
- `rc4_crypt`/`xor_crypt`：RC4/XOR加解密。
- `generate_ssti_encrypted_payload`：生成加密SSTI payload(绕过字符过滤)。
- `werkzeug_debugger_probe`/`werkzeug_debugger_exec`：Werkzeug调试器探测与利用(Flask debug模式RCE)。
- `ssti_route_probe`：SSTI入口路由自动探测。
- `logic_session_http`：会话保持HTTP请求(跨调用维持Cookie)。用于登录后操作、多步骤业务流程。
- `logic_idor_test`：越权检测(遍历ID/替换用户标识)。url可用__VALUE__占位符。
- `logic_param_fuzz`：参数边界值Fuzz(负数/零/超大值/空值/类型混淆)。自动对比基准响应。
- `logic_race_condition`：竞争条件测试(并发请求检测余额双花/优惠券重复使用)。
- `logic_flow_test`：业务流程绕过(跳步/重放/乱序)。传入steps JSON数组自动测试。

**CVE区分（重要）**：
- CVE-2021-44228 (Log4Shell)：JNDI注入，用 `log4j_exploit` 发送 `${{jndi:ldap://...}}` 字符串。
- CVE-2017-5645 (反序列化)：Java反序列化，用 `ysoserial_generate` + `ysoserial_test` 发送序列化对象。
- PHP反序列化：用 `php_deserialize_generate` 生成payload，通过GET/POST/Cookie注入。
- Python pickle反序列化：用 `python_pickle_generate` 生成payload。
- Flask session伪造：用 `flask_session_decode` 解码 → `flask_session_brute` 爆破key → `flask_session_encode` 伪造。
- 文件上传漏洞：用 `file_upload_webshell` 上传webshell，或 `file_upload_bypass` 自动绕过扩展名过滤。

**标准工作流**：
信息收集(nmap_scan) → 服务识别(log4j_scan检测) → 漏洞分析(knowledge_search) → 利用(根据CVE类型选工具) → 报告。
发现Web应用且有用户登录功能时，追加逻辑漏洞检测：logic_session_http登录 → logic_idor_test越权 → logic_param_fuzz参数边界 → logic_race_condition竞争条件 → logic_flow_test流程绕过。

**逻辑漏洞检测指南**（发现Web登录/下单/查询等功能时执行）：
1. **会话登录**：`logic_session_http(session_id='user1', method='POST', url='登录URL', data='{{"username":"test","password":"test"}}')` 获取会话Cookie
2. **越权检测**：`logic_idor_test(url='http://target/api/user?id=__VALUE__', param_name='id', current_value='当前ID', session_id='user1')` → 自动遍历相邻ID对比响应差异
3. **参数Fuzz**：`logic_param_fuzz(url='接口URL', method='POST', param_name='amount', param_value='100', session_id='user1')` → 测试负数/零/超大值/空值
4. **竞争条件**：`logic_race_condition(url='优惠券/签到/投票URL', method='POST', data='{{"coupon_id":"NEWUSER"}}', concurrency=20, session_id='user1')` → 并发检测双花
5. **流程绕过**：`logic_flow_test(steps='[{{...}}]', session_id='user1')` → 跳步/重放测试（如跳过支付步骤直接完成订单）
6. **双账号越权**：用不同session_id登录两个账号('user1'/'user2')，用user1的session访问user2的资源验证

**思维链**：每次行动前输出 `[思考] 当前阶段、目标端口、计划、工具、参数、预期结果`。

**错误回退**：
- HTTP服务连不上 → 端口可能不是Web服务，用 `log4j_scan` 检测是否是log4j/反序列化服务。
- `log4j_scan` 返回 `is_silent=true` → 用 `ysoserial_generate` + `ysoserial_test` 尝试反序列化攻击。
- 工具调用失败2次 → 换攻击路径，禁止死磕。
- 传统漏洞(注入/SSTI/上传)未发现 → 转向逻辑漏洞检测(越权/参数Fuzz/竞争条件/流程绕过)。

**输出规范**：
- 发现漏洞必须附带**命令执行回显**或**工具返回数据**作为证据。
- [VULN] 类型:XX 证据:XX (证据必须是工具返回的实际数据)
- [COMPLETE] 总结:XX
"""

    def _get_ctf_prompt(self, tools_desc: str, context_summary: str, tool_names: str) -> str:
        return f"""
你是专业CTF选手。目标：快速找到flag。

**硬约束（必须遵守）**：
1. 你**只能**调用以下已注册工具：{tool_names}。
2. 如果流程中提到的专用工具不在列表中，**禁止虚构调用**，必须改用 `execute_python` 或 `execute_bash` 手写脚本实现。
3. 工具参数必须是有效JSON，且必填参数不能缺。

{self._get_kb_rules()}

**约束**：遵守比赛规则，不破坏题目环境。

**上下文**：{context_summary}

**工具详情**：{tools_desc}

**工具用途说明**：
- `file_upload`/`file_upload_webshell`/`file_upload_bypass`/`file_upload_auto`：文件上传漏洞利用。
  * `file_upload_auto`（推荐）：多策略自动轮询+.htaccess+图片马+主动RCE验证，覆盖6种策略。优先使用。
  * `file_upload_webshell`：上传预置webshell，支持php/php_gif/php_jpg/htaccess/user_ini等20种模板。
  * `file_upload_bypass`：自动尝试多种扩展名绕过。
  * `file_upload`：自定义上传内容和文件名。
- `flask_session_decode`/`flask_session_encode`/`flask_session_brute`：Flask session cookie解码、伪造、爆破secret_key。
- `php_deserialize_generate`：PHP反序列化payload生成，支持rce/wakeup/phar/tostring/custom，可自定义属性(props)、__wakeup绕过(wakeup_bypass)、额外计数(extra_count)。
- `php_deserialize_pop`：根据POP链JSON生成PHP反序列化payload。
- `php_reference_bypass`：**PHP引用(R:)绕过__wakeup()**（手动模式）。需手动构造props JSON，被引用属性必须在引用属性之前定义。
- `php_reference_bypass_auto`：**PHP引用绕过快捷方法（推荐）**。自动处理属性顺序和引用ID，适用于__wakeup清空$a、__destruct中$b=$c、eval($a)的经典模式。参数: class_name, command(建议先用ls探测), ref_target(默认b), ref_src(默认a), command_prop(默认c)。
- `python_pickle_generate`/`python_pickle_reverse_shell`：Python pickle反序列化payload生成。
- `ysoserial_generate`/`ysoserial_test`/`ysoserial_list`：Java反序列化payload生成和测试。
- `sqlmap_scan`/`sqlmap_detect`：SQL注入检测和利用。
- `fenjing_scan`/`fenjing_attack`：**SSTI(服务端模板注入)自动化工具**，支持Jinja2/Flask/Mako等引擎，自动绕过WAF。调用时url必须用`{{payload}}`占位注入参数。示例:
    * GET参数扫描: `fenjing_scan(url='http://target/secret?secret={{payload}}')` (默认POST,如需GET显式指定method='GET')
    * POST参数扫描: `fenjing_scan(url='http://target/', method='POST', extra_data='name={{payload}}')`
    * 指定参数攻击: `fenjing_scan(url='http://target/', inputs='secret,name', exec_cmd='cat /flag')`
    * 快速扫描: `fenjing_scan(url='http://target/?q={{payload}}', detect_mode='fast')`
    * 带Cookie攻击: `fenjing_scan(url='http://target/?s={{payload}}', cookies='session=xxx')`
    * `fenjing_attack`默认exec_cmd='cat /flag',等同于带命令执行的scan
    * 内置重试机制(最多2次)和网络错误恢复，Connection reset会自动重试
    * 注意: url中的`{{payload}}`必须原样保留作为占位符，fenjing会自动替换成测试payload
- `log4j_scan`/`log4j_exploit`：Log4j漏洞检测和利用。
- `crypto_detect`：**加密算法识别**(从明密文对推断XOR/RC4/AES)。遇到加密接口时优先调用，避免手工猜测。
- `rc4_crypt`/`xor_crypt`：RC4/XOR加解密(对称)。用于加密SSTI payload或解密响应。
- `generate_ssti_encrypted_payload`：**生成加密后的SSTI payload**(绕过safe()等字符过滤)。payload+algorithm+key→URL编码后的加密串。
- `werkzeug_debugger_probe`/`werkzeug_debugger_exec`：**Werkzeug调试器探测与利用**(Flask debug模式)。比SSTI更直接的RCE路径。
- `ssti_route_probe`：**SSTI入口路由自动探测**(遍历路径和参数,用{{7*7}}检测)。避免只测单一路由导致漏判。
- `ssti_bypass_generate`：**SSTI绕过payload自动生成**(针对safe()等黑名单)。内置attr过滤器、lipsum/cycler全局对象、字符串拼接等5种绕过模板。当SSTI接口有过滤时使用。
- `http_request_retry`：**带指数退避重试的HTTP请求**(解决靶场不稳定/超时问题)。GET/POST，自动重试1-3次。
- `pwn_checksec`：**检查二进制保护机制**(NX/PIE/Canary/RELRO)+关键函数地址(system/gets等)+PLT/GOT表。PWN题第一步必调用。
- `pwn_file_info`：获取二进制文件类型、架构、strings。提取flag/shell/system等关键字符串。
- `pwn_disassemble`：反汇编指定函数(main/vuln等)，分析漏洞点(buffer overflow/format string)。
- `pwn_pattern_create`/`pwn_pattern_offset`：**生成循环模式+计算溢出偏移**。溢出crash后用崩溃地址算偏移。
- `pwn_rop_gadgets`：搜索ROP gadgets(pop rdi/rsi/rdx/ret等)，ret2libc/ROP利用必备。
- `pwn_rop_chain`：自动构建ROP链调用指定函数(如system("/bin/sh"))。
- `pwn_remote_exploit`：连接远程PWN服务发送payload(支持hex格式)。获取shell后交互。
- `pwn_remote_interact`：交互式连接(发送多条命令)。适用于菜单题(选选项再利用)。
- `pwn_shellcode_generate`：生成shellcode(sh/exec/cat_flag/read_flag类型，i386/amd64架构)。
- `pwn_search_string`：搜索二进制中字符串地址(如/bin/sh、/flag)。
- `pwn_fmtstr_exploit`：格式化字符串漏洞利用(leak泄漏/write任意写)。

**标准工作流**：
题目分析(识别类型) → 信息收集(web用http_raw/http_get,服务用nmap_scan,文件用execute_python) → 漏洞识别(knowledge_search) → 漏洞利用(专用工具/execute_python) → 验证提交。

**工具使用优先级（必须遵守）**：
- 需要发送HTTP请求时（特别是带自定义headers/cookies/body的请求），**优先使用 `http_raw`**，不要用 `execute_python` 写Python requests/socket代码。
  - http_raw 支持自定义headers、所有HTTP方法、JSON/表单body、重定向控制，不会出现Python代码语法错误。
  - 需要循环测试多个 payload 时，用 http_raw 逐个发送，不要用 execute_python 写 for 循环。
- **[分类指导] HTTP请求工具选择**：
  - **纯HTTP请求**(GET/POST获取网页内容/headers/body) → 用 `http_raw`，参数结构化不会被截断
  - **批量测试payload**(IP伪造/UA绕过/LFI/SQLi等) → 用 `payload_gen` 获取列表后 `http_raw` 逐个测试
  - **下载文件+本地分析**(图片隐写/二进制检测/file命令) → 允许 `execute_bash`，但命令尽量简短(<200字符)
  - **禁止**用 `execute_bash` 写 for循环+curl 批量测试脚本（命令超长会被LLM截断导致语法错误）
  - **禁止**用 `execute_python` 写 requests 库的HTTP请求代码（f-string花括号易导致语法错误）
- **需要批量测试多种payload变体时（IP伪造头、UA绕过、LFI路径、SQLi、SSTI、命令注入、目录爆破、认证绕过等），必须使用 `payload_gen` 获取payload列表**，然后用 http_raw 逐个测试。
  - **严禁用 execute_python 写 for 循环批量测试脚本**：这种代码超长会被LLM输出token限制截断，导致JSON解析失败、括号未闭合、SyntaxError。
  - 正确做法：payload_gen(category='ip_bypass') → 拿到20+个headers变体 → 对每个用 http_raw 测试。
  - payload_gen 支持的类别：ip_bypass/ua_bypass/lfi_paths/dir_wordlist/sqli/ssti/cmdi/xxe/deserialize/auth_bypass/xss。传 'list' 查看所有类别。
- execute_python 仅用于：数据处理、编码转换、payload生成、复杂逻辑运算等非HTTP场景，且代码长度控制在30行以内避免被截断。
- **【总原则】execute_python 只用于不涉及网络的代码执行：生成 payload、编码解码、计算。任何 HTTP 交互统一走 http_raw。**
- **工具结果被截断时，优先用原工具的分段参数补全（http_raw: body_offset/body_limit），不要切换到 execute_python/urllib 绕路。**
- **发现布尔盲注漏洞时，必须使用 `sqli_blind_extract` 工具提取数据**，不要用 execute_python 写盲注脚本（逐字符提取消耗大量迭代且脚本易被截断）。
  - 一次调用自动完成全部字符的二分查找提取。
  - 需要提供: url(含INJECT_HERE占位符)、true_marker(布尔为真标志)、query_template(SQL注入模板，用 {{pos}} 和 {{char}} 占位)。
- **遇到加密/编码的flag时，优先使用 `crypto_decode_all` 工具**自动尝试所有常见解密方法。
  - 支持: 凯撒/ROT13/ROT47/Atbash/Base64/Base32/Hex/URL/Vigenere/摩尔斯/培根密码。
  - 如果已知flag前缀(如flag{{)，传入known_prefix参数可自动验证解密结果并找到最佳匹配。

**解题策略原则（必须遵守）**：
1. **避免策略锁定**：在一个方向（如认证绕过、源码分析）投入最多8次迭代。若8次后无进展，必须转向其他方向。
2. **高价值线索优先**：发现以下线索时立即跟进，优先级高于其他所有方向：
   - YAML反序列化接口（/api/admin/yaml/import, /api/import, yaml import等）
   - 反序列化相关（pickle, unserialize, __wakeup, __destruct等）
   - RCE相关（eval(), exec(), subprocess, system(), popen()等）
   - 文件上传+解析配置（.htaccess, .user.ini, shell.php等）
   - SSTI（Jinja2/Mako模板注入）
   - Werkzeug调试器（debug mode, SECRET key等）
3. **获取凭证三步走（强制顺序）**：遇到需要认证的功能时，**必须按以下顺序执行，不可跳过**：
   - **第一步：检查注册接口** → POST /api/auth/register、/api/register、/api/signup 等。如果有注册功能，先注册一个账号。
   - **第二步：尝试默认/测试凭据** → 按顺序尝试：admin/admin、admin/admin123、admin/password、test/test、test@domain/test123、admin@domain/admin。使用合理的密码长度（≥8位）。
   - **第三步：搜索源码中的用户名和凭据** → 在JS/sourcemap中搜索：
     * 人名模式（如 "E. Vale", "J. Renn", "I. Cross" → evale, jrenn, icross），拼成邮箱如 evale@blackarchive.local
     * email、password、secret、credential、admin、test 等关键词
     * Notes/Operator notes 组件内容
     * legacy/ mobile archive sourcemap（mobile-archive.js.map）中的 session.ts
   - **只有前三步全部失败**，才能尝试认证绕过（X-Archive-Mobile、路径绕过、session伪造等）。
4. **认证绕过的正确用法**：当发现 X-Archive-Mobile 头机制时，**严格按以下步骤执行**：
   - **步骤A（立即执行）**：下载 mobile-archive.js.map → 分析 legacy/session.ts
   - **步骤B（构造用户名）**：从Notes/源码中提取人名，转为邮箱格式：
     * "E. Vale" → `evale@blackarchive.local`（去掉点号，小写拼接）
     * "J. Renn" → `jrenn@blackarchive.local`
     * "I. Cross" → `icross@blackarchive.local`
   - **步骤C（构造绕过请求）**：
     ```python
     POST /api/auth/login
     Headers: {{
         "Content-Type": "application/json",
         "X-Archive-Mobile": "BA-iOS/2.6.1"
     }}
     Body: {{"email": "evale@blackarchive.local", "password": "anypass1234"}}
     ```
     核心原理：移动客户端兼容模式跳过密码校验，只要用户名有效且带特殊头就能获取管理员Cookie
   - **步骤D（利用反序列化）**：拿到Cookie后立即调用 /api/admin/yaml/import，提交恶意YAML：
     ```yaml
     !!python/object/apply:os.system
     - "cat /flag* > /tmp/out.txt"
     ```
     注意：反序列化发生在import解析阶段，不需要触发文件下载，直接在API调用中嵌入payload
5. **不要过度分析边缘机制**：对单一绕过方法最多尝试5次。如果无效，立即换用户名或密码格式。
6. **信息收集全面**：优先下载完整JS bundle和所有source map（包括子模块如mobile-archive.js.map）。
7. **源码分析优先**：如果有source map，用它定位JS源码中的关键逻辑（路由、API调用、漏洞点、用户名）。

**CTF常见考点与对应工具**：
- 文件上传 → `file_upload_webshell`（上传PHP/JSP webshell），`file_upload_bypass`（自动绕过扩展名过滤）
- PHP反序列化基础(无__wakeup) → `php_deserialize_generate`（用props直接定义属性值）
- PHP反序列化(__wakeup属性数量法) → `php_deserialize_generate` + `wakeup_bypass=true` + `extra_count=N`
- PHP反序列化(引用绕过R:) → `php_reference_bypass`（用type=object创建嵌套对象产生引用，type=reference关联属性）
- PHP反序列化(POP链) → `php_deserialize_pop`（根据链信息构造）
- PHP反序列化(Phar) → `php_deserialize_generate` + `gadget_type=phar`
- Flask session伪造 → `flask_session_decode` 解码 → `flask_session_brute` 爆破key → `flask_session_encode` 伪造admin
- Python pickle反序列化 → `python_pickle_generate` 生成payload
- Java反序列化 → `ysoserial_generate` + `ysoserial_test`
- SQL注入 → `sqlmap_scan` / `sqlmap_detect`
- SSTI模板注入 → 先用 `ssti_route_probe` 探测入口 → `fenjing_scan` / `fenjing_attack` / 手写payload
- **加密SSTI**(接口对输入加密) → `crypto_detect` 识别算法 → 提取密钥 → `generate_ssti_encrypted_payload` 生成加密payload
- **Flask debug模式** → `werkzeug_debugger_probe` 探测 → 提取SECRET → `werkzeug_debugger_exec` 执行代码(比SSTI更直接)
- 命令注入/RCE 题：用 execute_python 构造 payload 字符串，发送请求必须用 http_raw。
- 文件包含 → `execute_python` 构造伪协议payload (php://filter等)
- 目录遍历 → `directory_brute` + `http_get`
- **PWN二进制利用** → `pwn_checksec`检查保护 → `pwn_file_info`+`pwn_disassemble`分析 → `pwn_pattern_create`+`pwn_remote_exploit`确定偏移 → `pwn_rop_gadgets`/`pwn_rop_chain`/`pwn_shellcode_generate`构建payload → `pwn_remote_exploit`发送

**PWN解题深度指南**：
面对PWN题（给定二进制文件+远程服务）时，必须按以下步骤操作：
1. **下载二进制文件**：用 `execute_bash` 的 `wget`/`curl` 下载题目附件到本地
2. **检查保护机制**：`pwn_checksec(binary_path='文件路径')` → 获取NX/PIE/Canary/RELRO状态
3. **分析文件信息**：`pwn_file_info(binary_path='文件路径')` → 获取架构、strings中的关键信息
4. **反汇编关键函数**：`pwn_disassemble(binary_path='文件路径', function_name='main')` → 分析漏洞点
   - 重点找：`gets`/`read`/`scanf`(缓冲区溢出)、`printf`无格式化参数(格式化字符串)、`strcpy`/`strcat`(溢出)
5. **确定溢出偏移**：
   - `pwn_pattern_create(length=200)` → 生成pattern
   - `pwn_remote_exploit(host='目标IP', port=端口, payload='生成的pattern')` → 发送pattern导致crash
   - `pwn_pattern_offset(value='崩溃地址如0x41414141')` → 计算偏移量
6. **根据保护机制选择利用方式**：
   - **无NX(栈可执行)** → `pwn_shellcode_generate` 生成shellcode → 填充到返回地址
   - **有NX无PIE** → ret2libc: 用 `pwn_search_string` 找/bin/sh → `pwn_rop_chain` 构建system("/bin/sh")
   - **有NX有PIE** → 需要先leak地址(格式化字符串或puts泄露)，再ret2libc
   - **有Canary** → 需要先leak canary值(格式化字符串或栈溢出逐字节爆破)
   - **格式化字符串漏洞** → `pwn_fmtstr_exploit(payload_type='leak')` 泄漏地址 → `pwn_fmtstr_exploit(payload_type='write')` 覆写GOT/返回地址
7. **发送最终payload**：`pwn_remote_exploit(host='IP', port=端口, payload='hex格式的payload')`
8. **获取flag**：拿到shell后执行 `cat /flag` 或搜索flag位置

**PWN payload构造辅助**：
- 用 `execute_python` 构造复杂payload: `python3 -c "from pwn import *; ..."` 或直接写Python代码
- payload格式: padding + 返回地址 + ROP链/shellcode
- 多次交互用 `pwn_remote_interact` (菜单题: 先选选项再发送payload)

**PHP反序列化深度分析指南**：
当面对PHP反序列化题目时，必须按以下步骤分析源码：
1. **识别入口**：`unserialize()` 接收的参数来自哪里？`$_GET['a']`/`$_POST['b']`/`$_COOKIE`?
2. **分析魔术方法链**：
   - `__wakeup()` 做了什么？清空了哪些属性？
   - `__destruct()` 做了什么？执行顺序？`eval()`/`assert()`/`include()` 在哪个属性上？
   - 有没有 `__toString()`/`__call()` 等可触发的方法？
3. **分析赋值关系**：`__destruct()` 中是否有 `$a = $b` 这类赋值？这是否意味着可以用引用绕过？
4. **检查WAF**：`preg_match()`/`strpos()` 检查了什么？正则要求什么字符串？黑名单有哪些关键字？
5. **选择绕过方法**：
   - 无`__wakeup()` → 直接用 `php_deserialize_generate`
   - 有`__wakeup()`但无WAF限制属性数 → 用 `php_deserialize_generate` + `wakeup_bypass`
   - 有`__wakeup()`+WAF限制属性数 → 用 `php_reference_bypass`（引用绕过）
   - 有`__wakeup()`+`__destruct()`有赋值操作 → **必须**用 `php_reference_bypass`
6. **验证payload**：用 `http_get` 提交payload，检查返回内容是否有命令执行回显

**SSTI深度分析指南**：
面对SSTI/Flask题目时，必须按以下步骤分析：
1. **路由探测**：用 `ssti_route_probe` 遍历常见路径和参数，**禁止只测单一路由**。命中后再深入。
2. **识别加密层**：若提交 `{{7*7}}` 返回的是十六进制/base64乱码而非 `49`，说明接口对输入做了加密。
   - **禁止手工猜测加密算法！** 必须用 `crypto_detect` 传入2组以上明密文对自动识别。
   - 收集样本方法: 提交 `a`/`b`/`aa` 等已知明文，记录返回的密文。
3. **提取密钥**：从源码 `key = "..."` / `SECRET_KEY = "..."` 提取。RC4无法从明密文反推密钥。
4. **生成加密payload**：`generate_ssti_encrypted_payload(payload="{{config}}", algorithm="rc4", key="提取的密钥")` → 返回URL编码的加密串，可直接作参数提交。
5. **检查过滤**：源码若有 `safe()` 过滤 `<>;|`，加密后字节经URL编码天然绕过字符黑名单。传入 `forbidden_chars` 参数可自动验证。
6. **Flask debug模式优先**：若发现 `app.run(debug=True)` 或 `/console` 页面，**优先用 `werkzeug_debugger_probe` + `werkzeug_debugger_exec`**，比SSTI更直接获得RCE。
   - Werkzeug<2.1: 需SECRET(从源码提取)
   - Werkzeug>=2.1: 需PIN(从/console页面或环境变量提取)

**思维链**：每次行动前输出 `[思考]CTF分析：题目类型、已收集信息、当前假设、计划、工具、参数、预期结果`。

**错误回退**：
- 工具调用失败2次 → 标记为不可用，换攻击路径。
- 端口开放但不响应HTTP → 尝试发送JNDI payload（使用 `log4j_scan` 或 `execute_python`），检测log4j漏洞。
- 发现文件上传点 → 优先用 `file_upload_webshell` 上传webshell获取RCE。
- 发现Flask应用 → 用 `flask_session_decode` 检查session，尝试 `flask_session_brute` 爆破key。
- 发现PHP应用 → 检查是否有反序列化接口，用 `php_deserialize_generate` 生成payload。
- **SSTI payload无效且返回乱码** → 接口可能做了加密，用 `crypto_detect` 识别算法。
- **发现Flask debug模式** → 优先 `werkzeug_debugger_probe` + `werkzeug_debugger_exec`，比SSTI更直接。
- **safe()/preg_match过滤字符** → 用 `generate_ssti_encrypted_payload` 加密payload绕过黑名单。

**RCE后操作规范（必须遵守）**：
获得RCE（命令执行/webshell/反序列化eval）后，**禁止直接猜测flag位置（如cat /flag）**！必须按以下顺序操作：
1. **环境确认**：执行 `id; pwd; whoami` 确认当前权限和工作目录
2. **当前目录探测**：执行 `ls -la` 查看当前目录文件
3. **上级目录探测**：执行 `ls -la ../` 和 `ls -la /var/www/html/` 查看Web目录
4. **全局搜索flag**：执行 `find / -name "*flag*" -type f 2>/dev/null` 搜索flag文件
5. **环境变量检查**：执行 `env | grep -i flag` 检查环境变量
6. **读取发现的文件**：根据搜索结果读取flag文件，不要假设文件名或路径
- 反序列化payload中的命令应先用 `ls` 等探测命令，确认环境后再针对性读取flag
- flag文件名可能是：flag、flag.txt、f1ag、fl4g、secret、ctf_flag等，必须搜索确认

**输出规范**：
- 发现漏洞必须附带**命令执行回显**或**文件读取内容**作为证据。
- [VULN] 类型:XX 证据:XX （状态标记，表示发现漏洞，不终止流程，需继续利用获取flag）
- [FLAG] xxx （找到flag，终止）
- [COMPLETE] 总结:XX （任务完成，终止）
"""
