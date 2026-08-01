import asyncio
import json
import logging
from typing import Dict, Any, Optional
from .llm_client import LLMClient
from .context import ContextManager
from .tools import ToolDispatcher
from .anti_loop import AntiLoopDetector

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
        1. 代码中的双引号未转义（与JSON字符串引号冲突）
        2. 代码中的换行符是真实换行而非\\n
        3. 代码中的反斜杠未转义
        """
        import re
        
        raw_str = raw_str.strip()
        if not raw_str:
            return {}
        
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
            # 如果字符串以 { 开头，尝试补全 }
            if fixed.startswith('{') and not fixed.endswith('}'):
                fixed += '}'
            # 尝试解析
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        
        return {}

    async def run(self, prompt: str) -> str:
        self.context_manager.add_history("user", prompt)
        no_tool_call_count = 0
        
        if self.mode == "ctf":
            max_iterations = self.max_iterations
            max_no_tool_calls = self.max_no_tool_calls
        else:
            max_iterations = self.max_iterations
            max_no_tool_calls = self.max_no_tool_calls
        
        for iteration in range(max_iterations):
            if self.anti_loop_detector.detect_loop(self.context_manager.get_recent_history()):
                return "[ERROR] 检测到死循环，已终止执行"

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
            except asyncio.TimeoutError:
                return "[ERROR] LLM调用超时"
            except Exception as e:
                return f"[ERROR] LLM调用失败: {str(e)}"
            
            if response["content"]:
                logger.info(f"\n[AI] {response['content']}\n")
                
                if "[COMPLETE]" in response["content"]:
                    return response["content"]
                
                if "[VULN]" in response["content"]:
                    return response["content"]
                
                if "[FLAG]" in response["content"]:
                    return response["content"]

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
                
                tool_result_msg = "\n\n工具执行结果:\n" + "\n".join(tool_results)
                self.context_manager.add_history("user", tool_result_msg)
            else:
                no_tool_call_count += 1
                self.context_manager.add_history("assistant", response["content"] or "")
                
                if response["content"] and ("[COMPLETE]" in response["content"] or "[VULN]" in response["content"] or "[FLAG]" in response["content"]):
                    return response["content"]
                
                if no_tool_call_count >= max_no_tool_calls:
                    logger.debug(f"连续{no_tool_call_count}次未调用工具，已终止")
                    return response["content"] or "[ERROR] 达到最大连续无工具调用次数"

        return "[ERROR] 达到最大迭代次数"

    def _build_messages(self) -> list:
        messages = [
            {"role": "system", "content": self._get_system_prompt()}
        ]
        
        for entry in self.context_manager.get_recent_history(limit=30):
            role = entry["role"]
            content = entry["content"]
            
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

    def _get_pentest_prompt(self, tools_desc: str, context_summary: str, tool_names: str) -> str:
        return f"""
你是专业渗透测试工程师。目标：发现漏洞、评估风险、提供修复建议。

**硬约束（必须遵守）**：
1. 你**只能**调用以下已注册工具：{tool_names}。
2. 如果流程中提到的专用工具不在列表中，**禁止虚构调用**，必须改用 `execute_python` 或 `execute_bash` 手写脚本实现。
3. 工具参数必须是有效JSON，且必填参数不能缺。
4. **禁止死磕**：同一工具对同一目标失败2次后，必须换攻击路径。
5. **仔细核对上下文**：每次行动前，确认目标端口和URL，不要混淆不同端口的响应。

**约束**：仅测试授权目标，不破坏系统，遵守法律法规。

**上下文**：{context_summary}

**工具详情**：{tools_desc}

**工具用途说明**：
- `log4j_scan`：只做检测，判断端口是否是log4j服务。返回会包含suggestion字段指导下一步。
- `log4j_exploit`：CVE-2021-44228(Log4Shell)的JNDI注入利用，发送JNDI字符串payload。
- `ysoserial_generate`：生成Java反序列化payload（用于CVE-2017-5645等反序列化漏洞）。
- `ysoserial_test`：将ysoserial生成的payload发送到目标端口。
- `ysoserial_list`：列出所有可用的gadget链。
- `kb_search`：搜索知识库，查找漏洞信息和攻击方法。
- `file_upload`：上传自定义文件到目标URL，支持自定义文件名、内容、Content-Type和额外表单字段。
- `file_upload_webshell`：上传预置webshell（支持php/php_gif/php_jpg/jsp/asp/phtml/htaccess类型）。
- `file_upload_bypass`：自动尝试多种扩展名绕过（.php/.php5/.phtml/.PHP等）上传PHP webshell。
- `flask_session_decode`：解码Flask session cookie（调用flask-session-cookie-manager工具），可选secret_key验证签名。
- `flask_session_encode`：使用secret_key伪造Flask session cookie，data参数为Python dict字符串如{'user':'admin'}。
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

**CVE区分（重要）**：
- CVE-2021-44228 (Log4Shell)：JNDI注入，用 `log4j_exploit` 发送 `${{jndi:ldap://...}}` 字符串。
- CVE-2017-5645 (反序列化)：Java反序列化，用 `ysoserial_generate` + `ysoserial_test` 发送序列化对象。
- PHP反序列化：用 `php_deserialize_generate` 生成payload，通过GET/POST/Cookie注入。
- Python pickle反序列化：用 `python_pickle_generate` 生成payload。
- Flask session伪造：用 `flask_session_decode` 解码 → `flask_session_brute` 爆破key → `flask_session_encode` 伪造。
- 文件上传漏洞：用 `file_upload_webshell` 上传webshell，或 `file_upload_bypass` 自动绕过扩展名过滤。

**标准工作流**：
信息收集(nmap_scan) → 服务识别(log4j_scan检测) → 漏洞分析(kb_search) → 利用(根据CVE类型选工具) → 报告。

**思维链**：每次行动前输出 `[思考] 当前阶段、目标端口、计划、工具、参数、预期结果`。

**错误回退**：
- HTTP服务连不上 → 端口可能不是Web服务，用 `log4j_scan` 检测是否是log4j/反序列化服务。
- `log4j_scan` 返回 `is_silent=true` → 用 `ysoserial_generate` + `ysoserial_test` 尝试反序列化攻击。
- 工具调用失败2次 → 换攻击路径，禁止死磕。
- 未知服务 → 用 `kb_search` 查找相关漏洞。

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

**约束**：遵守比赛规则，不破坏题目环境。

**上下文**：{context_summary}

**工具详情**：{tools_desc}

**工具用途说明**：
- `file_upload`/`file_upload_webshell`/`file_upload_bypass`：文件上传漏洞利用，支持自定义上传、预置webshell、自动绕过扩展名过滤。
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
- `kb_search`：知识库搜索，查找漏洞信息和CTF解题思路。

**标准工作流**：
题目分析(识别类型) → 信息收集(web用http_get,服务用nmap_scan,文件用execute_python) → 漏洞识别(kb_search) → 漏洞利用(专用工具/execute_python) → 验证提交。

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
- 命令注入/RCE → `execute_python` 或 `execute_bash` 手写payload
- 文件包含 → `execute_python` 构造伪协议payload (php://filter等)
- 目录遍历 → `directory_brute` + `http_get`

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
- 遇到不熟悉的考点 → 使用 `execute_python` 调用requests库搜索网络获取提示。
- 无思路时 → kb_search查找相关解题思路。
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
- [FLAG] xxx
- [VULN] 类型:XX 证据:XX (证据必须是工具返回的实际数据)
- [COMPLETE] 总结:XX
"""
