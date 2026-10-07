# -*- coding: utf-8 -*-
import asyncio
import sys
import os
from typing import Awaitable, TypeVar

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
"""
# 退出当前 venv       
deactivate
source /opt/miniconda3/bin/activate hermit-y
python src/main.py run
"""
import typer
from rich.console import Console
from rich.panel import Panel
from typing import Optional

T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """在已有或新建的事件循环中执行协程，兼容Python 3.14+"""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()

from src.agent.core import PentestAgent
from src.agent.context import ContextManager
from src.tools.http_client import HTTPClient
from src.tools.nmap_scanner import NmapScanner
from src.tools.crypto import CryptoTool
from src.tools.code_executor import CodeExecutor
from src.tools.web_scanner import WebScanner
from src.tools.knowledge_search import KnowledgeSearchTool
from src.tools.external_tools import (
    sqlmap_scan, sqlmap_detect, sqlmap_get_databases, sqlmap_get_tables, sqlmap_dump_table,
    fenjing_scan, fenjing_attack,
    log4j_scan, log4j_exploit,
    ysoserial_generate, ysoserial_list, ysoserial_test,
    file_upload, file_upload_webshell, file_upload_bypass, file_upload_auto,
    flask_session_decode, flask_session_encode, flask_session_brute,
    php_deserialize_generate, php_deserialize_pop, php_reference_bypass, php_reference_bypass_auto,
    python_pickle_generate, python_pickle_reverse_shell,
    crypto_detect, rc4_crypt, xor_crypt, generate_ssti_encrypted_payload,
    werkzeug_debugger_exec, werkzeug_debugger_probe,
    ssti_route_probe,
    ssti_bypass_generate,
    http_request_retry,
    http_raw,
    payload_gen,
    sqli_blind_extract,
    crypto_decode_all
)
from src.tools.pwn_tools import (
    pwn_checksec, pwn_file_info, pwn_disassemble,
    pwn_pattern_create, pwn_pattern_offset,
    pwn_rop_gadgets, pwn_rop_chain,
    pwn_remote_exploit, pwn_remote_interact,
    pwn_shellcode_generate, pwn_search_string,
    pwn_fmtstr_exploit
)
from src.tools.logic_vuln import (
    logic_session_http, logic_session_close, logic_session_cookies,
    logic_idor_test, logic_param_fuzz,
    logic_race_condition, logic_flow_test
)
from src.config.settings import Settings
from src.config.providers import LLMProviderType
from src.utils.logger import setup_logging

app = typer.Typer()
console = Console()


def _recover_from_logs(challenge_url: str) -> dict:
    """从日志文件中提取关键发现，用于恢复会话

    当没有会话文件时，从最新的日志中提取AI的关键发现和工具结果。
    """
    import glob
    import re

    # 找到所有CTF日志文件，按修改时间排序
    log_files = sorted(glob.glob("logs/ctf_*.log"), key=os.path.getmtime, reverse=True)

    for log_file in log_files[:5]:  # 只检查最近5个日志
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # 检查日志是否包含目标URL
            if challenge_url not in content:
                continue

            # 提取关键发现
            context = {}
            history = []

            # 1. 提取漏洞类型
            vuln_patterns = [
                (r"SQL.*盲注|布尔盲注|blind.*sql", "SQL布尔盲注"),
                (r"文件上传|file.*upload", "文件上传"),
                (r"SSTI|模板注入", "SSTI模板注入"),
                (r"反序列化|deserialize", "反序列化"),
                (r"命令注入|RCE|command.*inject", "命令注入"),
                (r"文件包含|LFI|php://filter", "文件包含"),
            ]
            for pattern, vuln_name in vuln_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    context["vuln_type"] = vuln_name
                    break

            # 2. 提取已发现的flag片段（优先从工具返回中提取）
            flag_patterns = [
                r"body\[1:21\]: '([^']+)'",  # 从工具输出提取
                r"提取到.*?flag.*?[：:]?\s*[`'\"]([^'\"`]+)",
                r"(flst\{[a-zA-Z0-9_]{10,})",  # 至少10个字符
                r"(flag\{[a-zA-Z0-9_]{10,})",
                r"(ctf\{[a-zA-Z0-9_]{10,})",
                r"(NSSCTF\{[a-zA-Z0-9_]{10,})",
            ]
            for pattern in flag_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # 取最长的匹配
                    longest = max(matches, key=len) if matches else ""
                    if len(longest) >= 10:
                        context["extracted_data"] = longest
                        break

            # 3. 提取数据长度（找最后一个匹配，通常是最终确认的长度）
            length_matches = re.findall(r"length\(body\)[=<>]+(\d+).*?True", content)
            if length_matches:
                context["flag_length"] = int(length_matches[-1])  # 取最后一个

            # 4. 提取注入点
            inject_match = re.search(r"(http[s]?://[^\s\'\"]+lookup\.php[^\s\'\"]*)", content)
            if inject_match:
                context["vuln_endpoint"] = inject_match.group(1)

            # 5. 提取true/false marker
            if '"found":true' in content:
                context["true_marker"] = '"found":true'
            if '"found":false' in content:
                context["false_marker"] = '"found":false'

            # 6. 提取AI的思考分析（最后几条）
            ai_thoughts = re.findall(r"\[AI\].*?\[思考\](.*?)(?=\n\[工具执行结果\]|\nHTTP Request|\Z)", content, re.DOTALL)
            if ai_thoughts:
                # 取最后3条AI思考
                recent_thoughts = ai_thoughts[-3:]
                summary = "\n".join(t.strip()[:500] for t in recent_thoughts)
                history.append({
                    "role": "assistant",
                    "content": f"[上次分析摘要]\n{summary}"
                })

            # 7. 提取关键工具结果
            tool_results = re.findall(r"工具返回: \{.*?'output': '([^']{0,500})", content)
            if tool_results:
                key_results = tool_results[-5:]  # 最后5个工具结果
                history.append({
                    "role": "user",
                    "content": "工具执行结果:\n" + "\n---\n".join(key_results)
                })

            context["target"] = challenge_url
            context["recovered_from"] = log_file

            if context.get("vuln_type") or context.get("extracted_data"):
                return {"context": context, "history": history}

        except Exception:
            continue

    return None


def setup_agent(provider: str = "deepseek", model: str = "deepseek-v4-flash", mode: str = "pentest") -> PentestAgent:
    settings = Settings()

    #provider自定义
    if provider:
        settings.provider = provider
    #model自定义
    if model:
        settings.default_model = model
    
    provider_type = LLMProviderType(settings.provider.lower())
    agent = PentestAgent(settings, provider_type, mode=mode)
    
    http_client = HTTPClient()
    nmap_scanner = NmapScanner()
    crypto_tool = CryptoTool()
    code_executor = CodeExecutor()
    web_scanner = WebScanner()
    knowledge_search = KnowledgeSearchTool()

    agent.add_tool(
        "knowledge_search",
        knowledge_search.search,
        "检索本地知识库(SRC课程文档/工具说明/漏洞笔记)。涉及具体漏洞名(如若依/nacos/shiro)、工具名、课程内容时必须先调用本工具。参数必须包含query，可选top_k/category/content_type",
        {"query": "string", "top_k": "number", "category": "string", "content_type": "string"},
        required_params=["query"]
    )
    
    agent.add_tool(
        "http_get",
        http_client.get,
        "发送HTTP GET请求获取网页内容，参数必须包含url",
        {"url": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "http_post",
        http_client.post,
        "发送HTTP POST请求，参数必须包含url",
        {"url": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "nmap_scan",
        nmap_scanner.scan,
        "端口扫描，参数必须包含target，可选ports",
        {"target": "string", "ports": "string"},
        required_params=["target"]
    )
    
    agent.add_tool(
        "base64_encode",
        crypto_tool.base64_encode,
        "Base64编码，参数必须包含data",
        {"data": "string"},
        required_params=["data"]
    )
    
    agent.add_tool(
        "base64_decode",
        crypto_tool.base64_decode,
        "Base64解码，参数必须包含data",
        {"data": "string"},
        required_params=["data"]
    )
    
    agent.add_tool(
        "sha256_hash",
        crypto_tool.sha256_hash,
        "SHA256哈希，参数必须包含data",
        {"data": "string"},
        required_params=["data"]
    )
    
    agent.add_tool(
        "md5_hash",
        crypto_tool.md5_hash,
        "MD5哈希，参数必须包含data",
        {"data": "string"},
        required_params=["data"]
    )
    
    agent.add_tool(
        "execute_python",
        code_executor.execute_python,
        "执行Python代码，参数必须包含code",
        {"code": "string"},
        required_params=["code"]
    )
    
    agent.add_tool(
        "execute_bash",
        code_executor.execute_bash,
        "执行Bash命令，参数必须包含command",
        {"command": "string"},
        required_params=["command"]
    )
    
    agent.add_tool(
        "directory_brute",
        web_scanner.directory_brute,
        "目录枚举，参数必须包含base_url和wordlist",
        {"base_url": "string", "wordlist": "array"},
        required_params=["base_url"]
    )
    
    agent.add_tool(
        "subdomain_enum",
        web_scanner.subdomain_enum,
        "子域名枚举，参数必须包含domain和wordlist",
        {"domain": "string", "wordlist": "array"},
        required_params=["domain"]
    )
    
    agent.add_tool(
        "detect_waf",
        web_scanner.detect_waf,
        "WAF检测，参数必须包含url",
        {"url": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "sqlmap_scan",
        sqlmap_scan,
        "SQLMap扫描，参数必须包含url，可选options",
        {"url": "string", "options": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "sqlmap_detect",
        sqlmap_detect,
        "SQL注入检测，参数必须包含url",
        {"url": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "sqlmap_get_databases",
        sqlmap_get_databases,
        "获取数据库列表，参数必须包含url",
        {"url": "string"},
        required_params=["url"]
    )
    
    agent.add_tool(
        "sqlmap_get_tables",
        sqlmap_get_tables,
        "获取数据表列表，参数必须包含url和db",
        {"url": "string", "db": "string"},
        required_params=["url", "db"]
    )
    
    agent.add_tool(
        "sqlmap_dump_table",
        sqlmap_dump_table,
        "导出数据表，参数必须包含url、db和table",
        {"url": "string", "db": "string", "table": "string"},
        required_params=["url", "db", "table"]
    )
    
    agent.add_tool(
        "fenjing_scan",
        fenjing_scan,
        (
            "SSTI(服务端模板注入)自动化扫描工具(支持Jinja2/Flask/Mako等，自动绕过WAF)。"
            "调用示例:\n"
            "- 扫描GET参数注入点: fenjing_scan(url='http://target/secret?secret={{payload}}')\n"
            "- 扫描POST参数: fenjing_scan(url='http://target/', method='POST', extra_data='name={{payload}}')\n"
            "- 指定参数名攻击: fenjing_scan(url='http://target/', inputs='secret,name', exec_cmd='cat /flag')\n"
            "- 快速扫描: fenjing_scan(url='http://target/?q={{payload}}', detect_mode='fast')\n"
            "参数说明:\n"
            "- url(必填): 目标URL, 注入点用{{payload}}占位\n"
            "- method: GET/POST, 默认POST\n"
            "- inputs: 参数名(逗号分隔), 为空则自动发现,不为空则用crack命令精确攻击\n"
            "- exec_cmd: 攻击成功后执行的命令(如cat /flag)\n"
            "- extra_params/extra_data: 额外GET/POST参数\n"
            "- headers/cookies: 自定义请求头/Cookie\n"
            "- detect_mode: accurate(默认)/fast\n"
            "- environment: jinja2(默认)/flask/mako\n"
            "已内置重试机制(最多2次,指数退避)和网络错误恢复。"
        ),
        {
            "url": "string",
            "method": "string",
            "inputs": "string",
            "exec_cmd": "string",
            "headers": "string",
            "cookies": "string",
            "extra_params": "string",
            "extra_data": "string",
            "detect_mode": "string",
            "environment": "string",
            "no_verify_ssl": "boolean",
            "proxy": "string",
        },
        required_params=["url"]
    )
    
    agent.add_tool(
        "fenjing_attack",
        fenjing_attack,
        (
            "SSTI自动化攻击工具(带默认命令执行,适合直接RCE)。"
            "与fenjing_scan相同,但默认exec_cmd='cat /flag'。"
            "调用示例:\n"
            "- 自动扫描并cat /flag: fenjing_attack(url='http://target/secret?secret={{payload}}')\n"
            "- 指定参数攻击: fenjing_attack(url='http://target/', inputs='secret')\n"
            "- 自定义命令: fenjing_attack(url='http://target/', exec_cmd='id')\n"
            "参数说明同fenjing_scan。"
        ),
        {
            "url": "string",
            "method": "string",
            "inputs": "string",
            "exec_cmd": "string",
            "headers": "string",
            "cookies": "string",
            "detect_mode": "string",
            "environment": "string",
            "no_verify_ssl": "boolean",
            "proxy": "string",
        },
        required_params=["url"]
    )
    
    agent.add_tool(
        "log4j_scan",
        log4j_scan,
        "Log4j漏洞检测，参数必须包含target，可选port和protocol",
        {"target": "string", "port": "integer", "protocol": "string"},
        required_params=["target"]
    )
    
    agent.add_tool(
        "log4j_exploit",
        log4j_exploit,
        "Log4j漏洞利用，参数必须包含target，可选port、protocol和command",
        {"target": "string", "port": "integer", "protocol": "string", "command": "string"},
        required_params=["target"]
    )

    agent.add_tool(
        "ysoserial_generate",
        ysoserial_generate,
        "生成ysoserial反序列化payload，参数必须包含gadget和command",
        {"gadget": "string", "command": "string"},
        required_params=["gadget", "command"]
    )
    
    agent.add_tool(
        "ysoserial_list",
        ysoserial_list,
        "列出所有可用的ysoserial gadgets",
        {},
        required_params=[]
    )
    
    agent.add_tool(
        "ysoserial_test",
        ysoserial_test,
        "测试ysoserial payload，参数必须包含payload_b64和target，可选port",
        {"payload_b64": "string", "target": "string", "port": "integer"},
        required_params=["payload_b64", "target"]
    )

    # === 文件上传工具 ===
    agent.add_tool(
        "file_upload",
        file_upload,
        "上传文件到目标URL，参数必须包含url，可选filename、content、field_name、content_type、extra_fields",
        {"url": "string", "filename": "string", "content": "string", "field_name": "string", "content_type": "string", "extra_fields": "string"},
        required_params=["url"]
    )

    agent.add_tool(
        "file_upload_webshell",
        file_upload_webshell,
        (
            "上传预置webshell模板。shell_type可选: "
            "php(基础), phtml, "
            "php_gif/gif马, php_jpg/jpg马, php_png/png马, "
            "php_script(script标签绕过<?), php_short_tag(短标签), "
            "php_gif_script/gif+script, php_jpg_script/jpg+script, "
            "php_info(phpinfo信息泄露), php_env(环境变量泄露), php_gif_info, "
            "htaccess_files_match(FilesMatch,纯文本不加图片头!), htaccess_addtype, user_ini(.user.ini), "
            "jsp, asp。"
            "参数必须包含url，可选shell_type(默认php)、field_name、extra_fields"
        ),
        {"url": "string", "shell_type": "string", "field_name": "string", "extra_fields": "string"},
        required_params=["url"]
    )

    agent.add_tool(
        "file_upload_bypass",
        file_upload_bypass,
        "自动尝试多种扩展名绕过上传PHP webshell（.php/.php5/.phtml/.PHP等），参数必须包含url，可选field_name、extra_fields",
        {"url": "string", "field_name": "string", "extra_fields": "string"},
        required_params=["url"]
    )

    agent.add_tool(
        "file_upload_auto",
        file_upload_auto,
        (
            "文件上传自动利用工具(推荐优先使用)。多策略轮询+主动RCE验证:\n"
            "策略1: .htaccess(AddType纯文本,MIME=image/jpeg) + 图片马(script标签) → POST验证RCE\n"
            "策略2: .htaccess(FilesMatch) + 图片马 → POST验证RCE\n"
            "策略3: .user.ini + 图片马 → 验证RCE\n"
            "策略4: 直接扩展名(.php/.phtml/.php5/.pht/.PHP/.phar) → 逐个验证RCE\n"
            "策略5: 双扩展名(.php.jpg) Apache多后缀 → 验证RCE\n"
            "策略6: 图片马直接上传(.jpg含PHP代码) → 验证RCE\n"
            "策略7: phpinfo/php_env信息泄露(disable_functions时)\n"
            "验证方式: 上传后POST cmd=echo PHP_RCE_VERIFY_OK; 检查回显，确认真正RCE。\n"
            "参数: url(上传接口URL), base_url(站点根URL,可选), field_name(默认file), extra_fields(额外表单字段)"
        ),
        {"url": "string", "base_url": "string", "field_name": "string", "extra_fields": "string"},
        required_params=["url"]
    )

    # === Flask会话Cookie工具 ===
    agent.add_tool(
        "flask_session_decode",
        flask_session_decode,
        "解码Flask session cookie查看内容（调用flask-session-cookie-manager工具），参数必须包含cookie，可选secret_key（提供时会验证签名）",
        {"cookie": "string", "secret_key": "string"},
        required_params=["cookie"]
    )

    agent.add_tool(
        "flask_session_encode",
        flask_session_encode,
        "使用secret_key伪造Flask session cookie（调用flask-session-cookie-manager工具），data参数为Python dict字符串如{'user':'admin'}，必须包含data和secret_key",
        {"data": "string", "secret_key": "string"},
        required_params=["data", "secret_key"]
    )

    agent.add_tool(
        "flask_session_brute",
        flask_session_brute,
        "爆破Flask session的secret_key，参数必须包含cookie，可选wordlist(逗号分隔)",
        {"cookie": "string", "wordlist": "string"},
        required_params=["cookie"]
    )

    # === PHP/Python反序列化工具 ===
    agent.add_tool(
        "php_deserialize_generate",
        php_deserialize_generate,
        "生成PHP反序列化payload。参数: gadget_type(rce/wakeup/phar/tostring/custom), command(命令), class_name(类名,动态计算长度), props(自定义属性JSON数组,格式:[{name,value,visibility}],用于复杂反序列化结构), wakeup_bypass(是否绕过__wakeup,CVE-2016-7124,设为true时属性计数+1), extra_count(额外增加的属性数,用于WAF绕过), visibility支持public/protected/private",
        {"gadget_type": "string", "command": "string", "class_name": "string", "props": "string", "wakeup_bypass": "boolean", "extra_count": "integer"},
        required_params=[]
    )

    agent.add_tool(
        "php_deserialize_pop",
        php_deserialize_pop,
        "根据POP链信息生成PHP反序列化payload，参数必须包含entry_class和chain(JSON格式)，可选command",
        {"entry_class": "string", "chain": "string", "command": "string"},
        required_params=["entry_class", "chain"]
    )

    agent.add_tool(
        "php_reference_bypass",
        php_reference_bypass,
        "生成PHP引用(R:)绕过__wakeup()的反序列化payload(手动模式)。当__wakeup()会清空属性但__destruct()中有赋值操作时，可用引用链恢复属性值。参数: class_name(类名), props(属性JSON数组,按顺序), command(默认命令)。props格式: [{name,type(object/string/int/null/reference),class(嵌套对象类名),value,ref(引用ID)}]。被引用属性必须在引用属性之前定义!",
        {"class_name": "string", "props": "string", "command": "string"},
        required_params=["class_name", "props"]
    )

    agent.add_tool(
        "php_reference_bypass_auto",
        php_reference_bypass_auto,
        "自动生成PHP引用绕过payload(快捷模式,推荐)。适用于__wakeup清空$a, __destruct中$b=$c, eval($a)的经典模式。自动处理属性顺序和引用ID。参数: class_name(类名), command(命令,建议先用ls探测), ref_target(被引用属性名,默认b), ref_src(引用者属性名,默认a), command_prop(命令存放属性,默认c)",
        {"class_name": "string", "command": "string", "ref_target": "string", "ref_src": "string", "command_prop": "string"},
        required_params=["class_name"]
    )

    agent.add_tool(
        "python_pickle_generate",
        python_pickle_generate,
        "生成Python pickle反序列化payload执行命令，参数必须包含command",
        {"command": "string"},
        required_params=[]
    )

    agent.add_tool(
        "python_pickle_reverse_shell",
        python_pickle_reverse_shell,
        "生成Python pickle反弹shell payload，参数必须包含host和port",
        {"host": "string", "port": "integer"},
        required_params=["host", "port"]
    )

    # === 加密分析与加密SSTI工具 ===
    agent.add_tool(
        "crypto_detect",
        crypto_detect,
        "识别加密算法(从明密文对推断)。参数samples为JSON数组: [{plaintext, ciphertext}]。返回算法类型(xor_single_byte/xor_multi_byte/rc4_likely/aes_likely)、密钥(若可推断)、建议工具。至少提供1组样本，建议2组以上以区分XOR和RC4",
        {"samples": "string"},
        required_params=["samples"]
    )

    agent.add_tool(
        "rc4_crypt",
        rc4_crypt,
        "RC4加密/解密(对称同一操作)。参数: data(待处理数据), key(密钥), output_format(hex/base64/url/utf8), input_format(utf8/hex/base64)。CTF场景: 当接口用RC4加密输入时，用此工具加密SSTI payload再提交",
        {"data": "string", "key": "string", "output_format": "string", "input_format": "string"},
        required_params=["data", "key"]
    )

    agent.add_tool(
        "xor_crypt",
        xor_crypt,
        "XOR加密/解密(对称)。参数: data, key(支持0xNN单字节如0x55), output_format(hex/base64/url/utf8), input_format(utf8/hex/base64)",
        {"data": "string", "key": "string", "output_format": "string", "input_format": "string"},
        required_params=["data", "key"]
    )

    agent.add_tool(
        "generate_ssti_encrypted_payload",
        generate_ssti_encrypted_payload,
        "生成加密后的SSTI payload(用于绕过safe()等字符过滤)。参数: payload(SSTI明文如{{config}}), algorithm(rc4/xor), key(密钥), output_format(url/hex/base64,默认url可直接作参数值), forbidden_chars(禁止字符,可选,用于验证绕过效果)",
        {"payload": "string", "algorithm": "string", "key": "string", "output_format": "string", "forbidden_chars": "string"},
        required_params=["payload"]
    )

    # === Werkzeug调试器工具 ===
    agent.add_tool(
        "werkzeug_debugger_probe",
        werkzeug_debugger_probe,
        "探测Werkzeug调试器是否开启及所需认证方式。参数必须包含base_url。返回是否需要PIN、版本提示",
        {"base_url": "string"},
        required_params=["base_url"]
    )

    agent.add_tool(
        "werkzeug_debugger_exec",
        werkzeug_debugger_exec,
        "通过Werkzeug调试器控制台执行Python代码。参数: base_url(目标根URL), code(Python代码如print(open('/flag').read())), secret(调试器SECRET,从源码提取,Werkzeug<2.1需要), pin(PIN码,Werkzeug>=2.1需要)",
        {"base_url": "string", "code": "string", "secret": "string", "pin": "string"},
        required_params=["base_url", "code"]
    )

    # === SSTI路由探测工具 ===
    agent.add_tool(
        "ssti_route_probe",
        ssti_route_probe,
        "自动探测SSTI入口路由(遍历常见路径和参数名,用{{7*7}}检测)。参数: base_url(目标根URL), paths(自定义路径逗号分隔,可选), params(自定义参数名逗号分隔,可选), test_payload(自定义测试payload,可选)。返回命中的path+param组合",
        {"base_url": "string", "paths": "string", "params": "string", "test_payload": "string"},
        required_params=["base_url"]
    )

    # === SSTI绕过辅助工具 ===
    agent.add_tool(
        "ssti_bypass_generate",
        ssti_bypass_generate,
        (
            "SSTI绕过payload生成工具(针对safe()等黑名单过滤)。"
            "内置多种绕过模板: attr过滤器、lipsum/cycler全局对象、字符串拼接等。"
            "调用示例:\n"
            "- 绕过class/read/popen关键字读flag: ssti_bypass_generate(target='read_file', command='cat /flag', forbidden_keywords='class,mro,read,popen')\n"
            "- 执行命令: ssti_bypass_generate(target='rce', command='id', forbidden_keywords='popen,system')\n"
            "- 列目录: ssti_bypass_generate(target='list_dir', forbidden_keywords='listdir')\n"
            "- 自定义payload绕过: ssti_bypass_generate(custom_payload='{{config}}', forbidden_keywords='config')\n"
            "参数说明:\n"
            "- target: read_file/rce/list_dir/config, 默认read_file\n"
            "- command: 要执行的命令, 默认cat /flag\n"
            "- forbidden_chars: 禁止字符(如 <>;|)\n"
            "- forbidden_keywords: 禁止关键字(逗号分隔,如 class,mro,read,popen)\n"
            "- custom_payload: 自定义payload模板(可选,提供时基于此绕过)\n"
            "返回usable_payloads列表,用http_get/http_post提交即可。"
        ),
        {"target": "string", "command": "string", "forbidden_chars": "string", "forbidden_keywords": "string", "custom_payload": "string"},
        required_params=[]
    )

    # === HTTP重试请求工具 ===
    agent.add_tool(
        "http_request_retry",
        http_request_retry,
        (
            "带指数退避重试的HTTP请求工具(解决靶场不稳定/超时问题)。"
            "超时后自动等待1s/2s/4s重试,避免快速请求加剧服务端压力。"
            "调用示例:\n"
            "- GET请求: http_request_retry(url='http://target/page')\n"
            "- POST表单: http_request_retry(url='http://target/', method='POST', data='name=test&cmd=id')\n"
            "- POST JSON: http_request_retry(url='http://target/api', method='POST', data='{\"key\":\"value\"}')\n"
            "参数说明:\n"
            "- url(必填): 目标URL\n"
            "- method: GET/POST, 默认GET\n"
            "- data: POST数据(form格式key=value或JSON字符串)\n"
            "- headers: 自定义头(JSON字符串或Key: value换行格式)\n"
            "- max_retries: 最大重试次数, 默认3\n"
            "- base_delay: 基础延迟秒数, 默认1.0(实际延迟=base_delay*2^attempt)"
        ),
        {"url": "string", "method": "string", "data": "string", "headers": "string", "max_retries": "integer", "base_delay": "number"},
        required_params=["url"]
    )

    # === HTTP原始请求工具（替代execute_python写HTTP请求）===
    agent.add_tool(
        "http_raw",
        http_raw,
        (
            "高级HTTP请求工具(支持自定义headers/method/body/重定向控制)。"
            "当需要发送带自定义headers的HTTP请求时，优先使用此工具而非execute_python，避免Python代码语法错误。\n"
            "调用示例:\n"
            "- 自定义UA: http_raw(url='http://target/', headers='{\"User-Agent\": \"Mozilla/5.0\"}')\n"
            "- IP伪造: http_raw(url='http://target/', headers='User-Agent: test\\nX-Forwarded-For: 127.0.0.1')\n"
            "- POST JSON: http_raw(url='http://target/api', method='POST', body='{\"key\":\"value\"}')\n"
            "- POST表单: http_raw(url='http://target/', method='POST', body='name=test&pass=123')\n"
            "- 不跟随重定向: http_raw(url='http://target/admin', follow_redirects=False)\n"
            "- 分段获取被截断内容: http_raw(url='http://target/', body_offset=2000) 从第2000字符续取\n"
            "参数说明:\n"
            "- url(必填): 目标URL\n"
            "- method: GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH, 默认GET\n"
            "- headers: 自定义头(JSON字符串或'Key: Value\\nKey2: Value2'格式)\n"
            "- body: 请求体，按原始字节发送，工具不做编码转换。**直接传原始字符，不要预先URL编码**"
            "（标准表单服务端会自动解码，php://input原样读取更应传原始字符；报错含unexpected '%'时改传原始字符）\n"
            "- follow_redirects: 是否跟随重定向, 默认True\n"
            "- timeout: 超时秒数, 默认15\n"
            "- body_offset: 分段获取起始位置(默认0)，结果含 body_truncated=true 时用它续取剩余部分\n"
            "- body_limit: 本次返回body最大长度(默认10000)\n"
            "注意: HTML响应自动剥样式标签并反转义(&lt;→<)，body为可直接阅读的文本；"
            "返回含 body_total/body_offset/body_truncated 字段用于判断是否需要分段续取"
        ),
        {"url": "string", "method": "string", "headers": "string", "body": "string",
         "follow_redirects": "boolean", "timeout": "integer",
         "body_offset": "integer", "body_limit": "integer"},
        required_params=["url"]
    )

    # === Payload生成工具（替代写循环批量测试代码，避免被LLM截断）===
    agent.add_tool(
        "payload_gen",
        payload_gen,
        (
            "生成CTF常用payload列表(避免写循环代码被截断导致语法错误)。\n"
            "当需要批量测试多种payload变体(IP伪造头/UA绕过/LFI路径/SQL注入/SSTI/命令注入等)时，"
            "优先使用此工具获取payload列表，再用http_raw逐个测试，**禁止用execute_python写for循环脚本**。\n"
            "调用示例:\n"
            "- 查看所有类别: payload_gen(category='list')\n"
            "- IP伪造头: payload_gen(category='ip_bypass') -> 返回20+个IP伪造headers变体\n"
            "- UA绕过: payload_gen(category='ua_bypass') -> 返回20+个User-Agent绕过变体\n"
            "- 文件包含: payload_gen(category='lfi_paths') -> 返回40+个LFI路径\n"
            "- 目录爆破: payload_gen(category='dir_wordlist') -> 返回80+个敏感路径\n"
            "- SQL注入: payload_gen(category='sqli') -> 返回30+个SQLi payload\n"
            "- SSTI: payload_gen(category='ssti') -> 返回25+个SSTI payload\n"
            "- 命令注入: payload_gen(category='cmdi') -> 返回30+个命令注入payload\n"
            "- XXE: payload_gen(category='xxe') -> 返回12+个XXE payload\n"
            "- 反序列化: payload_gen(category='deserialize') -> 返回PHP/Python常见POP链入口类\n"
            "- 认证绕过: payload_gen(category='auth_bypass') -> 返回30+个弱口令+SQL绕过+数组绕过\n"
            "- XSS: payload_gen(category='xss') -> 返回20+个XSS payload\n"
            "参数说明:\n"
            "- category(必填): payload类别, 传'list'查看所有可用类别\n"
            "- custom_data(可选): 自定义payload, 每行一个, 会追加到结果列表"
        ),
        {"category": "string", "custom_data": "string"},
        required_params=["category"]
    )

    # === SQL盲注自动化提取工具（一次调用提取完整数据，避免逐字符消耗迭代）===
    agent.add_tool(
        "sqli_blind_extract",
        sqli_blind_extract,
        (
            "SQL布尔盲注自动化提取数据(一次调用完成全部字符提取，避免用execute_python写盲注脚本)。\n"
            "当发现布尔盲注漏洞时，用此工具替代手动逐字符测试，自动二分查找提取完整数据。\n"
            "调用示例:\n"
            "- 基本用法: sqli_blind_extract(url='http://target/api?code=INJECT_HERE', true_marker='found\":true', query_template=\"x' OR ASCII(SUBSTR(body,{pos},1))>{char}--\")\n"
            "- 已知长度: sqli_blind_extract(url='...', data_length=43, true_marker='...', query_template='...')\n"
            "- POST注入: sqli_blind_extract(url='http://target/api', method='POST', body='code=INJECT_HERE', true_marker='...', query_template='...')\n"
            "参数说明:\n"
            "- url(必填): 目标URL，含INJECT_HERE占位符或用inject_param指定参数名\n"
            "- true_marker(必填): 布尔为真时响应中的标志(如 found\\\":true)\n"
            "- false_marker(可选): 布尔为假标志(如 found\\\":false)\n"
            "- query_template(必填): SQL注入模板，用{pos}和{char}占位\n"
            "  示例: \\\"x' OR (SELECT ASCII(SUBSTR(body,{pos},1)) FROM records WHERE is_public=false)>{char}--\\\"\n"
            "- data_length(可选): 已知数据长度，0=自动检测\n"
            "- headers(可选): 自定义headers\n"
            "- method: GET/POST, 默认GET\n"
            "- body: POST请求体模板(含INJECT_HERE)\n"
            "- charset(可选): 限定字符集加速提取"
        ),
        {
            "url": "string", "inject_param": "string", "true_marker": "string",
            "false_marker": "string", "query_template": "string", "method": "string",
            "body": "string", "headers": "string", "data_length": "integer",
            "charset": "string", "max_length": "integer", "timeout": "integer"
        },
        required_params=["url", "true_marker", "query_template"]
    )

    # === 密码自动分析解密工具（一次调用尝试所有常见解密方法）===
    agent.add_tool(
        "crypto_decode_all",
        crypto_decode_all,
        (
            "自动尝试所有常见CTF密码学解密方法(一次调用完成，避免多次迭代尝试)。\n"
            "支持: 凯撒密码(25种位移)/ROT13/ROT47/Atbash/Base64/Base32/Hex/URL解码/Vigenere/摩尔斯/培根密码。\n"
            "当遇到加密的flag或密文时，用此工具自动识别加密方式并解密。\n"
            "调用示例:\n"
            "- 基本用法: crypto_decode_all(data='flst{ujufylksinqnke4m', known_prefix='flag{')\n"
            "- 无已知前缀: crypto_decode_all(data='SGVsbG8gV29ybGQ=')\n"
            "参数说明:\n"
            "- data(必填): 待解密的字符串\n"
            "- known_prefix(可选): 已知明文前缀(如flag{)，用于验证解密结果\n"
            "- known_format(可选): 已知格式(如 flag{...})\n"
            "返回: 所有解密结果列表 + 最佳匹配 + 建议说明"
        ),
        {"data": "string", "known_prefix": "string", "known_format": "string"},
        required_params=["data"]
    )

    # === PWN二进制漏洞利用工具 ===
    agent.add_tool(
        "pwn_checksec",
        pwn_checksec,
        "检查二进制文件安全保护机制(NX/PIE/Canary/RELRO)及关键函数地址。参数必须包含binary_path(本地二进制文件路径)",
        {"binary_path": "string"},
        required_params=["binary_path"]
    )

    agent.add_tool(
        "pwn_file_info",
        pwn_file_info,
        "获取二进制文件基本信息(类型/架构/strings)。参数必须包含binary_path(本地二进制文件路径)。返回file类型、关键字符串、架构信息",
        {"binary_path": "string"},
        required_params=["binary_path"]
    )

    agent.add_tool(
        "pwn_disassemble",
        pwn_disassemble,
        "反汇编二进制文件的指定函数或地址区域。参数: binary_path(必填), function_name(函数名如main), address(十六进制地址如0x8048000,与function_name二选一), count(反汇编指令数,默认50)",
        {"binary_path": "string", "function_name": "string", "address": "string", "count": "integer"},
        required_params=["binary_path"]
    )

    agent.add_tool(
        "pwn_pattern_create",
        pwn_pattern_create,
        "生成De Bruijn循环模式用于缓冲区溢出偏移量计算。参数: length(模式长度,默认200)",
        {"length": "integer"},
        required_params=[]
    )

    agent.add_tool(
        "pwn_pattern_offset",
        pwn_pattern_offset,
        "计算给定值在循环模式中的偏移量。参数: value(崩溃地址如0x41414141或字符串如Aa0A)。用于确定缓冲区溢出到返回地址的偏移",
        {"value": "string"},
        required_params=["value"]
    )

    agent.add_tool(
        "pwn_rop_gadgets",
        pwn_rop_gadgets,
        "搜索二进制文件中的ROP gadgets(含pop rdi/rsi/rdx/ret等常用gadget)。参数必须包含binary_path",
        {"binary_path": "string", "depth": "integer"},
        required_params=["binary_path"]
    )

    agent.add_tool(
        "pwn_rop_chain",
        pwn_rop_chain,
        "构建ROP链调用指定函数。参数: binary_path(必填), func_name(函数名如system/execve), args(参数,逗号分隔,字符串用引号如'/bin/sh',十六进制如0x8048000,数字如1)",
        {"binary_path": "string", "func_name": "string", "args": "string"},
        required_params=["binary_path", "func_name"]
    )

    agent.add_tool(
        "pwn_remote_exploit",
        pwn_remote_exploit,
        "连接远程PWN服务并发送payload(支持hex和raw格式)。参数: host(目标IP), port(端口), payload(payload内容,支持\\xHH转义或raw文本), recv_timeout(接收超时秒,默认5)。返回初始数据和响应",
        {"host": "string", "port": "integer", "payload": "string", "recv_timeout": "integer"},
        required_params=["host", "port", "payload"]
    )

    agent.add_tool(
        "pwn_remote_interact",
        pwn_remote_interact,
        "连接远程PWN服务进行交互式操作(发送多条命令)。参数: host, port, commands(换行分隔的命令列表,每行一条), recv_timeout(默认5)。适用于菜单题、需要先选选项再利用的场景",
        {"host": "string", "port": "integer", "commands": "string", "recv_timeout": "integer"},
        required_params=["host", "port"]
    )

    agent.add_tool(
        "pwn_shellcode_generate",
        pwn_shellcode_generate,
        "生成shellcode(汇编+机器码)。参数: arch(i386/amd64/arm/thumb,默认amd64), os_name(linux/windows,默认linux), shellcode_type(sh/exec/cat_flag/read_flag), exec_cmd(exec类型时指定命令)。返回汇编代码和十六进制机器码",
        {"arch": "string", "os_name": "string", "shellcode_type": "string", "exec_cmd": "string"},
        required_params=[]
    )

    agent.add_tool(
        "pwn_search_string",
        pwn_search_string,
        "在二进制文件中搜索指定字符串返回地址(如搜索/bin/sh)。参数必须包含binary_path和search_string",
        {"binary_path": "string", "search_string": "string"},
        required_params=["binary_path", "search_string"]
    )

    agent.add_tool(
        "pwn_fmtstr_exploit",
        pwn_fmtstr_exploit,
        "格式化字符串漏洞利用工具。参数: host, port, offset(格式化参数偏移), payload_type(leak泄漏地址/write写任意地址), read_len(leak时读取长度), write_addr(write时目标地址十六进制), write_val(write时写入值十六进制)",
        {"host": "string", "port": "integer", "offset": "integer", "payload_type": "string", "read_len": "integer", "write_addr": "string", "write_val": "string"},
        required_params=["host", "port", "offset"]
    )

    # === 逻辑漏洞检测工具 ===
    agent.add_tool(
        "logic_session_http",
        logic_session_http,
        "会话保持HTTP请求(跨调用维持Cookie/Token)。用于登录后操作、多步骤业务流程。参数: session_id(会话标识如user1/admin,相同ID共享Cookie), method(GET/POST/PUT/DELETE), url, headers(JSON字符串), data(表单JSON), json_data(JSON数据,与data二选一)",
        {"session_id": "string", "method": "string", "url": "string", "headers": "string", "data": "string", "json_data": "string"},
        required_params=["session_id", "method", "url"]
    )

    agent.add_tool(
        "logic_session_close",
        logic_session_close,
        "关闭指定会话释放资源。参数: session_id(会话ID)",
        {"session_id": "string"},
        required_params=["session_id"]
    )

    agent.add_tool(
        "logic_session_cookies",
        logic_session_cookies,
        "获取指定会话当前的Cookie。参数: session_id(会话ID)",
        {"session_id": "string"},
        required_params=["session_id"]
    )

    agent.add_tool(
        "logic_idor_test",
        logic_idor_test,
        "越权检测(IDOR/水平/垂直越权)。遍历/递增ID参数检测是否可访问其他用户数据。参数: url(目标URL,可用__VALUE__占位符), param_name(参数名如user_id), current_value(当前用户ID), method(GET/POST), test_range(自定义测试值逗号分隔,留空自动生成), headers(JSON), session_id(会话ID)",
        {"url": "string", "param_name": "string", "current_value": "string", "method": "string", "test_range": "string", "headers": "string", "session_id": "string"},
        required_params=["url", "param_name", "current_value"]
    )

    agent.add_tool(
        "logic_param_fuzz",
        logic_param_fuzz,
        "参数边界值Fuzz测试(负数/零/超大值/空值/类型混淆/注入探测)。参数: url, method(GET/POST), param_name(参数名), param_value(原始值), extra_params(其他固定参数JSON), headers(JSON), session_id",
        {"url": "string", "method": "string", "param_name": "string", "param_value": "string", "extra_params": "string", "headers": "string", "session_id": "string"},
        required_params=["url", "param_name", "param_value"]
    )

    agent.add_tool(
        "logic_race_condition",
        logic_race_condition,
        "竞争条件测试(并发请求检测余额双花/优惠券重复使用/投票刷票)。参数: url, method, data(表单JSON), json_data(JSON数据), headers(JSON), concurrency(并发数默认10最大50), delay_ms(请求间延迟毫秒,0=同时), session_id",
        {"url": "string", "method": "string", "data": "string", "json_data": "string", "headers": "string", "concurrency": "integer", "delay_ms": "integer", "session_id": "string"},
        required_params=["url"]
    )

    agent.add_tool(
        "logic_flow_test",
        logic_flow_test,
        "业务流程绕过测试(跳步/重放/乱序)。参数: steps(JSON数组字符串,每步含name/method/url/headers/data/json_data/extract), session_id(会话ID)。extract提取变量用{{var_name}}在后续步骤引用。自动测试: 正常流程→跳过中间步→重放最后步",
        {"steps": "string", "session_id": "string"},
        required_params=["steps"]
    )

    return agent


@app.command()
def run(
    prompt: Optional[str] = None,
    provider: str = typer.Option("deepseek", "--provider", "-p", help="LLM Provider: openai, openrouter, deepseek, anthropic, google, local"),
    model: str = typer.Option("deepseek-v4-flash", "--model", "-m", help="Model name")
):
    """运行渗透测试Agent"""
    setup_logging("run")
    agent = setup_agent(provider, model)
    
    console.print(Panel(f"[bold green]AI Agent 已启动[/bold green]\nProvider: {provider}\nModel: {model}"))
    
    if prompt:
        console.print(f"\n[bold blue]用户输入:[/bold blue] {prompt}")
        result = run_async(agent.run(prompt))
        console.print(Panel(f"[bold blue]Agent输出:[/bold blue]\n{result}"))
    else:
        console.print("输入 'exit' 退出\n")
        
        while True:
            user_input = typer.prompt("> ")
            if user_input.lower() == "exit":
                break
            
            try:
                result = run_async(agent.run(user_input))
                console.print(Panel(f"[bold blue]Agent:[/bold blue]\n{result}"))
            except Exception as e:
                console.print(f"[bold red]错误:[/bold red] {e}")


@app.command()
def scan(
    target: str,
    provider: str = typer.Option("deepseek", "--provider", "-p"),
    model: str = typer.Option("deepseek-v4-flash", "--model", "-m")
):
    """扫描目标主机"""
    setup_logging("scan")
    agent = setup_agent(provider, model)
    agent.set_context("target", target)
    
    console.print(Panel(f"[bold green]开始扫描目标[/bold green]\nTarget: {target}\nProvider: {provider}\nModel: {model}"))
    
    prompt = f"对目标 {target} 进行全面的渗透测试。**重点聚焦目标端口，不要被其他开放端口分散注意力**。按照以下步骤进行：1) 端口扫描确认目标端口状态；2) 服务识别（HTTP测试→log4j_scan检测）；3) 漏洞分析（根据检测结果选择攻击路径）；4) 漏洞利用。"
    result = run_async(agent.run(prompt))
    console.print(Panel(f"[bold blue]扫描结果:[/bold blue]\n{result}"))


@app.command()
def ctf(
    challenge: str,
    provider: str = typer.Option("deepseek", "--provider", "-p"),
    model: str = typer.Option("deepseek-v4-flash", "--model", "-m"),
    continue_session: bool = typer.Option(False, "--continue", "-c", help="继续上次的会话"),
    from_url: str = typer.Option("", "--from", "-f", help="从指定旧URL复制会话成果到新靶场（题目相同但URL不同时用）")
):
    """解决CTF题目"""
    setup_logging("ctf")
    agent = setup_agent(provider, model, mode="ctf")

    # 会话文件路径
    session_file = ContextManager.get_session_filepath(challenge)

    # --from: 从旧URL的会话/日志复制成果到新URL
    if from_url:
        from_session_file = ContextManager.get_session_filepath(from_url)
        context_data, history_data = None, None

        # 1. 优先尝试旧会话文件
        if os.path.exists(from_session_file):
            tmp_cm = ContextManager()
            tmp_cm.load_from_file(from_session_file)
            context_data = tmp_cm.context
            history_data = tmp_cm.history
            source_type = "会话文件"
        else:
            # 2. 尝试从旧URL的日志恢复
            recovered = _recover_from_logs(from_url)
            if recovered:
                context_data = recovered["context"]
                history_data = recovered["history"]
                source_type = "日志恢复"

        if context_data is not None:
            # 替换URL：旧URL -> 新URL
            def replace_urls(obj, old_url, new_url):
                if isinstance(obj, str):
                    # 提取host部分进行更精确的替换
                    import re
                    old_host = re.search(r"https?://([^/]+)", old_url)
                    new_host = re.search(r"https?://([^/]+)", new_url)
                    if old_host and new_host:
                        obj = obj.replace(old_host.group(1), new_host.group(1))
                    return obj.replace(old_url.rstrip("/"), new_url.rstrip("/"))
                elif isinstance(obj, dict):
                    return {k: replace_urls(v, old_url, new_url) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [replace_urls(item, old_url, new_url) for item in obj]
                return obj

            context_data = replace_urls(context_data, from_url, challenge)
            history_data = replace_urls(history_data, from_url, challenge)

            # 写入新会话
            agent.context_manager.context = context_data
            agent.context_manager.history = []
            for msg in history_data:
                agent.context_manager.add_history(
                    msg.get("role", "user"),
                    msg.get("content", "")
                )

            console.print(Panel(
                f"[bold green]从旧靶场复制成果成功[/bold green]\n"
                f"来源: {source_type} ({from_url})\n"
                f"目标: {challenge}\n"
                f"已复制 {len(context_data)} 个关键发现, {len(history_data)} 条历史\n"
                f"所有URL已自动替换为新靶场"
            ))
            prompt = (
                f"这是CTF挑战，我们使用了与上一次相同的题目，但靶场URL已更换:\n{challenge}\n\n"
                f"之前的分析成果（漏洞类型、注入模板、已提取的数据等）已从「{from_url}」复制过来，\n"
                f"并且所有URL已替换为新靶场。请基于这些发现继续推进以找到flag。\n"
                f"如果是SQL盲注场景，直接调用 sqli_blind_extract 提取完整数据；\n"
                f"如果有加密flag，调用 crypto_decode_all 解密。"
            )
            # 立即保存新会话
            agent.context_manager.save_to_file(session_file)
        else:
            console.print(Panel(
                f"[bold red]未能从旧URL {from_url} 找到会话或日志[/bold red]\n"
                f"将从头开始新的CTF解题。"
            ))
            prompt = f"这是一个CTF挑战，请帮我分析并解决:\n{challenge}\n\n请按照CTF解题思路逐步分析，找到flag。"

    elif continue_session:
        # 从上次会话恢复
        if os.path.exists(session_file):
            agent.context_manager.load_from_file(session_file)
            history_count = len(agent.context_manager.history)
            context_count = len(agent.context_manager.context)
            console.print(Panel(
                f"[bold yellow]继续上次会话[/bold yellow]\n"
                f"Provider: {provider}\nModel: {model}\n"
                f"会话文件: {session_file}\n"
                f"已恢复 {history_count} 条历史记录, {context_count} 个上下文"
            ))
            prompt = (
                f"这是CTF挑战，我们继续上次的测试:\n{challenge}\n\n"
                f"之前的对话历史和上下文已恢复。请回顾之前的发现和进度，继续推进以找到flag。\n"
                f"如果有已发现的关键线索（如漏洞类型、已提取的部分数据等），请基于这些线索继续。\n"
                f"优先使用 sqli_blind_extract 提取完整数据，用 crypto_decode_all 解密。"
            )
        else:
            # 尝试从最新日志中提取关键发现
            console.print(Panel(
                f"[bold yellow]未找到会话文件: {session_file}[/bold yellow]\n"
                f"尝试从日志中恢复关键发现..."
            ))
            recovered = _recover_from_logs(challenge)
            if recovered:
                agent.context_manager.context = recovered["context"]
                for msg in recovered["history"]:
                    agent.context_manager.add_history(msg["role"], msg["content"])
                console.print(Panel(
                    f"[bold green]从日志中恢复了 {len(recovered['context'])} 个关键发现[/bold green]\n"
                    f"已恢复 {len(recovered['history'])} 条历史记录"
                ))
                prompt = (
                    f"这是CTF挑战，我们继续上次的测试:\n{challenge}\n\n"
                    f"之前的对话历史已从日志中恢复。请回顾之前的发现和进度，继续推进以找到flag。\n"
                    f"如果有已发现的关键线索（如漏洞类型、已提取的部分数据等），请基于这些线索继续。\n"
                    f"优先使用 sqli_blind_extract 提取完整数据，用 crypto_decode_all 解密。"
                )
            else:
                console.print(Panel(
                    f"[bold red]未能从日志中恢复关键发现[/bold red]\n"
                    f"将从头开始新的CTF解题。"
                ))
                prompt = f"这是一个CTF挑战，请帮我分析并解决:\n{challenge}\n\n请按照CTF解题思路逐步分析，找到flag。"
    else:
        console.print(Panel(f"[bold green]CTF解题模式[/bold green]\nProvider: {provider}\nModel: {model}"))
        prompt = f"这是一个CTF挑战，请帮我分析并解决:\n{challenge}\n\n请按照CTF解题思路逐步分析，找到flag。"

    result = run_async(agent.run(prompt))
    console.print(Panel(f"[bold blue]CTF解题结果:[/bold blue]\n{result}"))

    # 运行结束后自动保存会话
    agent.context_manager.save_to_file(session_file)
    console.print(f"[dim]会话已保存到: {session_file}[/dim]")
    console.print(f"[dim]下次可用 --continue 继续此会话: python3 src/main.py ctf \"{challenge}\" --continue[/dim]")


@app.command()
def tools():
    """列出所有可用工具"""
    agent = setup_agent()
    
    console.print(Panel("[bold green]可用工具列表[/bold green]"))
    tools = agent.loop_controller.tool_dispatcher.get_tools_description()
    console.print(tools)


if __name__ == "__main__":
    app()
