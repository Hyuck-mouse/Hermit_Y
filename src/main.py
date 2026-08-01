# -*- coding: utf-8 -*-
import asyncio
import sys
import os

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

from src.agent.core import PentestAgent
from src.tools.http_client import HTTPClient
from src.tools.nmap_scanner import NmapScanner
from src.tools.crypto import CryptoTool
from src.tools.code_executor import CodeExecutor
from src.tools.web_scanner import WebScanner
from src.tools.external_tools import (
    sqlmap_scan, sqlmap_detect, sqlmap_get_databases, sqlmap_get_tables, sqlmap_dump_table,
    fenjing_scan, fenjing_attack,
    log4j_scan, log4j_exploit,
    ysoserial_generate, ysoserial_list, ysoserial_test,
    kb_search, kb_get_vulnerability, kb_get_ctf_solution, kb_suggest_attack,
    file_upload, file_upload_webshell, file_upload_bypass, file_upload_auto,
    flask_session_decode, flask_session_encode, flask_session_brute,
    php_deserialize_generate, php_deserialize_pop, php_reference_bypass, php_reference_bypass_auto,
    python_pickle_generate, python_pickle_reverse_shell,
    crypto_detect, rc4_crypt, xor_crypt, generate_ssti_encrypted_payload,
    werkzeug_debugger_exec, werkzeug_debugger_probe,
    ssti_route_probe,
    ssti_bypass_generate,
    http_request_retry
)
from src.config.settings import Settings
from src.config.providers import LLMProviderType
from src.utils.logger import setup_logging

app = typer.Typer()
console = Console()


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
        "kb_search",
        kb_search,
        "知识库搜索，参数必须包含query，可选max_results",
        {"query": "string", "max_results": "integer"},
        required_params=["query"]
    )
    
    agent.add_tool(
        "kb_get_vulnerability",
        kb_get_vulnerability,
        "获取漏洞信息，参数必须包含vulnerability_type",
        {"vulnerability_type": "string"},
        required_params=["vulnerability_type"]
    )
    
    agent.add_tool(
        "kb_get_ctf_solution",
        kb_get_ctf_solution,
        "获取CTF解题思路，参数必须包含challenge_type",
        {"challenge_type": "string"},
        required_params=["challenge_type"]
    )
    
    agent.add_tool(
        "kb_suggest_attack",
        kb_suggest_attack,
        "获取攻击建议，参数必须包含service，可选port",
        {"service": "string", "port": "integer"},
        required_params=["service"]
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
        result = asyncio.run(agent.run(prompt))
        console.print(Panel(f"[bold blue]Agent输出:[/bold blue]\n{result}"))
    else:
        console.print("输入 'exit' 退出\n")
        
        while True:
            user_input = typer.prompt("> ")
            if user_input.lower() == "exit":
                break
            
            try:
                result = asyncio.run(agent.run(user_input))
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
    result = asyncio.run(agent.run(prompt))
    console.print(Panel(f"[bold blue]扫描结果:[/bold blue]\n{result}"))


@app.command()
def ctf(
    challenge: str,
    provider: str = typer.Option("deepseek", "--provider", "-p"),
    model: str = typer.Option("deepseek-v4-flash", "--model", "-m")
):
    """解决CTF题目"""
    setup_logging("ctf")
    agent = setup_agent(provider, model, mode="ctf")
    
    console.print(Panel(f"[bold green]CTF解题模式[/bold green]\nProvider: {provider}\nModel: {model}"))
    
    prompt = f"这是一个CTF挑战，请帮我分析并解决:\n{challenge}\n\n请按照CTF解题思路逐步分析，找到flag。"
    result = asyncio.run(agent.run(prompt))
    console.print(Panel(f"[bold blue]CTF解题结果:[/bold blue]\n{result}"))


@app.command()
def tools():
    """列出所有可用工具"""
    agent = setup_agent()
    
    console.print(Panel("[bold green]可用工具列表[/bold green]"))
    tools = agent.loop_controller.tool_dispatcher.get_tools_description()
    console.print(tools)


if __name__ == "__main__":
    app()
