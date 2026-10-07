"""工具技能卡生成:为源码脚本与二进制工具生成"怎么用"的精简文本。

设计:
  - 二进制(.exe/.jar/...): 不摄入内容,生成含工具名/路径/用途的技能卡,content_type=binary
  - 源码脚本(.py/.go/...): 提取文件头注释/docstring 作为用途提示,content_type=tool_card
  - 若向上 2 层目录内存在 README,说明工具用法已被文档覆盖,跳过卡片生成
"""
import logging
import re
from pathlib import Path
from typing import List, Optional

import config

log = logging.getLogger(__name__)

README_NAMES = {"readme", "readme.md", "readme.txt", "使用说明.md",
                "使用说明.txt", "usage.md", "usage.txt"}

# 工具名关键字 → 用途(小写子串精确匹配;宁可"未识别"也不要瞎猜)
TOOL_PURPOSE = {
    "jdumpspider": "heapdump 内存转储文件敏感信息提取",
    "heapdump": "heapdump 内存转储文件敏感信息提取",
    "turbo-intruder": "HTTP 高并发/竞争条件测试(Burp 插件)",
    "sqlmap": "SQL 注入自动化检测与利用",
    "nmap": "端口扫描与服务识别",
    "mpunpack": "微信小程序反编译/解包",
    "unpackminiapp": "微信小程序反编译/解包",
    "unpack": "小程序/应用反编译解包",
    "mfinger": "小程序指纹识别",
    "mfinder": "微信小程序信息收集/敏感信息发现",
    "swagger": "Swagger/API 接口泄露探测",
    "xray": "Web 漏洞自动化扫描",
    "fscan": "内网综合扫描(存活/端口/弱口令)",
    "fiddler": "HTTP(S) 抓包代理",
    "proxifier": "代理工具",
    "apifox": "API 接口调试/测试平台",
    "burp": "Web 抓包与漏洞测试平台",
    "behinder": "冰蝎 WebShell 管理",
    "godzilla": "哥斯拉 WebShell 管理",
    "antsword": "蚁剑 WebShell 管理",
    "frpc": "内网穿透反向代理客户端",
    "frps": "内网穿透反向代理服务端",
    "eyeurl": "资产测绘/截图探测",
    "ehole": "Web 指纹识别",
    "sessionkey": "微信小程序 SessionKey 加解密",
    "crypt": "加解密工具",
    "jndi": "JNDI 注入利用工具",
    "springboot": "SpringBoot 漏洞扫描",
    "dddd": "资产/漏洞自动化收集",
}


def is_readme(path: Path) -> bool:
    return path.name.lower() in README_NAMES or path.name.lower().startswith("readme")


def find_readme_upwards(path: Path, levels: int = 2) -> Optional[Path]:
    """从文件所在目录向上 levels 层找 README,找到说明工具用法已被覆盖。"""
    d = path.parent
    for _ in range(levels + 1):
        for child in d.iterdir() if d.exists() else []:
            if child.is_file() and is_readme(child):
                return child
        if d.parent == d:
            break
        d = d.parent
    return None


def is_tool_context(directory: Path) -> bool:
    """目录(含一层子目录)内存在源码或二进制文件,视为工具目录。"""
    try:
        children = list(directory.iterdir())
    except OSError:
        return False
    exts = config.CODE_EXTS | config.BINARY_EXTS
    for child in children:
        if child.is_file() and child.suffix.lower() in exts:
            return True
        if child.is_dir() and child.name not in config.IGNORE_DIRS:
            try:
                for sub in child.iterdir():
                    if sub.is_file() and sub.suffix.lower() in exts:
                        return True
            except OSError:
                continue
    return False


def _guess_purpose(name: str) -> str:
    lower = name.lower()
    # 先匹配最长关键字,避免 "unpack" 抢在 "mpunpack" 前面命中
    for key in sorted(TOOL_PURPOSE, key=len, reverse=True):
        if key in lower:
            return TOOL_PURPOSE[key]
    return "未识别用途,见同目录说明文档"


def _read_code_hints(path: Path, max_lines: int = 80) -> str:
    """提取脚本头部注释与 docstring 作为用途提示。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                lines.append(line)
    except OSError:
        return ""
    code = "".join(lines)
    hints = []
    doc = re.search(r'"""(.*?)"""', code, re.S) or re.search(r"'''(.*?)'''", code, re.S)
    if doc:
        hints.append(" ".join(doc.group(1).strip().splitlines()))
    for line in code.splitlines():
        s = line.strip()
        if s.startswith("#") and len(s) > 2:
            hints.append(s.lstrip("#! ").strip())
        elif s.startswith("//"):
            hints.append(s[2:].strip())
    return "\n".join(h for h in hints if h)[:600]


def build_binary_card(path: Path, source: str, origin: str, archive: str = "") -> str:
    """二进制工具技能卡文本(工具名前置并重复,提升关键词权重)。"""
    return "\n".join([
        "[工具卡] 工具名: %s" % path.stem,
        "文件名: %s" % path.name,
        "类型: 二进制工具 (%s)" % path.suffix.lower(),
        "用途: %s" % _guess_purpose(path.name),
        "来源: %s" % source,
        "所属: %s" % (archive or path.parent.name),
        "说明: 本地二进制,未摄入内容;Agent 可按路径直接调用或命令行执行。",
    ])


def build_code_card(path: Path, source: str, origin: str, archive: str = "") -> str:
    """源码脚本技能卡文本(头部注释/docstring 作为用途提示)。"""
    hints = _read_code_hints(path)
    parts = [
        "[工具卡] 工具名: %s" % path.stem,
        "文件名: %s" % path.name,
        "类型: 脚本工具 (%s)" % path.suffix.lower(),
        "用途: %s" % _guess_purpose(path.name),
        "来源: %s" % source,
        "所属: %s" % (archive or path.parent.name),
    ]
    if hints:
        parts.append("用途提示:\n%s" % hints)
    return "\n".join(parts)
