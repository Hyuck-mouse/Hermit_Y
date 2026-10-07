"""元数据推断:category(类别)、target(目标/漏洞标签)、chunk 质量过滤与包装。

category 取值:
  src_course  课程文档(默认)
  vuln_kb     漏洞笔记/实战案例(文件名含 漏洞/实战/挖掘/攻防 等)
  tools       工具说明、技能卡、配置/字典/payload

target 取值示例: ruoyi / nacos / jeecg / shiro / springboot / miniprogram ...
按路径与文件名关键字推断,可自行扩充 TARGET_KEYWORDS。
"""
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

import config

log = logging.getLogger(__name__)

# ---- 垃圾片段过滤:散行/孤立元数据/纯图片块没有语义,入库会占满 top-k ----
_JUNK_PATTERNS = [
    re.compile(r"^!\[.*?\]\(.*?\)$"),            # 整块只是一张图片
    re.compile(r"^[A-Za-z\-]+:\s*\S+$"),         # 纯 HTTP 头/键值对行
    re.compile(r"^```\w*$"),                     # 孤立代码块围栏
    re.compile(r"^#{1,6}\s*$"),                  # 空标题
]


def is_junk(text: str) -> bool:
    t = text.strip()
    if len(t) < 25:
        return True
    # 单行、短、无中文 → 多半是配置行/URL/命令碎片
    if "\n" not in t and len(t) < 60 and not re.search(r"[\u4e00-\u9fff]", t):
        return True
    return any(p.match(t) for p in _JUNK_PATTERNS)

# 目标/漏洞标签关键字(小写匹配路径)
TARGET_KEYWORDS = {
    "ruoyi": ["若依", "ruoyi", "ruo-yi"],
    "jeecg": ["jeecg"],
    "nacos": ["nacos"],
    "bladex": ["bladex"],
    "springboot": ["springboot", "spring-boot", "heapdump", "actuator"],
    "swagger": ["swagger"],
    "jndi": ["jndi", "log4j", "fastjson"],
    "shiro": ["shiro"],
    "sql_injection": ["sql注入", "sqli", "sql-injection", "sqlmap"],
    "miniprogram": ["小程序", "miniprogram"],
    "auth_bypass": ["任意用户", "越权", "未授权"],
    "logic_vuln": ["逻辑漏洞", "并发", "竞态"],
    "csrf": ["csrf"],
    "api": ["api接口", "wsdl"],
    "info_leak": ["信息泄漏", "信息泄露", "敏感信息", "泄露"],
    "info_collect": ["信息收集", "资产收集", "edusrc"],
}

# 漏洞笔记类文件名关键字
VULN_NAME_KEYWORDS = ["漏洞", "实战", "挖掘", "攻防", "渗透", "复现",
                      "vuln", "cve", "poc", "exploit"]


@dataclass
class Chunk:
    """入库前的最小单元:一段文本 + 元数据。"""
    text: str
    source: str                 # 相对路径(posix)
    origin: str                 # src / raw / archive
    category: str               # src_course / vuln_kb / tools
    content_type: str           # doc / data / tool_card / binary
    targets: List[str] = field(default_factory=list)
    archive: str = ""           # 来源压缩包标识(若来自解压产物)
    chunk_index: int = 0


def ext_to_content_type(ext: str) -> str:
    ext = ext.lower()
    if ext in config.BINARY_EXTS:
        return "binary"
    if ext in config.CODE_EXTS:
        return "code"
    if ext in config.DATA_EXTS:
        return "data"
    return "doc"


def infer_targets(source: str) -> List[str]:
    lower = source.lower()
    targets = []
    for tag, keywords in TARGET_KEYWORDS.items():
        if any(k in lower for k in keywords):
            targets.append(tag)
    return targets


def infer_category(source: str, content_type: str, origin: str = "src") -> str:
    if content_type in ("tool_card", "binary", "code"):
        return "tools"
    lower = source.lower()
    if any(k in source for k in VULN_NAME_KEYWORDS[:7]) or \
       any(k in lower for k in VULN_NAME_KEYWORDS[7:]):
        return "vuln_kb"
    if content_type == "data":
        # 配置/字典/payload:解压产物归工具侧,否则归课程资料
        return "tools" if origin == "archive" else "src_course"
    return "src_course"


def enrich(source: str, origin: str, text: str, ext: str,
           category: Optional[str] = None, content_type: Optional[str] = None,
           archive: str = "") -> List[Chunk]:
    """对单个文件的文本切片并附加元数据,返回 Chunk 列表。"""
    from ingestion.splitter import split_text

    ctype = content_type or ext_to_content_type(ext)
    cat = category or infer_category(source, ctype, origin)
    targets = infer_targets(source)

    parts = split_text(text)
    if not parts and len(text.strip()) >= config.MIN_TEXT_CHARS:
        parts = [text.strip()]

    chunks = []
    for i, part in enumerate(parts):
        part = part.strip()
        if len(part) < config.MIN_TEXT_CHARS or is_junk(part):
            continue
        chunks.append(Chunk(
            text=part, source=source, origin=origin,
            category=cat, content_type=ctype,
            targets=targets, archive=archive, chunk_index=i,
        ))
    return chunks
