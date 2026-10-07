"""文档加载:递归扫描候选文件并提取纯文本。

支持: .md / .txt / .json / .yaml / .yml / .csv(纯文本,utf-8 优先,GBK 回退)
      .pdf(pypdf,可选)、.docx(python-docx,可选)
"""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

import config
from ingestion.archive import is_archive

log = logging.getLogger(__name__)

# 依赖清单/锁文件:对渗透测试零价值,多行带中文注释会逃过 is_junk 短碎片过滤
JUNK_FILENAMES = {
    "requirements.txt", "package.json", "package-lock.json",
    "pipfile", "pipfile.lock", "pom.xml", "go.mod", "go.sum",
    "yarn.lock", "poetry.lock",
}


@dataclass
class RawDocument:
    """加载后的原始文档(未切片)。"""
    text: str
    path: Path
    source: str            # 相对路径(posix),如 008.第八天/若依漏洞挖掘.md 或 extracted/.../README.md
    origin: str            # src / raw / archive:<压缩包key>
    ext: str = field(default="")


def iter_files(roots, exts) -> Iterator[Path]:
    """递归产出指定扩展名的文件,跳过压缩包本体与无关目录。"""
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            if p.name.startswith("."):
                continue
            if any(part in config.IGNORE_DIRS for part in p.parts):
                continue
            if is_archive(p):
                continue
            if p.name.lower() in JUNK_FILENAMES or p.name.lower().endswith(".lock"):
                continue
            if p.suffix.lower() in exts:
                yield p


def _read_text_bytes(path: Path) -> Optional[str]:
    raw = b""
    with open(path, "rb") as f:
        raw = f.read(config.MAX_TEXT_BYTES + 1)
    truncated = len(raw) > config.MAX_TEXT_BYTES
    if truncated:
        raw = raw[: config.MAX_TEXT_BYTES]
    if b"\x00" in raw[:4096]:  # 伪装成文本的二进制
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("gbk", errors="replace")
        except Exception:
            return None
    if truncated:
        text += "\n[...文件过大,已截断...]"
    return text


def _read_pdf(path: Path) -> Optional[str]:
    try:
        from pypdf import PdfReader
    except ImportError:
        log.warning("未安装 pypdf,跳过 PDF: %s", path.name)
        return None
    try:
        reader = PdfReader(str(path))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        return "\n".join(pages)
    except Exception as e:
        log.warning("PDF 解析失败 %s: %s", path.name, e)
        return None


def _read_docx(path: Path) -> Optional[str]:
    try:
        import docx
    except ImportError:
        log.warning("未安装 python-docx,跳过 DOCX: %s", path.name)
        return None
    try:
        doc = docx.Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs)
    except Exception as e:
        log.warning("DOCX 解析失败 %s: %s", path.name, e)
        return None


def load_text(path: Path) -> Optional[str]:
    """按扩展名提取纯文本;失败/二进制返回 None。"""
    ext = path.suffix.lower()
    try:
        if ext in (".md", ".txt", ".json", ".yaml", ".yml", ".csv"):
            return _read_text_bytes(path)
        if ext == ".pdf":
            return _read_pdf(path)
        if ext == ".docx":
            return _read_docx(path)
    except OSError as e:
        log.warning("读取失败 %s: %s", path, e)
    return None
