"""语义切片:递归字符切分,chunk_size≈512, overlap≈64。

优先使用 langchain-text-splitters;未安装时回退到内置实现(保证 dry-run/最小环境可用)。
"""
from typing import List

import config

SEPARATORS = ["\n\n", "\n", "。", "！", "？", "；", "，", "、", " ", ""]


def split_text(text: str, chunk_size: int = None, overlap: int = None) -> List[str]:
    chunk_size = chunk_size or config.CHUNK_SIZE
    overlap = overlap or config.CHUNK_OVERLAP
    try:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=overlap,
            separators=SEPARATORS,
        )
        return [c.strip() for c in splitter.split_text(text) if c.strip()]
    except ImportError:
        return _builtin_split(text, chunk_size, overlap)


def _recursive_split(text: str, size: int, seps) -> List[str]:
    if len(text) <= size:
        return [text] if text.strip() else []
    sep, rest = "", []
    for i, s in enumerate(seps):
        if s == "":
            sep, rest = "", []
            break
        if s in text:
            sep, rest = s, seps[i + 1:]
            break
    pieces = text.split(sep) if sep else list(text)
    out, buf, buf_len = [], [], 0
    for piece in pieces:
        plen = len(piece) + (len(sep) if buf else 0)
        if buf and buf_len + plen > size:
            joined = sep.join(buf)
            out.extend(_recursive_split(joined, size, rest) if len(joined) > size else [joined])
            buf, buf_len = [], 0
        buf.append(piece)
        buf_len += plen
    if buf:
        joined = sep.join(buf)
        out.extend(_recursive_split(joined, size, rest) if len(joined) > size else [joined])
    return [c for c in out if c.strip()]


def _builtin_split(text: str, size: int, overlap: int) -> List[str]:
    base = _recursive_split(text, size, SEPARATORS)
    if overlap <= 0 or len(base) <= 1:
        return base
    # 将前一块尾部拼入后一块头部,形成重叠窗口
    out = [base[0]]
    for i in range(1, len(base)):
        tail = base[i - 1][-overlap:]
        out.append(tail + base[i])
    return out
