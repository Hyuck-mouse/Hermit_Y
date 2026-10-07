"""检索结果格式化:API 响应 / LLM 上下文两种形态。"""
from typing import Any, Dict, List


def to_response(hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    """API 响应格式。"""
    return {"results": hits, "degraded": False}


def to_prompt_context(hits: List[Dict[str, Any]], max_chars: int = 2000) -> str:
    """拼接为可注入 LLM 上下文的文本块。"""
    if not hits:
        return "未命中知识库"
    blocks = []
    used = 0
    for i, h in enumerate(hits, 1):
        block = "[%d] 来源:%s | 类别:%s | 分数:%s\n%s" % (
            i, h.get("source", "?"), h.get("category", "?"),
            h.get("score", 0), h.get("content", ""))
        if used + len(block) > max_chars:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks) if blocks else "未命中知识库"
