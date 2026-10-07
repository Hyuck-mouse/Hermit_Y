"""本地知识库检索工具:通过 HTTP 调用独立的 knowledge_service。

服务地址默认 http://127.0.0.1:8765,可用环境变量 KNOWLEDGE_SERVICE_URL 覆盖。
服务不可用时返回 {"results": [], "degraded": True},Agent 应标注"未命中知识库"后降级为自身推理。
"""
import os
from typing import Any, Dict, List, Optional

import httpx


class KnowledgeSearchTool:
    """只检索本地知识库(SRC课程文档/工具说明/漏洞笔记),不联网。"""

    def __init__(self, base_url: Optional[str] = None, timeout: float = 10.0):
        self.base_url = (base_url
                         or os.environ.get("KNOWLEDGE_SERVICE_URL")
                         or "http://127.0.0.1:8765").rstrip("/")
        self.timeout = timeout

    def _degraded(self, reason: str) -> Dict[str, Any]:
        return {"results": [], "degraded": True,
                "message": "未命中知识库: %s" % reason}

    def _payload(self, query: str, top_k: int = 5,
                 category: Optional[str] = None,
                 content_type: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"query": query, "top_k": top_k}
        if category:
            payload["category"] = category
        if content_type:
            payload["content_type"] = content_type
        return payload

    def search(self, query: str, top_k: int = 5,
               category: Optional[str] = None,
               content_type: Optional[str] = None) -> Dict[str, Any]:
        """同步检索(供 ToolDispatcher 直接调用)。"""
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post("%s/search" % self.base_url,
                                   json=self._payload(query, top_k, category, content_type))
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            return self._degraded(str(e) or type(e).__name__)
        if not isinstance(data, dict) or "results" not in data:
            return self._degraded("服务返回格式异常")
        data.setdefault("degraded", False)
        n = len(data.get("results", []))
        top = data["results"][0]["score"] if n else "N/A"
        print(f"[KB] query={query!r} cat={category} type={content_type} → {n} hits, top={top}")
        return data

    async def asearch(self, query: str, top_k: int = 5,
                      category: Optional[str] = None,
                      content_type: Optional[str] = None) -> Dict[str, Any]:
        """异步检索。"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post("%s/search" % self.base_url,
                                         json=self._payload(query, top_k, category, content_type))
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            return self._degraded(str(e) or type(e).__name__)
        if not isinstance(data, dict) or "results" not in data:
            return self._degraded("服务返回格式异常")
        data.setdefault("degraded", False)
        return data

    @staticmethod
    def format_for_prompt(results: List[Dict[str, Any]], max_chars: int = 1500) -> str:
        """把检索结果拼成可注入 LLM 上下文的紧凑文本。"""
        if not results:
            return "未命中知识库"
        blocks, used = [], 0
        for i, r in enumerate(results, 1):
            block = "[%d] 来源:%s | 类别:%s | 分数:%s\n%s" % (
                i, r.get("source", "?"), r.get("category", "?"),
                r.get("score", 0), r.get("content", ""))
            if used + len(block) > max_chars:
                break
            blocks.append(block)
            used += len(block)
        return "\n\n".join(blocks) if blocks else "未命中知识库"
