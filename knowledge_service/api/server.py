"""FastAPI 服务:POST /search 与 GET /health。

启动方式(在 knowledge_service/ 目录下):
  python -m api.server
或:
  uvicorn api.server:app --host 127.0.0.1 --port 8765
"""
import logging
import sys
from pathlib import Path

# 允许直接 `python api/server.py` 启动:把 knowledge_service/ 加入 sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from api.schemas import (HealthResponse, SearchRequest, SearchResponse,
                         SearchResultItem, StatsResponse)
from retrieval.formatter import to_response

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="本地知识检索服务", version="0.1.0")

# 本地前端(dev server / 打开文件)跨域访问用;生产仅本机监听,无暴露风险
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_searcher = None
_init_error = None


@app.on_event("startup")
def _startup():
    """启动时加载模型与向量库;失败进入降级态,不影响 /health。"""
    global _searcher, _init_error
    try:
        from retrieval.searcher import KnowledgeSearcher
        _searcher = KnowledgeSearcher()
        log.info("知识检索器就绪,当前向量数=%d", _searcher.store.count())
    except Exception as e:  # noqa: BLE001 - 启动失败不应使进程退出
        _init_error = str(e) or type(e).__name__
        log.exception("知识检索器初始化失败,服务进入降级态: %s", _init_error)


@app.get("/health", response_model=HealthResponse)
def health():
    if _searcher is None:
        return HealthResponse(status="degraded", doc_count=0,
                              model=config.EMBEDDING_MODEL, detail=_init_error)
    return HealthResponse(status="ok", doc_count=_searcher.store.count(),
                          model=config.EMBEDDING_MODEL)


@app.post("/search", response_model=SearchResponse)
def search(req: SearchRequest):
    if _searcher is None:
        return SearchResponse(results=[], degraded=True)
    try:
        hits = _searcher.search(req.query, top_k=req.top_k,
                                category=req.category,
                                content_type=req.content_type)
        return SearchResponse(
            results=[SearchResultItem(**h) for h in hits],
            degraded=False,
        )
    except Exception as e:  # noqa: BLE001 - 检索失败返回降级而非 500,Agent 侧可容错
        log.exception("检索失败: %s", e)
        return SearchResponse(results=[], degraded=True)


@app.get("/stats", response_model=StatsResponse)
def stats():
    """知识库统计:从 Chroma metadata 实时聚合(千级 chunk 内开销可忽略)。"""
    out = StatsResponse()
    try:
        if _searcher is None:
            return out
        data = _searcher.store.collection.get(include=["metadatas"])
        metas = data.get("metadatas") or []
        out.total_chunks = len(metas)
        sources = set()
        for m in metas:
            m = m or {}
            if m.get("source"):
                sources.add(m["source"])
            cat = m.get("category") or "unknown"
            ctype = m.get("content_type") or "unknown"
            out.by_category[cat] = out.by_category.get(cat, 0) + 1
            out.by_content_type[ctype] = out.by_content_type.get(ctype, 0) + 1
        out.doc_count = len(sources)
    except Exception as e:  # noqa: BLE001 - 统计失败返回零值,不影响服务
        log.exception("统计失败: %s", e)
    return out


def main():
    import uvicorn
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT, log_level="info")


if __name__ == "__main__":
    main()
