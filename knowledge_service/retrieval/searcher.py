"""混合检索:向量(BGE) + BM25 关键词,RRF 融合,同源去重。

设计要点:
  - RRF 只用排名融合,不比较两路原始分数 → 规避"向量分数不可信"问题
  - BM25 专治工具名/漏洞编号等精确匹配(纯向量天生不擅长)
  - 同一 source 最多保留 per_source 条,避免单文档占满 top-k
"""
import logging
from typing import Any, Dict, List, Optional

import config
from indexing.embedder import Embedder
from indexing.store import VectorStore
from retrieval.bm25 import BM25Index, tokenize

log = logging.getLogger(__name__)

_RRF_K = 60


def _build_where(category: Optional[str], content_type: Optional[str]) -> Optional[Dict]:
    conds = []
    if category:
        conds.append({"category": category})
    if content_type:
        conds.append({"content_type": content_type})
    if not conds:
        return None
    if len(conds) == 1:
        return conds[0]
    return {"$and": conds}


def rrf_fuse(vec_hits: List[Dict], bm_hits: List[Dict], k: int = _RRF_K) -> List[Dict]:
    """Reciprocal Rank Fusion:score = Σ 1/(k + rank + 1)。"""
    fused: Dict[str, Dict] = {}
    for rank, h in enumerate(vec_hits):
        fused.setdefault(h["id"], {"hit": h, "score": 0.0})
        fused[h["id"]]["score"] += 1.0 / (k + rank + 1)
    for rank, h in enumerate(bm_hits):
        meta = h.get("meta") or {}
        if h["id"] not in fused:
            fused[h["id"]] = {"hit": {
                "id": h["id"],
                "content": h["content"],
                "source": meta.get("source", ""),
                "category": meta.get("category", ""),
                "content_type": meta.get("content_type", "doc"),
                "target": meta.get("targets", ""),
            }, "score": 0.0}
        fused[h["id"]]["score"] += 1.0 / (k + rank + 1)
    out = sorted(fused.values(), key=lambda x: -x["score"])
    return [{**v["hit"], "score": round(v["score"], 4)} for v in out]


def dedup_by_source(hits: List[Dict], per_source: int = 2) -> List[Dict]:
    """同一 source 只保留前 per_source 条。"""
    seen: Dict[str, int] = {}
    out = []
    for h in hits:
        s = h.get("source", "")
        if seen.get(s, 0) >= per_source:
            continue
        seen[s] = seen.get(s, 0) + 1
        out.append(h)
    return out


class KnowledgeSearcher:
    """检索入口。启动慢(需加载模型),建议进程级单例复用。"""

    def __init__(self, embedder: Optional[Embedder] = None,
                 store: Optional[VectorStore] = None):
        self.embedder = embedder or Embedder()
        self.store = store or VectorStore()
        self._bm25: Optional[BM25Index] = None

    def _ensure_bm25(self) -> Optional[BM25Index]:
        """懒构建 BM25 索引(rebuild 后重启服务即可刷新)。"""
        if self._bm25 is None:
            data = self.store.collection.get(include=["documents", "metadatas"])
            if data.get("ids"):
                self._bm25 = BM25Index(data["documents"], data["ids"], data["metadatas"])
                log.info("BM25 索引就绪: %d 条", len(self._bm25.ids))
        return self._bm25

    def search(self, query: str, top_k: int = 5,
               category: Optional[str] = None,
               content_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """返回 [{content, source, category, content_type, target, score}, ...]

        score 为 RRF 融合分(仅用于排序,不代表语义相关度)。
        """
        where = _build_where(category, content_type)
        fetch_k = max(top_k * 4, 20)  # 两路各多召回,融合去重后再截断

        # 1) 向量召回
        embedding = self.embedder.embed_query(query)
        res = self.store.query(embedding, top_k=fetch_k, where=where)
        vec_hits = []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        ids = (res.get("ids") or [[]])[0]
        for doc, meta, dist, cid in zip(docs, metas, dists, ids):
            meta = meta or {}
            vec_hits.append({
                "id": cid,
                "content": doc,
                "source": meta.get("source", ""),
                "category": meta.get("category", ""),
                "content_type": meta.get("content_type", "doc"),
                "target": meta.get("targets", ""),
                "vec_sim": round(max(0.0, 1.0 - float(dist)), 4),
            })

        # 2) BM25 召回
        bm = self._ensure_bm25()
        bm_hits = bm.search(query, top_k=fetch_k, where=where) if bm else []

        # 3) 域外守门:BM25 原始分随查询长度膨胀,按查询有效 token 数归一后再判断。
        #    实测归一分:域内查询 >=1.78,域外(贪吃蛇/天气) <=0.86,阈值取中间 1.3。
        #    低于阈值 → 关键词在库中几乎无命中,仅剩的向量分不可信,返回空(降级为未命中)
        bm_top = bm_hits[0]["bm25"] if bm_hits else 0.0
        q_tokens = len(set(tokenize(query))) or 1
        if bm_top / q_tokens < config.BM25_GATE:
            log.info("域外守门生效: query=%r bm_top=%.2f/%d tok < %.1f, 返回空",
                     query, bm_top, q_tokens, config.BM25_GATE)
            return []

        # 4) RRF 融合 + 同源去重 + 截断
        fused = rrf_fuse(vec_hits, bm_hits)
        fused = dedup_by_source(fused, per_source=2)
        out = []
        for h in fused[:top_k]:
            h.pop("id", None)
            h.pop("vec_sim", None)
            out.append(h)
        return out
