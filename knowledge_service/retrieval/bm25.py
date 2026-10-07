"""BM25 关键词检索:与向量检索互补,专治专有名词/精确匹配(工具名、漏洞编号等)。

分词策略:中文按单字 + bigram,英文/数字按词,无需 jieba 依赖。
"""
import re
from typing import Dict, List, Optional

_CN_RE = re.compile(r"[\u4e00-\u9fff]")
_TOKEN_RE = re.compile(r"[a-z0-9_\-\.]+|[\u4e00-\u9fff]")

# 停用词:单字虚词 + 高频泛义词。不过滤会把"如何用Python写贪吃蛇"这类
# 域外查询的分数抬到和域内查询同一区间,导致无法区分
_STOPSingle = set("的了是在有和就不到被把个将往与或你我这那及对于从向给让使等啊呀吧吗呢么之")
_STOPWORDS = _STOPSingle | {
    "如何", "怎么", "什么", "为什么", "怎样", "可以", "能够", "进行", "使用",
    "通过", "应该", "需要", "是不是", "有没有", "这个", "那个", "一个",
    "我们", "你们", "他们", "以及", "关于",
}


def tokenize(text: str) -> List[str]:
    text = text.lower()
    tokens = [t for t in _TOKEN_RE.findall(text) if t not in _STOPWORDS]
    cn = [t for t in tokens if _CN_RE.match(t)]
    # 中文 bigram 提升匹配精度("若依"->["若","依","若依"])
    bigrams = [cn[i] + cn[i + 1] for i in range(len(cn) - 1)]
    return [t for t in tokens + bigrams if t not in _STOPWORDS]


def _meta_matches(meta: Dict, where: Optional[Dict]) -> bool:
    """Chroma where 形态的轻量后过滤:None / {k:v} / {"$and": [...]}"""
    if not where:
        return True
    if "$and" in where:
        return all(_meta_matches(meta, cond) for cond in where["$and"])
    return all(meta.get(k) == v for k, v in where.items())


class BM25Index:
    """内存 BM25 索引,启动时从 Chroma 全量构建(数百条秒级)。"""

    def __init__(self, docs: List[str], ids: List[str], metas: List[dict]):
        from rank_bm25 import BM25Okapi
        self.ids, self.metas, self.docs = ids, metas, docs
        self.bm25 = BM25Okapi([tokenize(d) for d in docs]) if docs else None

    def search(self, query: str, top_k: int = 10,
               where: Optional[Dict] = None) -> List[Dict]:
        if not self.bm25:
            return []
        scores = self.bm25.get_scores(tokenize(query))
        ranked = sorted(range(len(scores)), key=lambda i: -scores[i])
        out = []
        for i in ranked:
            if scores[i] <= 0:
                break
            meta = self.metas[i] or {}
            if not _meta_matches(meta, where):
                continue
            out.append({
                "id": self.ids[i],
                "content": self.docs[i],
                "meta": meta,
                "bm25": float(scores[i]),
            })
            if len(out) >= top_k:
                break
        return out
