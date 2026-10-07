"""BGE 本地嵌入模型封装(懒加载,避免 dry-run / 健康检查拖慢启动)。

文档侧不添加任何前缀;查询侧按 bge 官方建议添加 QUERY_INSTRUCTION 前缀。
"""
import logging
from typing import List, Optional

import config

log = logging.getLogger(__name__)

_model = None  # 全局单例


def _load_model():
    global _model
    if _model is not None:
        return _model
    from sentence_transformers import SentenceTransformer
    log.info("加载嵌入模型 %s (device=%s)...", config.EMBEDDING_MODEL,
             config.EMBEDDING_DEVICE or "auto")
    _model = SentenceTransformer(config.EMBEDDING_MODEL, device=config.EMBEDDING_DEVICE)
    log.info("嵌入模型加载完成,维度=%d", _model.get_sentence_embedding_dimension())
    return _model


class Embedder:
    """文档/查询嵌入接口。"""

    def __init__(self, model=None):
        self._model = model or _load_model()

    @property
    def model(self):
        if self._model is None:
            self._model = _load_model()
        return self._model

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """批量文档嵌入(入库用)。"""
        return self.model.encode(
            texts, normalize_embeddings=True,
            batch_size=32, show_progress_bar=False,
        ).tolist()

    def embed_query(self, text: str) -> List[float]:
        """单条查询嵌入(检索用,bge-zh 需加指令前缀)。"""
        return self.model.encode(
            [config.QUERY_INSTRUCTION + text],
            normalize_embeddings=True,
        )[0].tolist()

    def dimension(self) -> int:
        return self.model.get_sentence_embedding_dimension()
