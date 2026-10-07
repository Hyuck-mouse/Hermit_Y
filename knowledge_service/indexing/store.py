"""Chroma 本地向量库封装,持久化到 data/index/chroma/。

chunk_id 采用 source + chunk 序号 + 内容短哈希,保证重复灌库幂等(upsert 覆盖)。
"""
import hashlib
import logging
from typing import Any, Dict, List, Optional

import config
from ingestion.enricher import Chunk

log = logging.getLogger(__name__)

_BATCH = 256


def chunk_id(chunk: Chunk) -> str:
    raw = "%s::%d::%s" % (chunk.source, chunk.chunk_index, chunk.text[:64])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class VectorStore:
    """Chroma 持久化封装。"""

    def __init__(self, persist_dir=None, collection_name: str = None):
        import chromadb
        self.persist_dir = str(persist_dir or config.CHROMA_DIR)
        self.collection_name = collection_name or config.COLLECTION_NAME
        self.client = chromadb.PersistentClient(path=self.persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        return self.collection.count()

    def add_chunks(self, chunks: List[Chunk], embedder, batch_size: int = 64) -> int:
        """批量嵌入并 upsert。"""
        total = 0
        for start in range(0, len(chunks), batch_size):
            batch = chunks[start: start + batch_size]
            texts = [c.text for c in batch]
            embeddings = embedder.embed_documents(texts)
            ids, metadatas = [], []
            for chunk in batch:
                ids.append(chunk_id(chunk))
                metadatas.append({
                    "source": chunk.source,
                    "origin": chunk.origin,
                    "archive": chunk.archive,
                    "category": chunk.category,
                    "content_type": chunk.content_type,
                    "targets": ",".join(chunk.targets),
                    "chunk_index": chunk.chunk_index,
                })
            self.collection.upsert(
                ids=ids, documents=texts,
                embeddings=embeddings, metadatas=metadatas,
            )
            total += len(batch)
            log.info("已写入 %d/%d 个片段", total, len(chunks))
        return total

    def query(self, query_embedding: List[float], top_k: int = 5,
              where: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """向量相似度检索,返回 Chroma 原始结果。"""
        kwargs = {
            "query_embeddings": [query_embedding],
            "n_results": top_k,
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where
        return self.collection.query(**kwargs)

    def reset(self) -> None:
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
