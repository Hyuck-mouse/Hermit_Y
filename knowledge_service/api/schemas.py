"""API 请求/响应模型。"""
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="检索问题,如'若依后台信息泄漏'")
    top_k: int = Field(5, ge=1, le=20)
    category: Optional[str] = Field(None, description="按类别过滤: src_course/vuln_kb/tools/payloads")
    content_type: Optional[str] = Field(None, description="按类型过滤: doc/data/code/tool_card/binary")


class SearchResultItem(BaseModel):
    content: str
    source: str
    category: str = ""
    content_type: str = "doc"
    target: str = ""
    score: float = 0.0


class SearchResponse(BaseModel):
    results: List[SearchResultItem] = []
    degraded: bool = False


class HealthResponse(BaseModel):
    status: str                      # ok / degraded
    doc_count: int = 0
    model: str = ""
    detail: Optional[str] = None


class StatsResponse(BaseModel):
    """知识库统计(实时聚合自 Chroma metadata)。"""
    total_chunks: int = 0            # 切片总数
    doc_count: int = 0               # 唯一 source 文档数
    by_category: Dict[str, int] = {}    # 类别 -> chunk 数
    by_content_type: Dict[str, int] = {}  # 类型 -> chunk 数
