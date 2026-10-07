/** 与 knowledge_service/api/schemas.py 对齐的接口类型 */

export interface SearchResultItem {
  content: string
  source: string
  category: string
  content_type: string
  target: string
  score: number
}

export interface SearchResponse {
  results: SearchResultItem[]
  degraded: boolean
}

export interface HealthResponse {
  status: 'ok' | 'degraded'
  doc_count: number
  model: string
  detail?: string | null
}

export interface StatsResponse {
  total_chunks: number
  doc_count: number
  by_category: Record<string, number>
  by_content_type: Record<string, number>
}

export interface SearchParams {
  query: string
  top_k?: number
  category?: string | null
  content_type?: string | null
}

/** 本会话内最近检索记录(前端内存,后端暂无历史接口) */
export interface RecentSearch {
  query: string
  hits: number
  ms: number
  ts: number
}
