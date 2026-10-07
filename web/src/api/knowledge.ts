import client from '@/api/client'
import type { HealthResponse, SearchParams, SearchResponse, StatsResponse } from '@/api/types'

export async function fetchHealth(): Promise<HealthResponse> {
  const { data } = await client.get<HealthResponse>('/health')
  return data
}

export async function fetchStats(): Promise<StatsResponse> {
  const { data } = await client.get<StatsResponse>('/stats')
  return data
}

export async function searchKnowledge(params: SearchParams): Promise<SearchResponse> {
  const { data } = await client.post<SearchResponse>('/search', {
    query: params.query,
    top_k: params.top_k ?? 5,
    category: params.category || null,
    content_type: params.content_type || null,
  })
  return data
}
