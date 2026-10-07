import { defineStore } from 'pinia'
import { fetchHealth, fetchStats, searchKnowledge } from '@/api/knowledge'
import type { HealthResponse, RecentSearch, StatsResponse } from '@/api/types'

const RECENT_KEY = 'kb.recentSearches'
const RECENT_MAX = 20

function loadRecent(): RecentSearch[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]')
  } catch {
    return []
  }
}

export const useServiceStore = defineStore('service', {
  state: () => ({
    health: null as HealthResponse | null,
    stats: null as StatsResponse | null,
    healthLoading: false,
    lastError: '' as string,
    /** 最近检索(localStorage 持久化,跨刷新保留) */
    recentSearches: loadRecent(),
  }),
  getters: {
    isOk: (s) => s.health?.status === 'ok',
    isDegraded: (s) => s.health?.status === 'degraded',
  },
  actions: {
    async refreshHealth() {
      this.healthLoading = true
      try {
        this.health = await fetchHealth()
        this.lastError = ''
      } catch (e) {
        this.health = { status: 'degraded', doc_count: 0, model: '', detail: null }
        this.lastError = (e as Error).message
      } finally {
        this.healthLoading = false
      }
    },
    async refreshStats() {
      try {
        this.stats = await fetchStats()
      } catch {
        /* stats 失败不打断页面,显示零值 */
        this.stats = { total_chunks: 0, doc_count: 0, by_category: {}, by_content_type: {} }
      }
    },
    async search(params: { query: string; top_k?: number; category?: string | null; content_type?: string | null }) {
      const t0 = performance.now()
      const res = await searchKnowledge(params)
      const ms = Math.round(performance.now() - t0)
      this.recentSearches.unshift({ query: params.query, hits: res.results.length, ms, ts: Date.now() })
      if (this.recentSearches.length > RECENT_MAX) this.recentSearches.length = RECENT_MAX
      try {
        localStorage.setItem(RECENT_KEY, JSON.stringify(this.recentSearches))
      } catch { /* 存储失败不阻塞检索 */ }
      return { ...res, ms }
    },
  },
})
