import axios from 'axios'

/**
 * API 基址:默认走 vite 代理(/api → 127.0.0.1:8765)。
 * Settings 页可覆盖,存 localStorage('kb.apiBase'),如 http://127.0.0.1:8765
 */
const LS_KEY = 'kb.apiBase'

export function getApiBase(): string {
  const v = localStorage.getItem(LS_KEY)
  return v && v.trim() ? v.trim().replace(/\/+$/, '') : '/api'
}

export function setApiBase(base: string) {
  if (base.trim()) localStorage.setItem(LS_KEY, base.trim())
  else localStorage.removeItem(LS_KEY)
}

const client = axios.create({ timeout: 30_000 })

client.interceptors.request.use((config) => {
  config.baseURL = getApiBase()
  return config
})

/** 统一拦截 degraded/网络错误,转为可读错误信息抛给调用方 */
client.interceptors.response.use(
  (res) => res,
  (err) => {
    const msg = err?.response
      ? `HTTP ${err.response.status}: ${err.response.statusText}`
      : `服务不可达: ${err?.message ?? 'unknown'}`
    return Promise.reject(new Error(msg))
  },
)

export default client
