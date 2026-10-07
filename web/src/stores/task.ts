import { defineStore } from 'pinia'
import type { CtfTask, PentestTask } from '@/api/task'
import { deleteTask, listTasks, submitTask } from '@/api/task'

/**
 * 任务数据流:
 *   提交 → POST /task-api/tasks (agent_service:8766) → 成功后写入本地 state
 *   服务不可用时降级 localStorage,UI 照常可用
 */

const CTF_KEY = 'kb.ctfTasks'
const PENTEST_KEY = 'kb.pentestTasks'

function loadLocal<T>(key: string): T[] {
  try {
    return JSON.parse(localStorage.getItem(key) ?? '[]')
  } catch {
    return []
  }
}

function persistLocal(key: string, items: unknown[]) {
  try {
    localStorage.setItem(key, JSON.stringify(items))
  } catch { /* 存储失败不阻塞操作 */ }
}

/** 后端记录 {id, created_at, status, payload} → 前端任务对象 */
function fromBackend<T>(t: Record<string, unknown>): T {
  const payload = (t.payload ?? {}) as Record<string, unknown>
  return {
    ...payload,
    id: t.id as string,
    createdAt: (t.created_at as string) ?? '',
    status: (t.status as T extends { status: infer S } ? S : never) ?? 'pending',
  } as T
}

export const useTaskStore = defineStore('task', {
  state: () => ({
    ctfTasks: [] as CtfTask[],
    pentestTasks: [] as PentestTask[],
    /** 后端不可用降级到 localStorage */
    degraded: false,
    loaded: false,
  }),
  actions: {
    /** 页面初始化时从后端拉取历史任务 */
    async init() {
      try {
        const [ctf, pentest] = await Promise.all([listTasks('ctf'), listTasks('pentest')])
        this.ctfTasks = ctf.map((t) => fromBackend<CtfTask>(t))
        this.pentestTasks = pentest.map((t) => fromBackend<PentestTask>(t))
        this.degraded = false
      } catch {
        // 服务未启动:降级本地缓存
        this.ctfTasks = loadLocal<CtfTask>(CTF_KEY)
        this.pentestTasks = loadLocal<PentestTask>(PENTEST_KEY)
        this.degraded = true
      }
      this.loaded = true
    },

    /** 返回新建任务(含 id),供提交后跳转执行视图 */
    async addCtfTask(task: Omit<CtfTask, 'id' | 'createdAt' | 'status'>): Promise<CtfTask> {
      try {
        const saved = await submitTask('ctf', { ...task })
        const mapped = fromBackend<CtfTask>(saved)
        this.ctfTasks.unshift(mapped)
        this.degraded = false
        return mapped
      } catch {
        const local: CtfTask = {
          ...task, id: crypto.randomUUID(),
          createdAt: new Date().toISOString(), status: 'pending',
        }
        this.ctfTasks.unshift(local)
        persistLocal(CTF_KEY, this.ctfTasks)
        this.degraded = true
        return local
      }
    },

    async removeCtfTask(id: string) {
      this.ctfTasks = this.ctfTasks.filter((t) => t.id !== id)
      if (this.degraded) {
        persistLocal(CTF_KEY, this.ctfTasks)
      } else {
        await deleteTask(id).catch(() => { /* 删除失败仅本地移除 */ })
      }
    },

    async addPentestTask(task: Omit<PentestTask, 'id' | 'createdAt' | 'status'>) {
      try {
        const saved = await submitTask('pentest', { ...task })
        this.pentestTasks.unshift(fromBackend<PentestTask>(saved))
        this.degraded = false
      } catch {
        const local: PentestTask = {
          ...task, id: crypto.randomUUID(),
          createdAt: new Date().toISOString(), status: 'pending',
        }
        this.pentestTasks.unshift(local)
        persistLocal(PENTEST_KEY, this.pentestTasks)
        this.degraded = true
      }
    },

    async removePentestTask(id: string) {
      this.pentestTasks = this.pentestTasks.filter((t) => t.id !== id)
      if (this.degraded) {
        persistLocal(PENTEST_KEY, this.pentestTasks)
      } else {
        await deleteTask(id).catch(() => { /* 删除失败仅本地移除 */ })
      }
    },
  },
})
