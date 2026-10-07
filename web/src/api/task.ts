export type TaskStatus = 'pending' | 'running' | 'done' | 'failed'

/** worker 执行结果(flag 提取自运行日志) */
export interface TaskResult {
  flag?: string
  error?: string
}

export type TargetType = 'domain' | 'ip' | 'url' | 'cidr' | 'file'

export interface PentestTarget {
  type: TargetType
  value: string
}

export interface PentestConstraints {
  timeWindow?: { start: string; end: string }
  rateLimit?: { value: number; unit: string }
  forbiddenActions: string[]
  credentials?: string
  excludeTargets?: string
}

export interface PentestTask {
  id: string
  targets: PentestTarget[]
  constraints: PentestConstraints
  notes?: string
  createdAt: string
  status: TaskStatus
  result?: TaskResult
}

export type CtfCategory = 'Pwn' | 'Web' | 'Misc' | 'Crypto' | 'Reverse' | 'AI'

export interface CtfAttachment {
  name: string
  size: number
  type: string
}

export interface CtfTask {
  id: string
  category: CtfCategory
  title: string
  description: string
  remoteUrl?: string
  attachments: CtfAttachment[]
  notes?: string
  customFields: { key: string; value: string }[]
  createdAt: string
  status: TaskStatus
  result?: TaskResult
}

/** 状态显示映射 */
export const STATUS_MAP: Record<TaskStatus, { label: string; color: string }> = {
  pending: { label: '待执行', color: 'var(--warning)' },
  running: { label: '执行中', color: 'var(--accent)' },
  done: { label: '已完成', color: 'var(--success)' },
  failed: { label: '失败', color: 'var(--danger)' },
}

/* ==================== 后端接口(agent_service, 127.0.0.1:8766) ==================== */

const BASE = '/task-api'

/** 后端任务记录:task_type + 任意 payload,服务端补 id/created_at/status */
export interface BackendTask {
  id: string
  task_type: 'ctf' | 'pentest'
  created_at: string
  status: TaskStatus
  [key: string]: unknown
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export function submitTask(task_type: 'ctf' | 'pentest', payload: Record<string, unknown>) {
  return req<BackendTask>('/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ task_type, payload }),
  })
}

export function listTasks(task_type?: 'ctf' | 'pentest') {
  return req<BackendTask[]>(`/tasks${task_type ? `?task_type=${task_type}` : ''}`)
}

export function deleteTask(id: string) {
  return req<{ ok: boolean }>(`/tasks/${id}`, { method: 'DELETE' })
}

/** 任务执行日志(worker 落盘的子进程输出,末尾 12000 字符) */
export function getTaskLog(id: string) {
  return req<{ log: string; size: number; truncated: boolean }>(`/tasks/${id}/log`)
}
