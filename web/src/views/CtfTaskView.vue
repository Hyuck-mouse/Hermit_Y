<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NButton, NPopconfirm, NTag, useMessage } from 'naive-ui'
import { ArrowLeft, RotateCw, Trash2 } from 'lucide-vue-next'
import { useTaskStore } from '@/stores/task'
import { getTaskLog, STATUS_MAP } from '@/api/task'
import type { CtfCategory } from '@/api/task'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()
const message = useMessage()

const taskId = ref(route.params.id as string)
const task = computed(() => store.ctfTasks.find((t) => t.id === taskId.value) ?? null)

const CATEGORY_COLORS: Record<CtfCategory, string> = {
  Pwn: '#F85149', Web: '#4C8DFF', Misc: '#D29922',
  Crypto: '#8B5CF6', Reverse: '#3FB950', AI: '#F778BA',
}

const TERMINAL = new Set(['done', 'failed'])
function fmtTime(iso?: string) {
  if (!iso) return '-'
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/* ==================== 日志轮询(仅本视图打开期间,2.5s) ==================== */
const logText = ref('')
const logTruncated = ref(false)
const logSize = ref(0)
const logPre = ref<HTMLPreElement | null>(null)
/** 自动滚底开关:用户手动上滑后暂停,回到底部恢复 */
const stickBottom = ref(true)
let logTimer: number | undefined

async function refreshLog() {
  if (!task.value || task.value.status === 'pending') {
    logText.value = ''
    return
  }
  try {
    const r = await getTaskLog(taskId.value)
    logText.value = r.log
    logTruncated.value = r.truncated
    logSize.value = r.size
    if (stickBottom.value) {
      await nextTick()
      const el = logPre.value
      if (el) el.scrollTop = el.scrollHeight
    }
    // 终态后日志不再变化,停止轮询
    if (TERMINAL.has(task.value.status)) stopLogPolling()
  } catch {
    logText.value = '(日志获取失败,请确认任务服务运行中)'
  }
}

function onLogScroll() {
  const el = logPre.value
  if (!el) return
  stickBottom.value = el.scrollHeight - el.scrollTop - el.clientHeight < 24
}

function startLogPolling() {
  if (logTimer !== undefined) return
  refreshLog()
  logTimer = window.setInterval(refreshLog, 2500)
}
function stopLogPolling() {
  if (logTimer !== undefined) {
    clearInterval(logTimer)
    logTimer = undefined
  }
}

onMounted(() => {
  if (!store.loaded) store.init()
  startLogPolling()
})
onUnmounted(stopLogPolling)

/* ==================== 操作 ==================== */
function goBack() {
  router.push('/ctf')
}

async function removeTask() {
  await store.removeCtfTask(taskId.value)
  message.success('任务已删除')
  router.push('/ctf')
}

/** 再跑一次 = 克隆表单字段为新任务(worker 自动领取),跳转到新任务执行视图 */
async function rerun() {
  const t = task.value
  if (!t) return
  const created = await store.addCtfTask({
    category: t.category,
    title: t.title,
    description: t.description,
    remoteUrl: t.remoteUrl,
    attachments: t.attachments ?? [],
    notes: t.notes,
    customFields: t.customFields ?? [],
  })
  message.success('已克隆为新任务并开始执行')
  router.replace(`/ctf/task/${created.id}`)
}

/* rerun/删除后路由可能已切走,id 变化时重启日志轮询(同组件复用) */
watch(() => route.params.id, (nid) => {
  if (typeof nid === 'string' && nid !== taskId.value) {
    taskId.value = nid
    logText.value = ''
    stickBottom.value = true
    stopLogPolling()
    startLogPolling()
  }
})
</script>

<template>
  <div class="task-page">
    <template v-if="task">
      <!-- 头部:题目名 + 分类 + 状态徽章 -->
      <div class="panel head-card">
        <div class="head-top">
          <n-button size="small" quaternary @click="goBack">
            <template #icon><ArrowLeft :size="14" /></template>
            返回
          </n-button>
          <span
            class="mono status-badge"
            :style="{ color: STATUS_MAP[task.status].color, borderColor: STATUS_MAP[task.status].color }"
          >{{ STATUS_MAP[task.status].label }}</span>
        </div>
        <h2 class="task-title">{{ task.title }}</h2>
        <div class="head-meta">
          <n-tag
            size="small"
            :bordered="false"
            :style="{ color: CATEGORY_COLORS[task.category] }"
          >{{ task.category }}</n-tag>
          <span v-if="task.remoteUrl" class="mono meta-url">{{ task.remoteUrl }}</span>
          <span class="mono meta-time">提交 {{ fmtTime(task.createdAt) }}</span>
        </div>
      </div>

      <!-- flag 区:仅 done 且提取到 flag 时显示 -->
      <div v-if="task.status === 'done' && task.result?.flag" class="panel flag-card">
        <div class="flag-label">FLAG</div>
        <div class="mono flag-value">{{ task.result.flag }}</div>
      </div>

      <!-- 失败原因 -->
      <div v-if="task.result?.error" class="panel error-card">
        <span class="error-label">错误</span>
        <span class="mono error-msg">{{ task.result.error }}</span>
      </div>

      <!-- 日志区 -->
      <div class="panel log-card">
        <div class="log-head">
          <span class="log-title">执行日志</span>
          <span v-if="logTruncated" class="mono log-warn">仅显示末尾部分（共 {{ logSize }} 字符）</span>
          <span v-else-if="logSize" class="mono log-size">{{ logSize }} 字符</span>
          <span v-if="task.status === 'running'" class="log-live">
            <span class="live-dot" />实时
          </span>
        </div>
        <pre ref="logPre" class="mono log-view" @scroll="onLogScroll">{{ logText || (task.status === 'pending' ? '等待 worker 领取…' : '日志加载中…') }}</pre>
      </div>

      <!-- 操作区 -->
      <div class="actions">
        <n-button size="small" @click="goBack">返回列表</n-button>
        <n-button size="small" type="primary" ghost :disabled="task.status === 'running'" @click="rerun">
          <template #icon><RotateCw :size="14" /></template>
          再跑一次
        </n-button>
        <n-popconfirm @positive-click="removeTask">
          <template #trigger>
            <n-button size="small" type="error" ghost>
              <template #icon><Trash2 :size="14" /></template>
              删除
            </n-button>
          </template>
          确认删除该任务及其展示记录？（日志文件不会删除）
        </n-popconfirm>
      </div>
    </template>

    <!-- 任务不存在 -->
    <div v-else class="panel missing">
      <p>任务不存在或已被删除</p>
      <n-button size="small" @click="goBack">返回 CTF 列表</n-button>
    </div>
  </div>
</template>

<style scoped>
.task-page {
  max-width: 900px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* 头部 */
.head-card {
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.head-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.status-badge {
  font-size: 12px;
  font-weight: 600;
  padding: 3px 10px;
  border: 1px solid;
  border-radius: 999px;
}
.task-title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
}
.head-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.meta-url {
  font-size: 12px;
  color: var(--accent);
  word-break: break-all;
}
.meta-time {
  font-size: 11px;
  color: var(--text-muted);
  margin-left: auto;
}

/* flag */
.flag-card {
  padding: 14px 18px;
  border-left: 3px solid var(--success);
  display: flex;
  align-items: baseline;
  gap: 14px;
}
.flag-label {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: var(--success);
}
.flag-value {
  font-size: 16px;
  font-weight: 600;
  color: var(--success);
  word-break: break-all;
}

/* 错误 */
.error-card {
  padding: 12px 18px;
  border-left: 3px solid var(--danger);
  display: flex;
  gap: 12px;
  align-items: baseline;
}
.error-label {
  font-size: 11px;
  font-weight: 700;
  color: var(--danger);
}
.error-msg {
  font-size: 12px;
  color: var(--danger);
}

/* 日志 */
.log-card {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.log-head {
  display: flex;
  align-items: center;
  gap: 12px;
}
.log-title {
  font-size: 13px;
  font-weight: 600;
}
.log-warn {
  font-size: 11px;
  color: var(--warning);
}
.log-size {
  font-size: 11px;
  color: var(--text-muted);
}
.log-live {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: var(--accent);
}
.live-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  animation: pulse 1.4s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}
.log-view {
  margin: 0;
  height: 48vh;
  min-height: 300px;
  overflow-y: auto;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 12px;
  font-size: 11.5px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text-secondary);
}

/* 操作区 */
.actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

/* 缺失态 */
.missing {
  padding: 40px;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
  color: var(--text-secondary);
}
</style>
