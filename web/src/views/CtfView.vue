<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  NButton, NDrawer, NDrawerContent, NInput, NPopconfirm,
  NTag, NUpload, NUploadDragger,
  useMessage, type UploadFileInfo,
} from 'naive-ui'
import {
  Binary, Bot, FileCode2, Globe, Plus, Search,
  Shield, Trash2, X,
} from 'lucide-vue-next'
import { useTaskStore } from '@/stores/task'
import type { CtfCategory, CtfTask, CtfAttachment } from '@/api/task'
import { getTaskLog, STATUS_MAP } from '@/api/task'

const store = useTaskStore()
const message = useMessage()
const router = useRouter()

/* ==================== 分类定义 ==================== */
interface CategoryDef {
  value: CtfCategory
  icon: typeof Shield
  color: string
  hint: string
}
const CATEGORIES: CategoryDef[] = [
  { value: 'Pwn',     icon: Binary,     color: '#F85149', hint: '栈溢出、堆利用、格式化字符串' },
  { value: 'Web',     icon: Globe,      color: '#4C8DFF', hint: 'SQL注入、SSTI、反序列化、文件包含' },
  { value: 'Misc',    icon: Search,     color: '#D29922', hint: '流量分析、隐写、编码解码' },
  { value: 'Crypto',  icon: Shield,     color: '#8B5CF6', hint: 'RSA、AES、古典密码、格密码' },
  { value: 'Reverse', icon: FileCode2,  color: '#3FB950', hint: 'PE/ELF 分析、反调试、加壳' },
  { value: 'AI',      icon: Bot,        color: '#F778BA', hint: '模型越狱、对抗样本、数据投毒' },
]

/* ==================== 表单状态 ==================== */
const form = ref({
  category: '' as CtfCategory | '',
  title: '',
  description: '',
  remoteUrl: '',
  notes: '',
  customFields: [] as { key: string; value: string }[],
})

const formErrors = ref<Record<string, string>>({})

/* ---- 附件 ---- */
const fileList = ref<UploadFileInfo[]>([])
const attachments = ref<CtfAttachment[]>([])

const MAX_FILE_SIZE = 200 * 1024 * 1024 // 200MB

function handleFileChange(options: { fileList: UploadFileInfo[] }) {
  const newFiles: CtfAttachment[] = []
  for (const f of options.fileList) {
    if (f.file && f.file.size > MAX_FILE_SIZE) {
      message.error(`"${f.name}" 超过 200MB 限制，已跳过`)
      continue
    }
    newFiles.push({
      name: f.name,
      size: f.file?.size ?? 0,
      type: f.file?.type || 'unknown',
    })
  }
  attachments.value = newFiles
  fileList.value = options.fileList.filter(
    (f) => !(f.file && f.file.size > MAX_FILE_SIZE)
  )
}

function removeAttachment(index: number) {
  attachments.value.splice(index, 1)
  fileList.value.splice(index, 1)
}

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/* ---- 动态字段 ---- */
function addCustomField() {
  form.value.customFields.push({ key: '', value: '' })
}
function removeCustomField(i: number) {
  form.value.customFields.splice(i, 1)
}

/* ==================== 校验 & 提交 ==================== */
function validate(): boolean {
  const errs: Record<string, string> = {}
  if (!form.value.category) errs.category = '请选择题目分类'
  if (!form.value.title.trim()) errs.title = '请输入题目名称'
  if (!form.value.description.trim()) errs.description = '请输入题目描述'
  formErrors.value = errs
  return Object.keys(errs).length === 0
}

async function submit() {
  if (!validate()) {
    message.error('请填写必填项')
    return
  }
  const task = {
    category: form.value.category as CtfCategory,
    title: form.value.title.trim(),
    description: form.value.description.trim(),
    remoteUrl: form.value.remoteUrl.trim() || undefined,
    attachments: [...attachments.value],
    notes: form.value.notes.trim() || undefined,
    customFields: form.value.customFields.filter((f) => f.key.trim()),
  }
  const created = await store.addCtfTask(task)
  message.success(`已提交题目「${task.title}」${store.degraded ? '（后端不可用,已存本地）' : ''}`)
  reset()
  // 提交后跳转到执行视图(worker 会自动领取 pending 任务)
  router.push(`/ctf/task/${created.id}`)
}

function saveDraft() {
  // 草稿 = 把当前表单快照存入 localStorage,不触发校验,下次进入页面自动恢复
  const draft = {
    category: form.value.category,
    title: form.value.title,
    description: form.value.description,
    remoteUrl: form.value.remoteUrl,
    notes: form.value.notes,
    customFields: form.value.customFields,
    attachments: attachments.value,
  }
  try {
    localStorage.setItem('kb.ctfDraft', JSON.stringify(draft))
    message.success('草稿已保存')
  } catch {
    message.error('草稿保存失败')
  }
}

/** 进入页面时恢复草稿 */
function restoreDraft() {
  try {
    const raw = localStorage.getItem('kb.ctfDraft')
    if (!raw) return
    const draft = JSON.parse(raw)
    if (draft.category) form.value.category = draft.category
    if (draft.title) form.value.title = draft.title
    if (draft.description) form.value.description = draft.description
    if (draft.remoteUrl) form.value.remoteUrl = draft.remoteUrl
    if (draft.notes) form.value.notes = draft.notes
    if (draft.customFields?.length) form.value.customFields = draft.customFields
    if (draft.attachments?.length) attachments.value = draft.attachments
  } catch { /* 忽略脏数据 */ }
}

function reset() {
  form.value = { category: '', title: '', description: '', remoteUrl: '', notes: '', customFields: [] }
  attachments.value = []
  fileList.value = []
  formErrors.value = {}
  localStorage.removeItem('kb.ctfDraft')
}

/* ==================== 历史任务 ==================== */
const showDetail = ref(false)
const detailId = ref('')
/** computed 而非快照:列表轮询刷新后抽屉内容自动跟随最新状态 */
const detailTask = computed(() => store.ctfTasks.find((t) => t.id === detailId.value) ?? null)

function openDetail(task: CtfTask) {
  detailId.value = task.id
  showDetail.value = true
  loadLog()
}

/* ---- 执行日志 ---- */
const logText = ref('')
const logMeta = ref('')

async function loadLog() {
  const t = detailTask.value
  if (!t || t.status === 'pending') return
  try {
    const r = await getTaskLog(t.id)
    logText.value = r.log
    logMeta.value = r.truncated ? `${r.size} 字符 · 仅显示末尾` : `${r.size} 字符`
  } catch {
    logText.value = '(日志获取失败,请确认任务服务运行中)'
    logMeta.value = ''
  }
}

function fmtTime(iso: string) {
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

const selectedCategory = computed(() =>
  CATEGORIES.find((c) => c.value === form.value.category)
)

onMounted(() => {
  restoreDraft()
})
</script>

<template>
  <div class="ctf-page">
    <!-- ========== 题目分类 ========== -->
    <div class="panel form-section">
      <div class="section-label">题目分类 <span class="required">*</span></div>
      <div class="category-grid">
        <div
          v-for="cat in CATEGORIES"
          :key="cat.value"
          class="cat-card"
          :class="{ active: form.category === cat.value }"
          :style="form.category === cat.value ? { borderColor: cat.color } : {}"
          @click="form.category = cat.value; formErrors.category = ''"
        >
          <component :is="cat.icon" :size="22" :color="cat.color" :stroke-width="1.6" />
          <span class="cat-name mono">{{ cat.value }}</span>
          <span class="cat-hint">{{ cat.hint }}</span>
        </div>
      </div>
      <div v-if="formErrors.category" class="error-hint">{{ formErrors.category }}</div>
      <div v-if="selectedCategory" class="selected-hint" :style="{ color: selectedCategory.color }">
        已选择 {{ selectedCategory.value }}：{{ selectedCategory.hint }}
      </div>
    </div>

    <!-- ========== 题目信息 ========== -->
    <div class="panel form-section">
      <div class="section-label">题目信息 <span class="required">*</span></div>
      <div class="field">
        <label class="field-label">题目名称 <span class="required">*</span></label>
        <n-input v-model:value="form.title" placeholder="如：EzStack、babyheap" :status="formErrors.title ? 'error' : undefined" />
        <div v-if="formErrors.title" class="error-hint">{{ formErrors.title }}</div>
      </div>
      <div class="field">
        <label class="field-label">题目描述 <span class="required">*</span></label>
        <n-input
          v-model:value="form.description"
          type="textarea"
          :autosize="{ minRows: 4, maxRows: 12 }"
          placeholder="粘贴题目原文、提示、环境信息等"
          :status="formErrors.description ? 'error' : undefined"
        />
        <div v-if="formErrors.description" class="error-hint">{{ formErrors.description }}</div>
      </div>
      <div class="field">
        <label class="field-label">题目地址 <span class="optional">（选填）</span></label>
        <n-input v-model:value="form.remoteUrl" placeholder="nc 或 http 地址，如 nc 1.2.3.4 12345" class="mono" />
      </div>
    </div>

    <!-- ========== 附件上传 ========== -->
    <div class="panel form-section">
      <div class="section-label">附件上传 <span class="optional">（选填）</span></div>
      <n-upload
        v-model:file-list="fileList"
        multiple
        :show-file-list="false"
        @change="handleFileChange"
      >
        <n-upload-dragger>
          <div class="upload-inner">
            <Plus :size="24" class="upload-icon" />
            <p class="upload-text">拖拽文件到此处，或点击选择</p>
            <p class="upload-hint">单文件上限 200MB</p>
          </div>
        </n-upload-dragger>
      </n-upload>
      <div v-if="attachments.length" class="file-list">
        <div v-for="(f, i) in attachments" :key="i" class="file-item">
          <span class="mono file-name">{{ f.name }}</span>
          <span class="mono file-size">{{ fmtSize(f.size) }}</span>
          <span class="mono file-type muted-text">{{ f.type }}</span>
          <n-button quaternary size="tiny" type="error" @click="removeAttachment(i)">
            <template #icon><X :size="13" /></template>
          </n-button>
        </div>
      </div>
    </div>

    <!-- ========== 补充信息 ========== -->
    <div class="panel form-section">
      <div class="section-label">补充信息 <span class="optional">（选填，{{ form.notes.length }}/2000）</span></div>
      <n-input
        v-model:value="form.notes"
        type="textarea"
        :autosize="{ minRows: 2, maxRows: 6 }"
        maxlength="2000"
        show-count
        placeholder="补充题目之外的信息，例如比赛名称、已尝试的思路、卡住的点、队友提示"
      />
    </div>

    <!-- ========== 自定义字段 ========== -->
    <div class="panel form-section">
      <div class="section-header">
        <div class="section-label">自定义字段 <span class="optional">（选填）</span></div>
        <n-button size="tiny" quaternary type="primary" @click="addCustomField">
          <template #icon><Plus :size="13" /></template>
          添加字段
        </n-button>
      </div>
      <p class="field-desc">用于填写上面未覆盖的信息，如 flag 格式、提示来源、比赛名称</p>
      <div v-for="(field, i) in form.customFields" :key="i" class="custom-field-row">
        <n-input v-model:value="field.key" placeholder="字段名" class="field-key mono" />
        <n-input v-model:value="field.value" placeholder="值" class="field-value" />
        <n-button quaternary size="tiny" type="error" @click="removeCustomField(i)">
          <template #icon><X :size="13" /></template>
        </n-button>
      </div>
    </div>

    <!-- ========== 操作按钮 ========== -->
    <div class="action-bar">
      <n-popconfirm @positive-click="submit">
        <template #trigger>
          <n-button type="primary" size="large">提交题目</n-button>
        </template>
        确认提交？提交后任务将进入待执行队列。
      </n-popconfirm>
      <n-button size="large" @click="saveDraft">保存草稿</n-button>
      <n-button text size="large" @click="reset">重置</n-button>
    </div>

    <!-- ========== 历史任务 ========== -->
    <div v-if="store.ctfTasks.length" class="panel history-section">
      <div class="section-label">历史任务 <span class="optional">（{{ store.ctfTasks.length }}）</span></div>
      <div class="history-list">
        <div
          v-for="task in store.ctfTasks"
          :key="task.id"
          class="history-item enter-anim"
        >
          <span class="mono history-cat" :style="{ color: CATEGORIES.find(c => c.value === task.category)?.color }">
            {{ task.category }}
          </span>
          <span class="history-title" @click="openDetail(task)">{{ task.title }}</span>
          <span class="mono history-time">{{ fmtTime(task.createdAt) }}</span>
          <span class="status-tag mono" :style="{ color: STATUS_MAP[task.status].color }">
            {{ STATUS_MAP[task.status].label }}
          </span>
          <div class="history-actions">
            <n-button quaternary size="tiny" type="primary" @click="openDetail(task)">详情</n-button>
            <n-popconfirm @positive-click="store.removeCtfTask(task.id)">
              <template #trigger>
                <n-button quaternary size="tiny" type="error">
                  <template #icon><Trash2 :size="13" /></template>
                </n-button>
              </template>
              确认删除这条任务？
            </n-popconfirm>
          </div>
        </div>
      </div>
    </div>

    <!-- ========== 详情抽屉 ========== -->
    <n-drawer v-model:show="showDetail" :width="520" placement="right">
      <n-drawer-content v-if="detailTask" :title="detailTask!.title" closable>
        <div class="detail-body">
          <div class="detail-row">
            <span class="detail-label">分类</span>
            <n-tag size="small" :bordered="false"
              :style="{ color: CATEGORIES.find(c => c.value === detailTask!.category)?.color }"
            >{{ detailTask!.category }}</n-tag>
          </div>
          <div class="detail-row">
            <span class="detail-label">状态</span>
            <span class="mono" :style="{ color: STATUS_MAP[detailTask!.status].color }">
              {{ STATUS_MAP[detailTask!.status].label }}
            </span>
          </div>
          <div class="detail-row" v-if="detailTask!.result?.flag">
            <span class="detail-label">执行结果</span>
            <span class="mono flag-text">{{ detailTask!.result.flag }}</span>
          </div>
          <div class="detail-row" v-if="detailTask!.result?.error">
            <span class="detail-label">错误信息</span>
            <span class="mono error-text">{{ detailTask!.result.error }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">提交时间</span>
            <span class="mono">{{ fmtTime(detailTask!.createdAt) }}</span>
          </div>
          <div class="detail-row" v-if="detailTask!.remoteUrl">
            <span class="detail-label">题目地址</span>
            <span class="mono">{{ detailTask!.remoteUrl }}</span>
          </div>
          <div class="detail-row" v-if="detailTask!.attachments.length">
            <span class="detail-label">附件</span>
            <div>
              <div v-for="(a, i) in detailTask!.attachments" :key="i" class="mono detail-attach">
                {{ a.name }} ({{ fmtSize(a.size) }})
              </div>
            </div>
          </div>
          <div class="detail-row">
            <span class="detail-label">题目描述</span>
            <pre class="detail-desc">{{ detailTask!.description }}</pre>
          </div>
          <div class="detail-row" v-if="detailTask!.notes">
            <span class="detail-label">补充信息</span>
            <pre class="detail-desc">{{ detailTask!.notes }}</pre>
          </div>
          <template v-if="detailTask!.customFields.length">
            <div class="detail-row" v-for="(f, i) in detailTask!.customFields" :key="i">
              <span class="detail-label">{{ f.key }}</span>
              <span>{{ f.value }}</span>
            </div>
          </template>
          <div class="detail-row" v-if="detailTask!.status !== 'pending'">
            <span class="detail-label">执行日志</span>
            <div class="log-box">
              <div class="log-toolbar">
                <n-button size="tiny" quaternary type="primary" @click="loadLog">刷新日志</n-button>
                <span class="log-meta mono" v-if="logMeta">{{ logMeta }}</span>
              </div>
              <pre class="log-view mono">{{ logText || '暂无日志' }}</pre>
            </div>
          </div>
        </div>
      </n-drawer-content>
    </n-drawer>
  </div>
</template>

<style scoped>
.ctf-page {
  max-width: 860px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.form-section {
  padding: 16px 18px;
}

.section-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 10px;
}
.required { color: var(--danger); }
.optional { color: var(--text-muted); font-weight: 400; }

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

/* ---- 分类卡片 ---- */
.category-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
}
.cat-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 14px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  transition: border-color 120ms, background 120ms;
  background: var(--bg-base);
}
.cat-card:hover {
  background: var(--bg-raised);
}
.cat-card.active {
  background: var(--bg-raised);
}
.cat-name {
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
}
.cat-hint {
  font-size: 12px;
  color: var(--text-secondary);
  text-align: center;
  line-height: 1.4;
}
.selected-hint {
  margin-top: 8px;
  font-size: 12px;
}

/* ---- 表单字段 ---- */
.field {
  margin-bottom: 12px;
}
.field-label {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 4px;
}
.error-hint {
  color: var(--danger);
  font-size: 12px;
  margin-top: 4px;
}

/* ---- 上传 ---- */
.upload-inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 20px 0;
}
.upload-icon {
  color: var(--text-muted);
}
.upload-text {
  color: var(--text-secondary);
  margin: 0;
}
.upload-hint {
  color: var(--text-muted);
  font-size: 12px;
  margin: 0;
}

.file-list {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.file-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 8px;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 12px;
}
.file-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.file-size {
  color: var(--text-secondary);
  min-width: 60px;
  text-align: right;
}
.file-type {
  min-width: 50px;
}

/* ---- 自定义字段 ---- */
.custom-field-row {
  display: flex;
  gap: 8px;
  margin-bottom: 6px;
}
.field-key {
  width: 160px;
}
.field-value {
  flex: 1;
}
.field-desc {
  margin: 0 0 8px;
  font-size: 12px;
  color: var(--text-muted);
}

/* ---- 操作 ---- */
.action-bar {
  display: flex;
  gap: 10px;
}

/* ---- 历史任务 ---- */
.history-section {
  padding: 16px 18px;
}
.history-list {
  display: flex;
  flex-direction: column;
}
.history-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.history-item:last-child {
  border-bottom: none;
}
.history-cat {
  width: 60px;
  font-weight: 700;
  flex-shrink: 0;
}
.history-title {
  flex: 1;
  cursor: pointer;
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.history-title:hover {
  color: var(--accent);
}
.history-time {
  color: var(--text-muted);
  font-size: 11px;
  flex-shrink: 0;
}
.status-tag {
  font-size: 11px;
  flex-shrink: 0;
}
.history-actions {
  display: flex;
  gap: 4px;
  flex-shrink: 0;
}

/* ---- 详情抽屉 ---- */
.detail-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.detail-row {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}
.detail-label {
  width: 64px;
  flex-shrink: 0;
  font-size: 12px;
  color: var(--text-muted);
  padding-top: 2px;
}
.detail-desc {
  flex: 1;
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow-y: auto;
  background: var(--bg-base);
  padding: 8px 10px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
}
.detail-attach {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 2px;
}

/* ---- 执行日志 ---- */
.log-box {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 1;
}
.log-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.log-meta {
  font-size: 11px;
  color: var(--text-muted);
}
.log-view {
  max-height: 320px;
  overflow-y: auto;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 8px 10px;
  font-size: 11px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  color: var(--text-secondary);
}
.flag-text {
  color: var(--success);
  font-weight: 600;
}
.error-text {
  color: var(--danger);
}

.muted-text { color: var(--text-muted); }
</style>
