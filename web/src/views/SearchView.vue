<script setup lang="ts">
import { computed, ref } from 'vue'
import { useMessage, NButton, NInput, NInputNumber, NSelect } from 'naive-ui'
import { Copy, Loader2, Search } from 'lucide-vue-next'
import { useServiceStore } from '@/stores/service'
import type { SearchResultItem } from '@/api/types'

const store = useServiceStore()
const message = useMessage()

const query = ref('')
const category = ref<string | null>(null)
const contentType = ref<string | null>(null)
const topK = ref(5)
const loading = ref(false)

const results = ref<SearchResultItem[]>([])
const degraded = ref(false)
const ms = ref(0)
const searched = ref(false)

const categoryOptions = [
  { label: '全部类别', value: '' },
  { label: 'src_course 课程资料', value: 'src_course' },
  { label: 'vuln_kb 漏洞库', value: 'vuln_kb' },
  { label: 'tools 工具', value: 'tools' },
  { label: 'payloads 载荷', value: 'payloads' },
]
const typeOptions = [
  { label: '全部类型', value: '' },
  { label: 'doc 文档', value: 'doc' },
  { label: 'data 数据', value: 'data' },
  { label: 'code 源码', value: 'code' },
  { label: 'tool_card 技能卡', value: 'tool_card' },
  { label: 'binary 二进制', value: 'binary' },
]

async function doSearch() {
  const q = query.value.trim()
  if (!q) return
  loading.value = true
  try {
    const res = await store.search({
      query: q,
      top_k: topK.value,
      category: category.value || null,
      content_type: contentType.value || null,
    })
    results.value = res.results
    degraded.value = res.degraded
    ms.value = res.ms
    searched.value = true
  } catch (e) {
    message.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

/** 剥离 Markdown/HTML 标记,只保留纯文本(保守方案,不渲染防 XSS) */
function stripMarkup(text: string): string {
  return text
    .replace(/<\/?[a-zA-Z][^>]*>/g, '')          // <h3 id="...">、</h3> 等标签
    .replace(/\*\*([^*]+)\*\*/g, '$1')           // **加粗**
    .replace(/^#{1,6}\s+/gm, '')                 // ## 标题井号
    .replace(/`([^`]+)`/g, '$1')                 // `行内代码`
}

/** 简单词高亮:按空白拆 token,命中处包 mark */
function highlight(text: string): string {
  const tokens = query.value.trim().split(/\s+/).filter((t) => t.length >= 2)
  if (!tokens.length) return escapeHtml(text)
  const re = new RegExp(`(${tokens.map(escapeRe).join('|')})`, 'gi')
  return escapeHtml(text).replace(re, '<mark>$1</mark>')
}
const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** 内容预览:默认前 6 行(剥离标记后的纯文本),可展开 */
const expanded = ref<Set<number>>(new Set())
function toggleExpand(i: number) {
  const next = new Set(expanded.value)
  next.has(i) ? next.delete(i) : next.add(i)
  expanded.value = next
}
function plainText(content: string): string {
  return stripMarkup(content)
}
function preview(text: string, i: number) {
  if (expanded.value.has(i)) return text
  const lines = text.split('\n')
  return lines.length > 6 ? lines.slice(0, 6).join('\n') + '\n…' : text
}

async function copyResult(item: SearchResultItem) {
  await navigator.clipboard.writeText(`${item.source}\n\n${item.content}`)
  message.success('已复制到剪贴板')
}

/** 类别/类型标签颜色 */
const catColor = (c: string) =>
  ({ src_course: 'var(--accent)', vuln_kb: 'var(--danger)', tools: 'var(--info)', payloads: 'var(--warning)' })[c] ?? 'var(--text-muted)'

const hasResults = computed(() => results.value.length > 0)
</script>

<template>
  <div class="search-page">
    <!-- 检索表单 -->
    <div class="panel form-panel">
      <div class="query-row">
        <n-input
          v-model:value="query"
          placeholder="输入检索问题,如:若依后台信息泄漏 / heapdump 利用"
          size="large"
          :input-props="{ class: 'mono' }"
          @keydown.enter="doSearch"
        />
        <n-button type="primary" size="large" :loading="loading" @click="doSearch">
          <template #icon><Search :size="15" /></template>
          检索
        </n-button>
      </div>
      <div class="filter-row">
        <n-select v-model:value="category" :options="categoryOptions" class="filter-select" size="small" placeholder="全部类别" />
        <n-select v-model:value="contentType" :options="typeOptions" class="filter-select" size="small" placeholder="全部类型" />
        <n-input-number v-model:value="topK" :min="1" :max="20" size="small" class="topk-input">
          <template #prefix>top_k</template>
        </n-input-number>
      </div>
    </div>

    <!-- 状态行 -->
    <div v-if="searched" class="meta-row enter-anim">
      <span v-if="degraded" class="degraded-tag">⚠ 服务降级,结果不可用</span>
      <template v-else>
        <span class="mono meta-text">
          {{ results.length }} hits · {{ ms }}ms
        </span>
      </template>
    </div>

    <!-- 空态:区分"未检索"与"未命中(可能域外守门)" -->
    <div v-if="searched && !degraded && !hasResults" class="panel empty-panel enter-anim">
      <span class="warn-text mono">0 hits</span>
      <p class="empty-hint">未命中知识库。若查询词与安全域无关,可能被 BM25 域外守门拦截(返回空)。</p>
    </div>

    <!-- 结果卡列表 -->
    <div
      v-for="(item, i) in results"
      :key="i"
      class="panel result-card enter-anim"
      :style="{ animationDelay: `${i * 40}ms` }"
    >
      <div class="result-head">
        <span class="score mono">{{ item.score.toFixed(4) }}</span>
        <span class="source mono" :title="item.source">{{ item.source }}</span>
        <span class="tag mono" :style="{ color: catColor(item.category) }">{{ item.category }}</span>
        <span class="tag mono muted-text">{{ item.content_type }}</span>
        <span class="result-actions">
          <n-button quaternary size="tiny" @click="copyResult(item)">
            <template #icon><Copy :size="13" /></template>
          </n-button>
        </span>
      </div>
      <pre class="result-content mono" v-html="highlight(preview(plainText(item.content), i))" />
      <div class="result-foot" v-if="plainText(item.content).split('\n').length > 6 || expanded.has(i)">
        <n-button quaternary size="tiny" type="primary" @click="toggleExpand(i)">
          {{ expanded.has(i) ? '收起' : '展开全文' }}
        </n-button>
      </div>
    </div>

    <!-- 加载中 -->
    <div v-if="loading" class="loading-row">
      <Loader2 :size="16" class="spin" />
      <span class="muted-text">检索中…</span>
    </div>
  </div>
</template>

<style scoped>
.search-page {
  max-width: 860px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.form-panel {
  padding: 14px;
}
.query-row {
  display: flex;
  gap: 10px;
}
.query-row .n-input {
  flex: 1;
}
.filter-row {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}
.filter-select {
  width: 190px;
}
.topk-input {
  width: 150px;
}

.meta-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 2px;
}
.meta-text {
  color: var(--text-secondary);
  font-size: 12px;
}
.degraded-tag {
  color: var(--warning);
  font-size: 12px;
}

.empty-panel {
  padding: 28px;
  text-align: center;
}
.empty-hint {
  color: var(--text-secondary);
  margin: 8px 0 0;
}

.result-card {
  padding: 12px 14px;
  border-left: 3px solid var(--success);
}
.result-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.score {
  font-size: 16px;
  font-weight: 700;
  color: var(--success);
  min-width: 68px;
}
.source {
  color: var(--text-primary);
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}
.tag {
  font-size: 11px;
  flex-shrink: 0;
}
.result-actions {
  flex-shrink: 0;
}

.result-content {
  margin: 0;
  padding: 10px 12px;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 12px;
  line-height: 1.7;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 420px;
  overflow-y: auto;
}
.result-content :deep(mark) {
  background: rgba(76, 141, 255, 0.25);
  color: var(--accent);
  border-radius: 2px;
  padding: 0 1px;
}

.result-foot {
  margin-top: 6px;
  text-align: right;
}

.loading-row {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 24px;
}
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.warn-text { color: var(--warning); }
.muted-text { color: var(--text-muted); }
</style>
