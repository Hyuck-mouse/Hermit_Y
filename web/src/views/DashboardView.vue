<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { NButton, NTag } from 'naive-ui'
import CountUp from '@/components/CountUp.vue'
import { useServiceStore } from '@/stores/service'

const store = useServiceStore()
const router = useRouter()

/* ---- 类别/类型颜色映射(语义化:颜色承担语义) ---- */
const CAT_COLORS: Record<string, string> = {
  src_course: '#4C8DFF',
  vuln_kb: '#F85149',
  tools: '#8B5CF6',
  payloads: '#D29922',
  unknown: '#565E70',
}
const TYPE_COLORS: Record<string, string> = {
  doc: '#4C8DFF',
  data: '#D29922',
  code: '#8B5CF6',
  tool_card: '#3FB950',
  binary: '#F85149',
  unknown: '#565E70',
}

interface DistItem {
  key: string
  count: number
  pct: number
  color: string
}

function toDist(map: Record<string, number>, colors: Record<string, string>): DistItem[] {
  const total = Object.values(map).reduce((a, b) => a + b, 0) || 1
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .map(([key, count]) => ({
      key,
      count,
      pct: (count / total) * 100,
      color: colors[key] ?? colors.unknown,
    }))
}

const catDist = computed(() => toDist(store.stats?.by_category ?? {}, CAT_COLORS))
const typeDist = computed(() => toDist(store.stats?.by_content_type ?? {}, TYPE_COLORS))
const totalChunks = computed(() => store.stats?.total_chunks ?? 0)

/* ---- 最近检索 ---- */
function fmtTime(ts: number) {
  const d = new Date(ts)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
</script>

<template>
  <div class="dashboard">
    <!-- KPI 行:扁平 + 细边框 + 等宽大数字 -->
    <div class="kpi-row">
      <div class="panel kpi-card enter-anim">
        <span class="kpi-label">文档数</span>
        <span class="kpi-value"><CountUp :value="store.stats?.doc_count ?? 0" /></span>
        <span class="kpi-sub muted-text mono">源文件数</span>
      </div>
      <div class="panel kpi-card enter-anim" style="animation-delay: 40ms">
        <span class="kpi-label">切片数</span>
        <span class="kpi-value"><CountUp :value="totalChunks" /></span>
        <span class="kpi-sub muted-text mono">chunks</span>
      </div>
      <div class="panel kpi-card enter-anim" style="animation-delay: 80ms">
        <span class="kpi-label">类别数</span>
        <span class="kpi-value"><CountUp :value="catDist.length" /></span>
        <span class="kpi-sub muted-text mono">categories</span>
      </div>
      <div class="panel kpi-card enter-anim" style="animation-delay: 120ms">
        <span class="kpi-label">服务状态</span>
        <span class="kpi-status">
          <n-tag :type="store.isOk ? 'success' : 'warning'" size="large" :bordered="false">
            {{ store.isOk ? 'OK' : 'DEGRADED' }}
          </n-tag>
        </span>
        <span class="kpi-sub muted-text mono">{{ store.health?.model || '—' }}</span>
      </div>
    </div>

    <!-- 分布行:横向堆叠条 -->
    <div class="dist-row">
      <div class="panel dist-card enter-anim" style="animation-delay: 160ms">
        <div class="panel-title">类别分布</div>
        <div v-if="totalChunks" class="stack-bar">
          <div
            v-for="d in catDist"
            :key="d.key"
            :style="{ width: d.pct + '%', background: d.color }"
            class="stack-seg"
            :title="`${d.key}: ${d.count} (${d.pct.toFixed(1)}%)`"
          />
        </div>
        <div v-else class="stack-bar empty" />
        <div class="legend">
          <span v-for="d in catDist" :key="d.key" class="legend-item mono">
            <i :style="{ background: d.color }" />{{ d.key }} {{ d.pct.toFixed(1) }}%
          </span>
        </div>
      </div>

      <div class="panel dist-card enter-anim" style="animation-delay: 200ms">
        <div class="panel-title">类型分布</div>
        <div v-if="totalChunks" class="stack-bar">
          <div
            v-for="d in typeDist"
            :key="d.key"
            :style="{ width: d.pct + '%', background: d.color }"
            class="stack-seg"
            :title="`${d.key}: ${d.count} (${d.pct.toFixed(1)}%)`"
          />
        </div>
        <div v-else class="stack-bar empty" />
        <div class="legend">
          <span v-for="d in typeDist" :key="d.key" class="legend-item mono">
            <i :style="{ background: d.color }" />{{ d.key }} {{ d.pct.toFixed(1) }}%
          </span>
        </div>
      </div>
    </div>

    <!-- 底部行:最近检索 + 服务详情 -->
    <div class="bottom-row">
      <div class="panel list-card enter-anim" style="animation-delay: 240ms">
        <div class="card-head">
          <span class="panel-title">最近检索</span>
          <n-button quaternary size="tiny" type="primary" @click="router.push('/search')">
            去检索
          </n-button>
        </div>
        <div v-if="store.recentSearches.length" class="recent-list">
          <div
            v-for="(r, i) in store.recentSearches"
            :key="i"
            class="recent-item enter-anim"
            :style="{ animationDelay: `${i * 30}ms` }"
          >
            <span class="mono recent-query" :title="r.query">{{ r.query }}</span>
            <span class="mono" :class="r.hits ? 'ok-text' : 'warn-text'">{{ r.hits }} hits</span>
            <span class="mono muted-text">{{ r.ms }}ms</span>
            <span class="mono muted-text">{{ fmtTime(r.ts) }}</span>
          </div>
        </div>
        <p v-else class="empty-text muted-text">本会话暂无检索记录</p>
      </div>

      <div class="panel list-card enter-anim" style="animation-delay: 280ms">
        <div class="card-head">
          <span class="panel-title">服务详情</span>
          <n-button quaternary size="tiny" @click="store.refreshHealth(); store.refreshStats()">
            刷新
          </n-button>
        </div>
        <div class="detail-list mono">
          <div class="detail-item">
            <span class="muted-text">status</span>
            <span :class="store.isOk ? 'ok-text' : 'warn-text'">{{ store.health?.status ?? '—' }}</span>
          </div>
          <div class="detail-item">
            <span class="muted-text">model</span>
            <span>{{ store.health?.model || '—' }}</span>
          </div>
          <div class="detail-item">
            <span class="muted-text">endpoint</span>
            <span>127.0.0.1:8765</span>
          </div>
          <div v-if="store.health?.detail" class="detail-item">
            <span class="muted-text">detail</span>
            <span class="error-text detail-ellipsis" :title="store.health.detail">{{ store.health.detail }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dashboard {
  max-width: 1100px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* ---- KPI ---- */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
}
.kpi-card {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 16px 18px;
}
.kpi-label {
  font-size: 12px;
  color: var(--text-secondary);
}
.kpi-value {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: 30px;
  font-weight: 700;
  line-height: 1.2;
}
.kpi-sub {
  font-size: 11px;
}
.kpi-status {
  display: flex;
  align-items: center;
  min-height: 38px;
}

/* ---- 分布 ---- */
.dist-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.dist-card {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.stack-bar {
  display: flex;
  height: 14px;
  border-radius: 3px;
  overflow: hidden;
  background: var(--bg-base);
}
.stack-bar.empty {
  background: var(--bg-base);
}
.stack-seg {
  height: 100%;
  min-width: 2px;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 14px;
}
.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--text-secondary);
}
.legend-item i {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  display: inline-block;
}

/* ---- 底部 ---- */
.bottom-row {
  display: grid;
  grid-template-columns: 1.4fr 1fr;
  gap: 14px;
}
.list-card {
  padding: 14px 16px;
}
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.recent-list {
  display: flex;
  flex-direction: column;
}
.recent-item {
  display: grid;
  grid-template-columns: 1fr 70px 60px 70px;
  gap: 12px;
  align-items: center;
  padding: 6px 0;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
}
.recent-item:last-child {
  border-bottom: none;
}
.recent-query {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.detail-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 12px;
}
.detail-item {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.detail-ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 260px;
}

.empty-text {
  font-size: 12px;
  text-align: center;
  padding: 18px 0;
  margin: 0;
}

.ok-text { color: var(--success); }
.warn-text { color: var(--warning); }
.error-text { color: var(--danger); }
.muted-text { color: var(--text-muted); }

@media (max-width: 900px) {
  .kpi-row {
    grid-template-columns: repeat(2, 1fr);
  }
  .dist-row,
  .bottom-row {
    grid-template-columns: 1fr;
  }
}
</style>
