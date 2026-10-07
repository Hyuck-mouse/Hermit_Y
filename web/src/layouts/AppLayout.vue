<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  ChevronsLeft,
  ChevronsRight,
  Crosshair,
  Database,
  FlaskConical,
  LayoutDashboard,
  Radar,
  Search,
  Settings,
  Swords,
} from 'lucide-vue-next'
import { useServiceStore } from '@/stores/service'
import { useTaskStore } from '@/stores/task'
import StatusDot from '@/components/StatusDot.vue'

const route = useRoute()
const store = useServiceStore()
const taskStore = useTaskStore()

const collapsed = ref(false)

const navItems = [
  { path: '/', label: '总览', icon: LayoutDashboard },
  { path: '/monitor', label: 'Agent 监控', icon: Radar },
  { path: '/knowledge', label: '知识库', icon: Database },
  { path: '/search', label: '检索台', icon: Search },
  { path: '/ctf', label: 'CTF', icon: Swords },
  { path: '/pentest', label: '渗透测试', icon: Crosshair },
  { path: '/eval', label: '评测', icon: FlaskConical },
  { path: '/settings', label: '设置', icon: Settings },
]

const pageTitle = computed(() => (route.meta.title as string) ?? '')

onMounted(() => {
  store.refreshHealth()
  store.refreshStats()
  // 30s 轮询服务健康状态(轻量 GET)
  setInterval(() => store.refreshHealth(), 30_000)
})

/* 任务状态 5s 全量轮询:仅在 CTF/渗透测试相关页面运行(列表与执行视图共用) */
let taskTimer: number | undefined
watch(() => route.path, (p) => {
  const onTaskPage = p.startsWith('/ctf') || p.startsWith('/pentest')
  if (onTaskPage && taskTimer === undefined) {
    taskStore.init()
    taskTimer = window.setInterval(() => taskStore.init(), 5000)
  } else if (!onTaskPage && taskTimer !== undefined) {
    clearInterval(taskTimer)
    taskTimer = undefined
  }
}, { immediate: true })
</script>

<template>
  <div class="shell">
    <!-- 左侧窄边栏 -->
    <aside class="sidebar" :class="{ collapsed }">
      <div class="brand">
        <span class="brand-mark mono">&gt;_</span>
        <span v-if="!collapsed" class="brand-name">CTF AI Console</span>
      </div>
      <nav class="nav">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="nav-item"
          :class="{ active: route.path === item.path }"
        >
          <component :is="item.icon" :size="17" :stroke-width="1.8" />
          <span v-if="!collapsed">{{ item.label }}</span>
        </router-link>
      </nav>
      <button class="collapse-btn" @click="collapsed = !collapsed">
        <ChevronsLeft v-if="!collapsed" :size="15" />
        <ChevronsRight v-else :size="15" />
      </button>
    </aside>

    <!-- 主区域 -->
    <div class="main">
      <!-- 全局状态条 -->
      <header class="statusbar">
        <span class="statusbar-title">{{ pageTitle }}</span>
        <span class="statusbar-spacer" />
        <StatusDot :status="store.isOk ? 'ok' : 'degraded'" :pulse="store.isOk" />
        <span class="mono status-item" :class="store.isOk ? 'ok-text' : 'warn-text'">
          {{ store.isOk ? '运行中' : store.isDegraded ? '降级' : '连接失败' }}
        </span>
        <span v-if="store.health?.model" class="mono status-item muted-text">
          {{ store.health.model }}
        </span>
        <span v-if="store.stats" class="mono status-item muted-text">
          {{ store.stats.total_chunks }} 条
        </span>
        <span v-if="store.lastError" class="mono status-item error-text" :title="store.lastError">
          {{ store.lastError }}
        </span>
      </header>

      <main class="content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  height: 100%;
  overflow: hidden;
}

/* ---- 侧边栏 ---- */
.sidebar {
  width: 210px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  background: var(--bg-surface);
  border-right: 1px solid var(--border);
  transition: width 150ms ease;
}
.sidebar.collapsed {
  width: 56px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 14px 12px;
  border-bottom: 1px solid var(--border);
  overflow: hidden;
  white-space: nowrap;
}
.brand-mark {
  color: var(--accent);
  font-weight: 700;
  font-size: 14px;
}
.brand-name {
  font-weight: 600;
  font-size: 13px;
  letter-spacing: 0.02em;
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px;
  flex: 1;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 10px;
  border-radius: var(--radius);
  color: var(--text-secondary);
  text-decoration: none;
  white-space: nowrap;
  transition: background 120ms, color 120ms;
}
.nav-item:hover {
  background: var(--bg-raised);
  color: var(--text-primary);
}
.nav-item.active {
  background: var(--bg-raised);
  color: var(--accent);
}

.collapse-btn {
  margin: 8px;
  padding: 6px;
  display: flex;
  justify-content: center;
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-muted);
  cursor: pointer;
  transition: color 120ms;
}
.collapse-btn:hover {
  color: var(--text-primary);
}

/* ---- 主区域 ---- */
.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.statusbar {
  display: flex;
  align-items: center;
  gap: 14px;
  height: 42px;
  padding: 0 18px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-surface);
  flex-shrink: 0;
}
.statusbar-title {
  font-weight: 600;
  font-size: 13px;
}
.statusbar-spacer {
  flex: 1;
}
.status-item {
  font-size: 12px;
}
.ok-text { color: var(--success); }
.warn-text { color: var(--warning); }
.error-text { color: var(--danger); }
.muted-text { color: var(--text-muted); }

.content {
  flex: 1;
  overflow-y: auto;
  padding: 18px;
}
</style>
