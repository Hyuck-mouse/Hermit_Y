import { createRouter, createWebHashHistory } from 'vue-router'

// Hash 路由:本地工具,免history模式的服务端配置
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'dashboard', component: () => import('@/views/DashboardView.vue'), meta: { title: '总览' } },
    { path: '/monitor', name: 'monitor', component: () => import('@/views/MonitorView.vue'), meta: { title: 'Agent 监控' } },
    { path: '/knowledge', name: 'knowledge', component: () => import('@/views/KnowledgeView.vue'), meta: { title: '知识库' } },
    { path: '/search', name: 'search', component: () => import('@/views/SearchView.vue'), meta: { title: '检索台' } },
    { path: '/ctf', name: 'ctf', component: () => import('@/views/CtfView.vue'), meta: { title: 'CTF' } },
    { path: '/ctf/task/:id', name: 'ctf-task', component: () => import('@/views/CtfTaskView.vue'), meta: { title: '任务执行' } },
    { path: '/pentest', name: 'pentest', component: () => import('@/views/PentestView.vue'), meta: { title: '渗透测试' } },
    { path: '/eval', name: 'eval', component: () => import('@/views/EvalView.vue'), meta: { title: '评测' } },
    { path: '/settings', name: 'settings', component: () => import('@/views/SettingsView.vue'), meta: { title: '设置' } },
  ],
})

export default router
