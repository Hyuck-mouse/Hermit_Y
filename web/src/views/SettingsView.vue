<script setup lang="ts">
import { ref } from 'vue'
import { useMessage, NButton, NInput } from 'naive-ui'
import { getApiBase, setApiBase } from '@/api/client'
import { useServiceStore } from '@/stores/service'

const store = useServiceStore()
const message = useMessage()

const apiBase = ref(getApiBase())

function save() {
  setApiBase(apiBase.value)
  message.success('已保存,重新验证服务状态…')
  store.refreshHealth()
  store.refreshStats()
}

function reset() {
  apiBase.value = ''
  setApiBase('')
  message.success('已恢复默认(/api 代理)')
  store.refreshHealth()
}
</script>

<template>
  <div class="settings-page">
    <div class="panel section">
      <div class="panel-title section-title">服务连接</div>
      <div class="field">
        <span class="field-label">知识服务地址</span>
        <div class="field-body">
          <n-input
            v-model:value="apiBase"
            placeholder="默认走代理: /api → http://127.0.0.1:8765"
            class="mono"
          />
          <n-button size="small" @click="reset">恢复默认</n-button>
          <n-button type="primary" size="small" @click="save">保存</n-button>
        </div>
        <p class="field-hint">
          留空使用开发代理(仅 npm run dev 下可用);直连地址如 http://127.0.0.1:8765 用于构建产物部署。
        </p>
      </div>
    </div>

    <div class="panel section">
      <div class="panel-title section-title">关于</div>
      <div class="about mono">
        <div><span class="muted-text">version</span><span>web 0.1.0</span></div>
        <div><span class="muted-text">backend</span><span>knowledge_service (FastAPI)</span></div>
        <div><span class="muted-text">retrieval</span><span>BGE + BM25 · RRF 融合 · 域外守门</span></div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  max-width: 640px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.section {
  padding: 16px 18px;
}
.section-title {
  margin-bottom: 12px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.field-label {
  font-size: 12px;
  color: var(--text-secondary);
}
.field-body {
  display: flex;
  gap: 8px;
}
.field-body .n-input {
  flex: 1;
}
.field-hint {
  margin: 4px 0 0;
  font-size: 11px;
  color: var(--text-muted);
}
.about {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 12px;
}
.about > div {
  display: flex;
  justify-content: space-between;
}
.muted-text { color: var(--text-muted); }
</style>
