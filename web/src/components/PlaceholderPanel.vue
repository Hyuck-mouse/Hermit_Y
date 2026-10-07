<script setup lang="ts">
import { Construction } from 'lucide-vue-next'

defineProps<{
  title: string
  hint: string
}>()
</script>

<template>
  <div class="placeholder panel">
    <Construction :size="28" :stroke-width="1.5" class="icon" />
    <h2 class="title">{{ title }}</h2>
    <p class="hint">{{ hint }}</p>
    <slot />
  </div>
</template>

<style scoped>
.placeholder {
  max-width: 560px;
  margin: 60px auto;
  padding: 48px 32px;
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.icon {
  color: var(--text-muted);
}
.title {
  margin: 8px 0 0;
  font-size: 16px;
  font-weight: 600;
}
.hint {
  margin: 0;
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.7;
}
</style>
