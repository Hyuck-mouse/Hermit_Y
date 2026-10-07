<script setup lang="ts">
defineProps<{
  status: 'ok' | 'degraded' | 'error'
  pulse?: boolean
}>()
</script>

<template>
  <span
    class="dot"
    :class="{
      'dot-ok': status === 'ok',
      'dot-warn': status === 'degraded',
      'dot-error': status === 'error',
      'pulse-dot': pulse && status === 'ok',
    }"
  />
</template>

<style scoped>
.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-ok {
  background: var(--success);
}
.dot-warn {
  background: var(--warning);
}
.dot-error {
  background: var(--danger);
}
</style>
