<script setup lang="ts">
/** 数字滚动:值变化时从旧值滚动到新值(rAF),不做跳变 */
import { onBeforeUnmount, ref, watch } from 'vue'

const props = defineProps<{
  value: number
  duration?: number // ms,默认 400
  decimals?: number
}>()

const display = ref(props.value)
let raf = 0

watch(
  () => props.value,
  (to, from) => {
    cancelAnimationFrame(raf)
    const start = performance.now()
    const dur = props.duration ?? 400
    const step = (now: number) => {
      const p = Math.min((now - start) / dur, 1)
      const eased = 1 - Math.pow(1 - p, 3) // easeOutCubic
      display.value = from + (to - from) * eased
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
  },
)

onBeforeUnmount(() => cancelAnimationFrame(raf))

const fmt = (v: number) => {
  const d = props.decimals ?? 0
  return d > 0 ? v.toFixed(d) : Math.round(v).toLocaleString()
}
</script>

<template>
  <span class="mono">{{ fmt(display) }}</span>
</template>
