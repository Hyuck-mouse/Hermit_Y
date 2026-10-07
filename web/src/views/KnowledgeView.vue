<script setup lang="ts">
import PlaceholderPanel from '@/components/PlaceholderPanel.vue'
</script>

<template>
  <PlaceholderPanel
    title="知识库管理"
    hint="灌库进度、文档列表与切片明细。依赖后端异步 /ingest 接口与文档列表接口,当前可通过 scripts/ingest.py 与 scripts/rebuild.py 命令行操作。"
  />
</template>
