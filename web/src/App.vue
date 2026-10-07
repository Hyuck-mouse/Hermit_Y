<script setup lang="ts">
import { NConfigProvider, NDialogProvider, NMessageProvider, darkTheme, type GlobalThemeOverrides } from 'naive-ui'
import AppLayout from '@/layouts/AppLayout.vue'

const overrides: GlobalThemeOverrides = {
  common: {
    bodyColor: '#0B0E14',
    cardColor: '#12161F',
    modalColor: '#1A1F2B',
    popoverColor: '#1A1F2B',
    inputColor: '#0B0E14',
    actionColor: '#1A1F2B',
    borderColor: '#232A38',
    dividerColor: '#232A38',
    primaryColor: '#4C8DFF',
    primaryColorHover: '#6AA0FF',
    primaryColorPressed: '#3A74E0',
    primaryColorSuppl: '#4C8DFF',
    successColor: '#3FB950',
    warningColor: '#D29922',
    errorColor: '#F85149',
    infoColor: '#8B5CF6',
    textColorBase: '#E6EAF2',
    textColor1: '#E6EAF2',
    textColor2: '#8B94A7',
    textColor3: '#565E70',
    fontFamily: 'var(--font-ui)',
    fontFamilyMono: 'var(--font-mono)',
    borderRadius: '6px',
  },
}
</script>

<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="overrides">
    <n-dialog-provider>
      <n-message-provider placement="bottom-right">
        <AppLayout />
      </n-message-provider>
    </n-dialog-provider>
  </n-config-provider>
</template>
