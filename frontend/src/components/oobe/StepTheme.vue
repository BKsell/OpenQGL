<script setup>
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { GetThemeColor, SetThemeColor } from '../../../wailsjs/go/main/App.js'
import { EventsEmit } from '../../../wailsjs/runtime/runtime.js'

const emit = defineEmits(['next', 'back'])

const { t } = useI18n()

const themeColors = [
  { id: 'blue', label: 'blue', color: '#2196F3' },
  { id: 'cyan', label: 'cyan', color: '#00BCD4' },
  { id: 'pink', label: 'pink', color: '#E91E63' },
  { id: 'purple', label: 'purple', color: '#9C27B0' },
  { id: 'orange', label: 'orange', color: '#FF9800' },
  { id: 'yellow', label: 'yellow', color: '#FDD835' },
  { id: 'green', label: 'green', color: '#4CAF50' },
]

const selected = ref('cyan')

onMounted(async () => {
  try {
    const current = await GetThemeColor()
    if (current) selected.value = current
  } catch {}
})

async function selectTheme(color) {
  selected.value = color
  // 即时预览 + 持久化到当前用户配置
  EventsEmit('themeChanged', color)
  try { await SetThemeColor(color) } catch {}
}
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-title">{{ t('oobe.themeTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.themeSubtitle') }}</div>

    <div class="oobe-theme-row">
      <div
        v-for="c in themeColors"
        :key="c.id"
        class="oobe-theme-dot"
        :class="{ active: selected === c.id }"
        :style="{ background: c.color }"
        :title="c.id"
        @click="selectTheme(c.id)"
      ></div>
    </div>

    <button class="oobe-btn" @click="emit('next')">{{ t('oobe.next') }}</button>
    <button class="oobe-back-btn" @click="emit('back')">&#x2190; {{ t('oobe.back') }}</button>
  </div>
</template>

<style scoped>
.oobe-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
  width: 100%;
}
</style>
