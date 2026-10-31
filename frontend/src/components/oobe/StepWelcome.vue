<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'

const emit = defineEmits(['next'])

const { t, locale } = useI18n()

// 问候语循环：你好 → hello → hola，每 3 秒切换
const greetings = ['你好', 'hello', 'hola']
const greetingIndex = ref(0)
let timer = null

onMounted(() => {
  timer = setInterval(() => {
    greetingIndex.value = (greetingIndex.value + 1) % greetings.length
  }, 3000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})

const languages = [
  { code: 'zh-CN', name: '简体中文', native: '你好' },
  { code: 'en-US', name: 'English', native: 'hello' },
  { code: 'zh-TW', name: '繁體中文', native: '你好' },
]

function selectLanguage(code) {
  locale.value = code
  try { localStorage.setItem('qgl-locale', code) } catch {}
}
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-kaomoji">\(@^0^@)/</div>
    <div class="oobe-greeting">{{ greetings[greetingIndex] }}</div>
    <div class="oobe-subtitle">{{ t('oobe.welcomeSubtitle') }}</div>

    <div class="oobe-list">
      <div
        v-for="lang in languages"
        :key="lang.code"
        class="oobe-list-item"
        :class="{ active: locale === lang.code }"
        @click="selectLanguage(lang.code)"
      >
        <span>{{ lang.name }}</span>
        <span class="oobe-lang-native">{{ lang.native }}</span>
      </div>
    </div>

    <button class="oobe-btn" @click="emit('next')">{{ t('oobe.next') }}</button>
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

.oobe-lang-native {
  font-size: 12px;
  color: #999999;
}
</style>
