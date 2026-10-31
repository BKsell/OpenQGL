<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { SelectBackgroundImage, SetBackgroundImage, GetBackgroundImageDataURL } from '../../../wailsjs/go/main/App.js'

const emit = defineEmits(['next', 'back'])

const { t } = useI18n()

// 是否使用自定义背景（null 表示用户未操作，沿用默认）
const hasCustom = ref(false)
const previewURL = ref('')
const selecting = ref(false)

async function pickImage() {
  selecting.value = true
  try {
    const result = await SelectBackgroundImage()
    if (result) {
      hasCustom.value = true
      try { previewURL.value = await GetBackgroundImageDataURL() } catch {}
    }
  } catch {}
  selecting.value = false
}

async function resetDefault() {
  hasCustom.value = false
  previewURL.value = ''
  try { await SetBackgroundImage('') } catch {}
}
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-title">{{ t('oobe.bgTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.bgSubtitle') }}</div>

    <div v-if="hasCustom && previewURL" class="oobe-bg-preview" :style="{ backgroundImage: 'url(' + previewURL + ')' }"></div>
    <div v-else class="oobe-bg-preview oobe-bg-default">{{ t('oobe.bgDefaultPreview') }}</div>

    <div class="oobe-btn-row">
      <button class="oobe-btn-outline" :disabled="selecting" @click="pickImage">
        {{ selecting ? t('oobe.bgSelecting') : t('oobe.bgSelect') }}
      </button>
      <button class="oobe-btn-outline" :disabled="!hasCustom" @click="resetDefault">{{ t('oobe.bgReset') }}</button>
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

.oobe-bg-preview {
  width: 100%;
  height: 120px;
  border-radius: 10px;
  border: 1.5px solid #E0E0E0;
  background-size: cover;
  background-position: center;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  color: #999999;
}

.oobe-bg-default {
  background: var(--primary-bg);
}
</style>
