<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { SetUserOOBEDone } from '../../../wailsjs/go/main/App.js'
import StepTheme from './StepTheme.vue'
import StepBackground from './StepBackground.vue'

const emit = defineEmits(['done'])

const { t } = useI18n()

// 步骤: welcome(让我们来设置一下用户吧) → theme → background → done
const step = ref('welcome')

async function finish() {
  try { await SetUserOOBEDone() } catch {}
  emit('done')
}
</script>

<template>
  <div class="oobe-page">
    <div class="oobe-glass">
      <!-- 欢迎页：让我们来设置一下用户吧 -->
      <div v-if="step === 'welcome'" class="oobe-step">
        <div class="oobe-kaomoji">\(@^0^@)/</div>
        <div class="oobe-greeting">{{ t('oobe.userWizardTitle') }}</div>
        <div class="oobe-subtitle">{{ t('oobe.userWizardSubtitle') }}</div>
        <button class="oobe-btn" @click="step = 'theme'">{{ t('oobe.next') }}</button>
      </div>

      <!-- 主题色 -->
      <StepTheme v-else-if="step === 'theme'" @next="step = 'background'" @back="step = 'welcome'" />

      <!-- 背景 -->
      <StepBackground v-else-if="step === 'background'" @next="step = 'done'" @back="step = 'theme'" />

      <!-- 完成 -->
      <div v-else-if="step === 'done'" class="oobe-step">
        <div class="oobe-done-icon">&#x2714;</div>
        <div class="oobe-title">{{ t('oobe.userWizardDone') }}</div>
        <div class="oobe-subtitle">{{ t('oobe.userWizardDoneSubtitle') }}</div>
        <button class="oobe-btn" @click="finish">{{ t('oobe.startUsing') }}</button>
      </div>
    </div>
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
