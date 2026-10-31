<script setup>
import { useI18n } from 'vue-i18n'

const emit = defineEmits(['start', 'back'])

const { t } = useI18n()
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-done-icon">&#x2714;</div>
    <div class="oobe-title">{{ t('oobe.doneTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.doneSubtitle') }}</div>
    <button class="oobe-btn" @click="emit('start')">{{ t('oobe.startUsing') }}</button>
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
