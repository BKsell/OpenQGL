<script setup>
import { useI18n } from 'vue-i18n'

const emit = defineEmits(['choose', 'back'])

const { t } = useI18n()
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-title">{{ t('oobe.moreTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.moreSubtitle') }}</div>

    <!-- 访客账户作用说明 -->
    <div class="oobe-info-box">{{ t('oobe.guestExplain') }}</div>

    <div class="oobe-btn-row">
      <button class="oobe-btn" @click="emit('choose', 'yes')">{{ t('oobe.moreYes') }}</button>
      <button class="oobe-btn-outline" @click="emit('choose', 'no')">{{ t('oobe.moreNo') }}</button>
    </div>

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
