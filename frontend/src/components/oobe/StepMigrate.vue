<script setup>
import { useI18n } from 'vue-i18n'

const emit = defineEmits(['choose', 'back'])

const { t } = useI18n()
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-title">{{ t('oobe.migrateQTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.migrateQSubtitle') }}</div>

    <div class="oobe-choice-row">
      <button class="oobe-choice-card" @click="emit('choose', 'migrate')">
        <div class="oobe-choice-name">{{ t('oobe.migrateYes') }}</div>
        <div class="oobe-choice-desc">{{ t('oobe.migrateYesDesc') }}</div>
      </button>
      <button class="oobe-choice-card" @click="emit('choose', 'fresh')">
        <div class="oobe-choice-name">{{ t('oobe.migrateNo') }}</div>
        <div class="oobe-choice-desc">{{ t('oobe.migrateNoDesc') }}</div>
      </button>
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
