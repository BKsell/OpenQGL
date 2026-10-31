<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { GetFullLog, ExportLogTxt, ViewFullLog } from '../../wailsjs/go/main/App.js'

const { t } = useI18n()

const visible = ref(false)
const title = ref('')
const reason = ref('')
const feedback = ref('')
let _resolve = null

function show(options) {
  title.value = options.title || t('crash.titleFailed')
  reason.value = options.reason || ''
  feedback.value = ''
  visible.value = true
  return new Promise((resolve) => { _resolve = resolve })
}

function close() {
  visible.value = false
  if (_resolve) {
    _resolve()
    _resolve = null
  }
}

async function copyLog() {
  try {
    await navigator.clipboard.writeText(await GetFullLog())
    feedback.value = t('crash.logCopied')
  } catch (e) {
    feedback.value = t('crash.copyFailed') + String(e).replace('Error: ', '')
  }
}

async function exportLog() {
  try {
    const path = await ExportLogTxt()
    feedback.value = path ? t('crash.logExported') + path : ''
  } catch (e) {
    feedback.value = t('crash.exportFailed') + String(e).replace('Error: ', '')
  }
}

function viewLog() {
  try { ViewFullLog() } catch (e) {
    feedback.value = t('crash.viewFailed') + String(e).replace('Error: ', '')
  }
}

function copyReason() {
  if (navigator.clipboard && reason.value) {
    navigator.clipboard.writeText(reason.value)
  }
}

defineExpose({ show })
</script>

<template>
  <Transition name="dialog-fade">
    <div v-if="visible" class="crash-overlay" @click="close">
      <div class="crash-dialog" @click.stop>
        <!-- 大标题（PCL 风格） -->
        <div class="crash-title">
          <span class="crash-title-icon">&#x26A0;</span>
          <span class="crash-title-text">{{ title }}</span>
        </div>
        <div class="crash-subtitle">{{ t('crash.subtitle') }}</div>

        <!-- 原因（可点击复制） -->
        <div v-if="reason" class="crash-reason-box" @click="copyReason" :title="t('dialog.clickToCopy')">
          <div class="crash-reason-label">{{ t('crash.reasonLabel') }}</div>
          <pre class="crash-reason-text">{{ reason }}</pre>
        </div>

        <!-- 反馈信息（复制/导出结果） -->
        <div v-if="feedback" class="crash-feedback">{{ feedback }}</div>

        <!-- 按钮区（PCL 式一排小按钮） -->
        <div class="crash-btn-row">
          <button class="crash-btn" @click="viewLog">{{ t('crash.btnViewLog') }}</button>
          <button class="crash-btn" @click="exportLog">{{ t('crash.btnExportLog') }}</button>
          <button class="crash-btn" @click="copyLog">{{ t('crash.btnCopyLog') }}</button>
          <button class="crash-btn crash-btn-primary" @click="close">{{ t('crash.btnClose') }}</button>
        </div>
      </div>
    </div>
  </Transition>
</template>

<style scoped>
.crash-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10000;
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
}

.crash-dialog {
  background: rgba(255, 255, 255, 0.97);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border-radius: 16px;
  min-width: 460px;
  max-width: 680px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 12px 48px rgba(0, 0, 0, 0.25);
  overflow: hidden;
  padding: 24px 28px;
}

.crash-title {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

.crash-title-icon {
  font-size: 30px;
  color: #f44336;
}

.crash-title-text {
  font-size: 26px;
  font-weight: 800;
  color: #f44336;
}

.crash-subtitle {
  text-align: center;
  font-size: 13px;
  color: var(--text-light, #888);
  margin-top: 8px;
}

.crash-reason-box {
  margin-top: 16px;
  background: rgba(244, 67, 54, 0.06);
  border: 1px solid rgba(244, 67, 54, 0.3);
  border-radius: 10px;
  padding: 12px 14px;
  cursor: pointer;
  overflow-y: auto;
}

.crash-reason-label {
  font-size: 12px;
  font-weight: 600;
  color: #f44336;
  margin-bottom: 6px;
}

.crash-reason-text {
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text, #333);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  max-height: 200px;
  overflow-y: auto;
}

.crash-feedback {
  margin-top: 12px;
  font-size: 12px;
  color: var(--primary, #00BCD4);
  text-align: center;
  word-break: break-all;
}

.crash-btn-row {
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 18px;
}

.crash-btn {
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  border: 1px solid var(--border, rgba(0,0,0,0.12));
  background: var(--glass-bg, rgba(0,0,0,0.04));
  color: var(--text, #333);
}

.crash-btn:hover {
  border-color: var(--primary, #00BCD4);
  background: var(--primary-bg, rgba(0,188,212,0.08));
}

.crash-btn-primary {
  background: #f44336;
  border-color: #f44336;
  color: white;
}

.crash-btn-primary:hover {
  background: #d32f2f;
  border-color: #d32f2f;
}

.dialog-fade-enter-active,
.dialog-fade-leave-active {
  transition: opacity 0.2s ease;
}

.dialog-fade-enter-from,
.dialog-fade-leave-to {
  opacity: 0;
}
</style>
