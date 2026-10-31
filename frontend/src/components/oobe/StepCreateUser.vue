<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  CreateOfflineUser, CreateGuestUser, StartMicrosoftLogin
} from '../../../wailsjs/go/main/App.js'
import { EventsOn, EventsOff } from '../../../wailsjs/runtime/runtime.js'

const props = defineProps({
  mode: { type: String, default: 'initial' } // 'initial' | 'more'
})

const emit = defineEmits(['created', 'skip', 'back'])

const { t } = useI18n()

const selected = ref('') // 'offline' | 'premium' | 'external' | 'guest'
const error = ref('')
const loading = ref(false)

// 离线
const offlineName = ref('')
// 访客
const guestName = ref('')
const guestPwd = ref('')
const guestPwd2 = ref('')

// 微软登录
const msLoginStep = ref('')
const msDeviceCode = ref('')
const msVerifyURL = ref('')
const msProgressMsg = ref('')

onMounted(() => {
  EventsOn('msLoginSuccess', () => {
    loading.value = false
    msLoginStep.value = ''
    emit('created', 'premium')
  })
  EventsOn('msLoginError', (errMsg) => {
    loading.value = false
    msLoginStep.value = ''
    error.value = errMsg
  })
  EventsOn('msLoginProgress', (msg) => {
    msProgressMsg.value = msg
  })
})

onUnmounted(() => {
  EventsOff('msLoginSuccess')
  EventsOff('msLoginError')
  EventsOff('msLoginProgress')
})

const showGuest = computed(() => props.mode === 'more')

function choose(type) {
  selected.value = type
  error.value = ''
}

async function createOffline() {
  const name = offlineName.value.trim()
  if (!name) { error.value = t('migrate.enterName'); return }
  if (name.length < 2) { error.value = t('migrate.nameMinLength'); return }
  loading.value = true
  error.value = ''
  try {
    await CreateOfflineUser(name, '')
    emit('created', 'offline')
  } catch (e) {
    error.value = String(e).replace('Error: ', '')
  } finally {
    loading.value = false
  }
}

async function createGuest() {
  const name = guestName.value.trim()
  const pwd = guestPwd.value
  if (!name) { error.value = t('migrate.enterName'); return }
  if (name.length < 2) { error.value = t('migrate.nameMinLength'); return }
  if (pwd.length < 4) { error.value = t('login.securityPasswordMinLength'); return }
  if (pwd !== guestPwd2.value) { error.value = t('login.passwordMismatch'); return }
  loading.value = true
  error.value = ''
  try {
    await CreateGuestUser(name, pwd)
    emit('created', 'guest')
  } catch (e) {
    error.value = String(e).replace('Error: ', '')
  } finally {
    loading.value = false
  }
}

async function startPremium() {
  error.value = ''
  loading.value = true
  msLoginStep.value = 'polling'
  msProgressMsg.value = t('login.gettingDeviceCode')
  try {
    const result = await StartMicrosoftLogin()
    const parts = result.split('|')
    msVerifyURL.value = parts[0] || ''
    msDeviceCode.value = parts[1] || ''
    msLoginStep.value = 'device-code'
    msProgressMsg.value = t('login.completeLoginInBrowser')
  } catch (e) {
    loading.value = false
    msLoginStep.value = ''
    error.value = String(e).replace('Error: ', '')
  }
}
</script>

<template>
  <div class="oobe-step">
    <div class="oobe-title">{{ mode === 'more' ? t('oobe.createMoreTitle') : t('oobe.createTitle') }}</div>
    <div class="oobe-subtitle">{{ t('oobe.createSubtitle') }}</div>

    <!-- 微软登录流程 -->
    <template v-if="msLoginStep === 'device-code'">
      <div class="oobe-info-box oobe-ms-box">
        <div class="oobe-ms-hint">{{ t('login.autoOpenedBrowser') }}</div>
        <div class="oobe-ms-label">{{ t('login.step1OpenUrl') }}</div>
        <div class="oobe-ms-url">{{ msVerifyURL }}</div>
        <div class="oobe-ms-label">{{ t('login.step2EnterCode') }}</div>
        <div class="oobe-ms-code">{{ msDeviceCode }}</div>
        <div class="oobe-ms-progress">{{ msProgressMsg }}</div>
      </div>
    </template>
    <template v-else-if="msLoginStep === 'polling'">
      <div class="oobe-checking">
        <div class="oobe-spinner"></div>
        <div class="oobe-subtitle">{{ msProgressMsg }}</div>
      </div>
    </template>

    <template v-else>
      <div class="oobe-choice-row">
        <button class="oobe-choice-card" :class="{ selected: selected === 'offline' }" @click="choose('offline')">
          <div class="oobe-choice-name">{{ t('login.offline') }}</div>
          <div class="oobe-choice-desc">{{ t('oobe.offlineDesc') }}</div>
        </button>
        <button class="oobe-choice-card" :class="{ selected: selected === 'premium' }" @click="choose('premium')">
          <div class="oobe-choice-name">{{ t('login.premium') }}</div>
          <div class="oobe-choice-desc">{{ t('oobe.premiumDesc') }}</div>
        </button>
        <button class="oobe-choice-card" :class="{ selected: selected === 'external' }" @click="choose('external')">
          <div class="oobe-choice-name">{{ t('login.external') }}</div>
          <div class="oobe-choice-desc">{{ t('oobe.externalDesc') }}</div>
        </button>
        <button v-if="showGuest" class="oobe-choice-card" :class="{ selected: selected === 'guest' }" @click="choose('guest')">
          <div class="oobe-choice-name">{{ t('login.guest') }}</div>
          <div class="oobe-choice-desc">{{ t('oobe.guestDesc') }}</div>
        </button>
      </div>

      <!-- 离线创建 -->
      <div v-if="selected === 'offline'" class="oobe-form">
        <input v-model="offlineName" class="oobe-input" :placeholder="t('migrate.offlineName')" @keyup.enter="createOffline" />
        <button class="oobe-btn" :disabled="loading" @click="createOffline">
          {{ loading ? t('migrate.migrating') : t('oobe.createAndContinue') }}
        </button>
      </div>

      <!-- 访客创建 -->
      <div v-else-if="selected === 'guest'" class="oobe-form">
        <input v-model="guestName" class="oobe-input" :placeholder="t('oobe.guestName')" />
        <input v-model="guestPwd" type="password" class="oobe-input" :placeholder="t('login.securityPassword')" />
        <input v-model="guestPwd2" type="password" class="oobe-input" :placeholder="t('login.confirmPassword')" />
        <button class="oobe-btn" :disabled="loading" @click="createGuest">
          {{ loading ? t('migrate.migrating') : t('oobe.createAndContinue') }}
        </button>
      </div>

      <!-- 正版创建 -->
      <div v-else-if="selected === 'premium'" class="oobe-form">
        <button class="oobe-btn" :disabled="loading" @click="startPremium">{{ t('login.loginMicrosoft') }}</button>
      </div>

      <!-- 外置：稍后添加 -->
      <div v-else-if="selected === 'external'" class="oobe-form">
        <div class="oobe-info-box">{{ t('oobe.externalLater') }}</div>
        <button class="oobe-btn-outline" @click="emit('skip')">{{ t('oobe.continueBtn') }}</button>
      </div>
    </template>

    <div v-if="error" class="oobe-error">{{ error }}</div>

    <button v-if="msLoginStep === ''" class="oobe-back-btn" @click="emit('back')">&#x2190; {{ t('oobe.back') }}</button>
  </div>
</template>

<style scoped>
.oobe-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
  width: 100%;
}

.oobe-choice-card.selected {
  border-color: var(--primary);
  background: var(--primary-bg);
}

.oobe-form {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  width: 100%;
}

.oobe-ms-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.oobe-ms-hint {
  background: #E8F5E9;
  color: #2E7D32;
  padding: 4px 14px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.oobe-ms-label {
  font-size: 13px;
  color: #666666;
  align-self: flex-start;
}

.oobe-ms-url {
  background: #F5F5F5;
  border: 1px solid #E0E0E0;
  border-radius: 4px;
  padding: 6px 10px;
  font-size: 12.5px;
  color: var(--primary-dark);
  word-break: break-all;
  font-family: monospace;
  width: 100%;
  box-sizing: border-box;
}

.oobe-ms-code {
  background: var(--primary-bg);
  border: 2px solid var(--primary);
  border-radius: 4px;
  padding: 8px;
  font-size: 20px;
  font-weight: 700;
  color: var(--primary-dark);
  letter-spacing: 4px;
  font-family: monospace;
  width: 100%;
  text-align: center;
  box-sizing: border-box;
}

.oobe-ms-progress {
  font-size: 12px;
  color: var(--primary);
  font-weight: 500;
}
</style>
