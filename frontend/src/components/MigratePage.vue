<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  MigrateFromPCLCE, SelectPclExe, GetPclMcDir, SelectMinecraftDir,
  GetPclCEMcDir, MigrateMinecraftDir, CreateOfflineUser, SetCurrentUser,
  SetVersionIsolation, StartMicrosoftLogin
} from '../../wailsjs/go/main/App.js'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'

const props = defineProps({
  currentUser: Object
})

const emit = defineEmits(['back', 'finished', 'login-success'])

const { t } = useI18n()

// ===== 迁移向导状态 =====
// step: 0=选择来源 1=来源操作 2=目录迁移 3=账户设置(PCL) 4=完成
const step = ref(0)
const source = ref('') // 'pclce' | 'pcl'
const error = ref('')
const loading = ref(false)

// PCL CE 结果
const ceResult = ref(null)

// PCL 配置
const pclExePath = ref('')
const pclMcDir = ref('')

// 目录迁移模式
const dirMode = ref('full') // 'full' | 'minimal'

// PCL 账户设置
const accountMode = ref('') // 'offline' | 'premium' | 'external'
const offlineName = ref('')

// 微软登录（PCL 正版迁移）
const msLoginStep = ref('') // 'device-code' | 'polling'
const msDeviceCode = ref('')
const msVerifyURL = ref('')
const msProgressMsg = ref('')

const finalMcDir = ref('')
const migratedUser = ref(null)

// 复用入口（OOBE 以后可用）：是否显示返回按钮
const showBack = computed(() => true)

onMounted(() => {
  EventsOn('msLoginSuccess', (mcUsername) => {
    // PCL 正版迁移：登录成功后设置版本隔离并完成
    loading.value = false
    msLoginStep.value = ''
    migratedUser.value = mcUsername
    finishAndLogin(mcUsername, 'premium')
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

function chooseSource(s) {
  source.value = s
  error.value = ''
  step.value = 1
}

function goBack() {
  if (step.value <= 0 || loading.value) {
    emit('back')
    return
  }
  if (step.value === 1) {
    step.value = 0
    source.value = ''
  } else if (step.value === 2) {
    step.value = 1
  } else if (step.value === 3) {
    step.value = 2
  } else {
    emit('back')
  }
  error.value = ''
}

// ===== PCL CE：导入离线用户 =====
async function handleMigratePCLCE() {
  loading.value = true
  error.value = ''
  try {
    ceResult.value = await MigrateFromPCLCE()
    // 自动获取 PCL CE 的游戏目录
    try { pclMcDir.value = await GetPclCEMcDir() } catch {}
    step.value = 2
  } catch (e) {
    error.value = String(e).replace('Error: ', '')
  } finally {
    loading.value = false
  }
}

// ===== PCL：选择可执行文件并解析游戏目录 =====
async function handleSelectPclExe() {
  error.value = ''
  try {
    const p = await SelectPclExe()
    if (!p) return
    pclExePath.value = p
    pclMcDir.value = await GetPclMcDir(p)
  } catch (e) {
    pclMcDir.value = ''
    error.value = String(e).replace('Error: ', '')
  }
}

async function handleBrowseDir() {
  error.value = ''
  try {
    const p = await SelectMinecraftDir()
    if (p) pclMcDir.value = p
  } catch {}
}

// ===== 目录迁移 =====
async function handleMigrateDir(skip = false) {
  error.value = ''
  if (!skip && !pclMcDir.value.trim()) {
    error.value = t('migrate.selectDirFirst')
    return
  }
  loading.value = true
  try {
    if (!skip) {
      finalMcDir.value = await MigrateMinecraftDir(pclMcDir.value.trim(), dirMode.value)
    }
    if (source.value === 'pcl') {
      step.value = 3
    } else {
      step.value = 4
    }
  } catch (e) {
    error.value = String(e).replace('Error: ', '')
  } finally {
    loading.value = false
  }
}

// ===== PCL：手动设置账户模式 =====
function chooseAccount(mode) {
  accountMode.value = mode
  error.value = ''
}

async function handleCreateOffline() {
  const name = offlineName.value.trim()
  if (!name) {
    error.value = t('migrate.enterName')
    return
  }
  if (name.length < 2) {
    error.value = t('migrate.nameMinLength')
    return
  }
  loading.value = true
  error.value = ''
  try {
    const dir = await CreateOfflineUser(name, '')
    await SetCurrentUser(dir)
    // PCL 默认开启版本隔离
    await SetVersionIsolation(true)
    migratedUser.value = name
    step.value = 4
  } catch (e) {
    error.value = String(e).replace('Error: ', '')
  } finally {
    loading.value = false
  }
}

async function handlePremiumMigration() {
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

// 完成并直接登录
async function finishAndLogin(name, type) {
  if (type === 'premium') {
    try { await SetVersionIsolation(true) } catch {}
  }
  emit('login-success', {
    username: name,
    hasPassword: false,
    type,
    isLocked: false
  })
}

function finishToLogin() {
  // 迁移流程走完（区别于中途返回）
  emit('finished')
}
</script>

<template>
  <div class="migrate-page">
    <div class="migrate-glass">
      <!-- 步骤 0：选择来源 -->
      <template v-if="step === 0">
        <div class="mig-header">
          <div class="mig-icon">&#x21C4;</div>
          <div class="mig-title">{{ t('migrate.title') }}</div>
          <div class="mig-subtitle">{{ t('migrate.subtitle') }}</div>
        </div>
        <div class="source-row">
          <button class="source-card" @click="chooseSource('pclce')">
            <div class="source-name">PCL CE</div>
            <div class="source-desc">{{ t('migrate.ceSourceDesc') }}</div>
          </button>
          <button class="source-card" @click="chooseSource('pcl')">
            <div class="source-name">PCL</div>
            <div class="source-desc">{{ t('migrate.pclSourceDesc') }}</div>
          </button>
        </div>
      </template>

      <!-- 步骤 1：来源操作 -->
      <template v-else-if="step === 1 && source === 'pclce'">
        <div class="mig-title-small">{{ t('migrate.ceTitle') }}</div>
        <div class="mig-desc">{{ t('migrate.ceDesc') }}</div>
        <button class="mig-primary-btn" :disabled="loading" @click="handleMigratePCLCE">
          {{ loading ? t('migrate.migrating') : t('migrate.ceStart') }}
        </button>
      </template>

      <template v-else-if="step === 1 && source === 'pcl'">
        <div class="mig-title-small">{{ t('migrate.pclTitle') }}</div>
        <div class="mig-desc">{{ t('migrate.pclDesc') }}</div>
        <button class="mig-small-btn" @click="handleSelectPclExe">{{ t('migrate.selectPcl') }}</button>
        <div v-if="pclExePath" class="mig-path">{{ pclExePath }}</div>
        <div v-if="pclMcDir" class="mig-detected">
          <span class="mig-detected-label">{{ t('migrate.detectedDir') }}</span>
          <span class="mig-detected-value">{{ pclMcDir }}</span>
        </div>
        <button v-if="pclMcDir" class="mig-primary-btn" @click="step = 2">{{ t('migrate.next') }}</button>
      </template>

      <!-- 步骤 2：目录迁移 -->
      <template v-else-if="step === 2">
        <div v-if="source === 'pclce' && ceResult" class="mig-result">
          {{ t('migrate.ceResult', { n: ceResult.imported, m: ceResult.skipped }) }}
        </div>
        <div class="mig-title-small">{{ t('migrate.dirTitle') }}</div>
        <div class="dir-row">
          <button class="dir-card" :class="{ active: dirMode === 'full' }" @click="dirMode = 'full'">
            <div class="dir-name">{{ t('migrate.dirFull') }}</div>
            <div class="dir-desc">{{ t('migrate.dirFullDesc') }}</div>
          </button>
          <button class="dir-card" :class="{ active: dirMode === 'minimal' }" @click="dirMode = 'minimal'">
            <div class="dir-name">{{ t('migrate.dirMinimal') }}</div>
            <div class="dir-desc">{{ t('migrate.dirMinimalDesc') }}</div>
          </button>
        </div>
        <div v-if="dirMode === 'minimal'" class="mig-warn">{{ t('migrate.dirMinimalWarn') }}</div>
        <input
          v-model="pclMcDir"
          class="mig-input"
          :placeholder="t('migrate.dirPlaceholder')"
        />
        <button class="mig-small-btn" @click="handleBrowseDir">{{ t('migrate.browseDir') }}</button>
        <div class="mig-btn-row">
          <button class="mig-primary-btn" :disabled="loading" @click="handleMigrateDir(false)">
            {{ loading ? t('migrate.migrating') : t('migrate.dirApply') }}
          </button>
          <button class="mig-skip-btn" :disabled="loading" @click="handleMigrateDir(true)">{{ t('migrate.skip') }}</button>
        </div>
      </template>

      <!-- 步骤 3：PCL 账户设置 -->
      <template v-else-if="step === 3">
        <div class="mig-title-small">{{ t('migrate.accountTitle') }}</div>
        <div class="mig-desc">{{ t('migrate.accountDesc') }}</div>

        <!-- 微软登录流程 -->
        <template v-if="msLoginStep === 'device-code'">
          <div class="ms-box">
            <div class="ms-auto-hint">{{ t('login.autoOpenedBrowser') }}</div>
            <div class="ms-step-desc">{{ t('login.step1OpenUrl') }}</div>
            <div class="ms-url-box">{{ msVerifyURL }}</div>
            <div class="ms-step-desc">{{ t('login.step2EnterCode') }}</div>
            <div class="ms-code-box">{{ msDeviceCode }}</div>
            <div class="ms-progress">{{ msProgressMsg }}</div>
          </div>
        </template>
        <template v-else-if="msLoginStep === 'polling'">
          <div class="ms-box">
            <div class="ms-progress">{{ msProgressMsg }}</div>
            <div class="ms-waiting">{{ t('login.connectingMicrosoft') }}</div>
          </div>
        </template>
        <template v-else>
          <div class="account-row">
            <button class="account-card" :class="{ active: accountMode === 'offline' }" @click="chooseAccount('offline')">
              <div class="dir-name">{{ t('login.offline') }}</div>
            </button>
            <button class="account-card" @click="handlePremiumMigration">
              <div class="dir-name">{{ t('login.premium') }}</div>
            </button>
            <button class="account-card" @click="step = 4; accountMode = 'external'">
              <div class="dir-name">{{ t('login.external') }}</div>
            </button>
          </div>
          <div v-if="accountMode === 'offline'" class="offline-form">
            <input
              v-model="offlineName"
              class="mig-input"
              :placeholder="t('migrate.offlineName')"
              @keyup.enter="handleCreateOffline"
            />
            <button class="mig-primary-btn" :disabled="loading" @click="handleCreateOffline">
              {{ loading ? t('migrate.migrating') : t('migrate.createOffline') }}
            </button>
            <div class="mig-hint">{{ t('migrate.externalHint') }}</div>
          </div>
        </template>
      </template>

      <!-- 步骤 4：完成 -->
      <template v-else-if="step === 4">
        <div class="mig-header">
          <div class="mig-icon done">&#x2714;</div>
          <div class="mig-title">{{ t('migrate.done') }}</div>
          <div class="mig-subtitle">{{ t('migrate.doneDesc', { dir: finalMcDir || '-' }) }}</div>
          <div v-if="source === 'pcl' && accountMode === 'external'" class="mig-hint">{{ t('migrate.externalRegisterHint') }}</div>
        </div>
        <button class="mig-primary-btn" @click="finishToLogin">{{ t('migrate.backToLogin') }}</button>
      </template>

      <!-- 错误信息 -->
      <div v-if="error" class="mig-error">{{ error }}</div>

      <!-- 返回 -->
      <button v-if="showBack && step > 0 && !loading" class="mig-back-btn" @click="goBack">&#x2190; {{ t('migrate.back') }}</button>
    </div>
  </div>
</template>

<style scoped>
.migrate-page {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 2;
}

.migrate-glass {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
  min-width: 460px;
  max-width: 560px;
  max-height: 82vh;
  overflow-y: auto;
  padding: 32px 30px;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.88);
  border: 1px solid rgba(255, 255, 255, 0.4);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
}

.mig-header {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.mig-icon {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background: #E0F7FA;
  color: #0097A7;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 30px;
}

.mig-icon.done {
  background: #E8F5E9;
  color: #2E7D32;
}

.mig-title {
  font-size: 22px;
  font-weight: 600;
  color: #333333;
}

.mig-title-small {
  font-size: 17px;
  font-weight: 600;
  color: #333333;
}

.mig-subtitle {
  font-size: 13px;
  color: #777777;
  text-align: center;
  line-height: 1.6;
  word-break: break-all;
}

.mig-desc {
  font-size: 13px;
  color: #666666;
  text-align: center;
  line-height: 1.7;
  max-width: 420px;
}

.mig-result {
  background: #E8F5E9;
  color: #2E7D32;
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  text-align: center;
}

/* 来源选择卡片 */
.source-row {
  display: flex;
  gap: 14px;
  width: 100%;
}

.source-card {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 24px 16px;
  border: 2px solid #E0E0E0;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.7);
  cursor: pointer;
  transition: all 0.15s;
}

.source-card:hover {
  border-color: #00BCD4;
  background: rgba(0, 188, 212, 0.06);
}

.source-name {
  font-size: 18px;
  font-weight: 600;
  color: #333333;
}

.source-desc {
  font-size: 12px;
  color: #999999;
  text-align: center;
  line-height: 1.5;
}

/* 目录迁移卡片 */
.dir-row {
  display: flex;
  gap: 10px;
  width: 100%;
}

.dir-card {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 14px;
  border: 2px solid #E0E0E0;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.7);
  cursor: pointer;
  transition: all 0.15s;
  text-align: left;
}

.dir-card:hover { border-color: #B0BEC5; }
.dir-card.active { border-color: #00BCD4; background: rgba(0, 188, 212, 0.06); }

.dir-name {
  font-size: 14px;
  font-weight: 600;
  color: #333333;
}

.dir-desc {
  font-size: 11.5px;
  color: #888888;
  line-height: 1.5;
}

.mig-warn {
  background: #FFF8E1;
  color: #E65100;
  border: 1px solid #FFE0B2;
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.6;
  width: 100%;
}

/* 账户选择卡片 */
.account-row {
  display: flex;
  gap: 10px;
  width: 100%;
}

.account-card {
  flex: 1;
  padding: 12px;
  border: 2px solid #E0E0E0;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.7);
  cursor: pointer;
  transition: all 0.15s;
  text-align: center;
}

.account-card:hover { border-color: #B0BEC5; }
.account-card.active { border-color: #00BCD4; background: rgba(0, 188, 212, 0.06); }

.offline-form {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  width: 100%;
}

/* 输入框与按钮 */
.mig-input {
  width: 100%;
  padding: 10px 14px;
  border: 2px solid #E0E0E0;
  border-radius: 6px;
  font-size: 14px;
  outline: none;
  background: rgba(255, 255, 255, 0.8);
  color: #333333;
  transition: border-color 0.15s;
  box-sizing: border-box;
}

.mig-input:focus { border-color: #00BCD4; }
.mig-input::placeholder { color: #BBBBBB; }

.mig-primary-btn {
  width: 100%;
  padding: 11px 0;
  border: 2px solid #00BCD4;
  border-radius: 6px;
  background: #00BCD4;
  color: white;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
}

.mig-primary-btn:hover:not(:disabled) { background: #0097A7; border-color: #0097A7; }
.mig-primary-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.mig-small-btn {
  padding: 8px 18px;
  border: 1.5px solid #E0E0E0;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.8);
  color: #555555;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}

.mig-small-btn:hover { border-color: #00BCD4; color: #0097A7; }

.mig-skip-btn {
  padding: 11px 18px;
  border: 1.5px solid #E0E0E0;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.8);
  color: #777777;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}

.mig-skip-btn:hover { border-color: #B0BEC5; }

.mig-btn-row {
  display: flex;
  gap: 10px;
  width: 100%;
  align-items: stretch;
}

.mig-path {
  font-size: 12px;
  color: #0097A7;
  word-break: break-all;
  text-align: center;
  background: rgba(0, 188, 212, 0.06);
  padding: 6px 10px;
  border-radius: 6px;
  max-width: 100%;
}

.mig-detected {
  display: flex;
  flex-direction: column;
  gap: 4px;
  width: 100%;
  background: #E8F5E9;
  border: 1px solid #C8E6C9;
  border-radius: 8px;
  padding: 10px 14px;
}

.mig-detected-label {
  font-size: 11px;
  color: #2E7D32;
  font-weight: 600;
}

.mig-detected-value {
  font-size: 12.5px;
  color: #333333;
  word-break: break-all;
}

.mig-hint {
  font-size: 12px;
  color: #999999;
  text-align: center;
  line-height: 1.6;
}

/* 微软登录 */
.ms-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  width: 100%;
  background: rgba(255, 255, 255, 0.75);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 12px;
  padding: 16px;
}

.ms-auto-hint {
  background: #E8F5E9;
  color: #2E7D32;
  padding: 5px 14px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.ms-step-desc {
  font-size: 13px;
  color: #666666;
  align-self: flex-start;
}

.ms-url-box {
  background: #F5F5F5;
  border: 1px solid #E0E0E0;
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 13px;
  color: #0097A7;
  word-break: break-all;
  font-family: monospace;
  width: 100%;
  box-sizing: border-box;
}

.ms-code-box {
  background: #E0F7FA;
  border: 2px solid #00BCD4;
  border-radius: 4px;
  padding: 10px;
  font-size: 22px;
  font-weight: 700;
  color: #0097A7;
  letter-spacing: 4px;
  font-family: monospace;
  width: 100%;
  text-align: center;
  box-sizing: border-box;
}

.ms-progress {
  font-size: 13px;
  color: #00BCD4;
  font-weight: 500;
}

.ms-waiting {
  font-size: 12px;
  color: #999999;
}

/* 错误与返回 */
.mig-error {
  background: rgba(255, 235, 238, 0.9);
  color: #F44336;
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 13px;
  border: 1px solid #FFCDD2;
  text-align: center;
  width: 100%;
}

.mig-back-btn {
  padding: 6px 14px;
  border: none;
  background: transparent;
  color: #999999;
  font-size: 13px;
  cursor: pointer;
  transition: color 0.15s;
}

.mig-back-btn:hover { color: #333333; }
</style>
