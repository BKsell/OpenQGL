<script setup>
import { ref, onMounted, onUnmounted, computed, defineAsyncComponent, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import LoginPage from './components/LoginPage.vue'
// 主页是首屏，保持同步加载
import MainPage from './components/MainPage.vue'
// 其他页面懒加载，首次访问时才加载组件代码
const DownloadPage = defineAsyncComponent(() => import('./components/DownloadPage.vue'))
const SettingsPage = defineAsyncComponent(() => import('./components/SettingsPage.vue'))
const ModPage = defineAsyncComponent(() => import('./components/ModPage.vue'))
const LicensePage = defineAsyncComponent(() => import('./components/LicensePage.vue'))
const MigratePage = defineAsyncComponent(() => import('./components/MigratePage.vue'))
const OobePage = defineAsyncComponent(() => import('./components/oobe/OobePage.vue'))
// 用户向导在 out-in 过渡中紧跟登录页，必须同步加载：异步 chunk 会造成过渡空档期渲染异常
import UserWizard from './components/oobe/UserWizard.vue'
const EasyQGLPage = defineAsyncComponent(() => import('./components/EasyQGLPage.vue'))
const QGLPlusPage = defineAsyncComponent(() => import('./components/QGLPlusPage.vue'))
import QGLDialog from './components/QGLDialog.vue'
import CrashDialog from './components/CrashDialog.vue'
import {
  CheckFirstRun, GetCurrentUser, IsGuestLocked, UnlockGuest,
  GetDownloadList, GetDownloadListCount, RemoveFromDownloadList, StartDownloadList,
  GetThemeColor, SetThemeColor, GetBackgroundImageDataURL, GetHelperMode, GetOOBEDone, SetOOBEDone,
  GetUserOOBEDone
} from '../wailsjs/go/main/App.js'
import { EventsOn, BrowserOpenURL, Quit } from '../wailsjs/runtime/runtime.js'
import { useEasyQGL } from './stores/easyQGL.js'
import { setQGLDialogRef } from './composables/qglDialog.js'
import { setCrashDialogRef, showCrashDialog } from './composables/crashDialog.js'
import defaultBg from './assets/images/background.jpg'

const { t } = useI18n()

const currentPage = ref('login')
const currentUser = ref(null)
const isFirstRun = ref(false)

const { state: easyQGL } = useEasyQGL()

// 页面过渡动画方向: 'left'(进入) | 'right'(退出)
const transitionName = ref('page-left')

// 主题和背景（backgroundDataURL 存储实际可用的 data URL）
const themeColor = ref('cyan')
const backgroundImageURL = ref('')

// 下载列表相关
const downloadCount = ref(0)
const isDownloading = ref(false)
const showDownloadList = ref(false)
const downloadList = ref([])
const downloadListLoading = ref(false)

// 解锁相关
const unlockPassword = ref('')
const unlockError = ref('')
const unlockLoading = ref(false)
const showUnlockModal = ref(false)

// 辅助模式（绕过 PCL/HMCL 下载到外部 .minecraft）
const helperMode = ref({ active: false, dir: '' })
// 辅助下载设置流程（从主页辅助功能进入）
const helperSetupMode = ref(false)

async function refreshHelperMode() {
  try { helperMode.value = await GetHelperMode() || { active: false, dir: '' } }
  catch { helperMode.value = { active: false, dir: '' } }
}

function startHelperSetup() {
  helperSetupMode.value = true
  navigateTo('download')
}

function onHelperEntered() {
  helperSetupMode.value = false
  refreshHelperMode()
  navigateTo('main')
  showToast(t('app.helperModeEnabled'))
}

function onHelperExited() {
  helperSetupMode.value = false
  refreshHelperMode()
  showToast(t('app.helperModeDisabled'))
}

// QGL 弹窗
const qglDialog = ref(null)
// 崩溃弹窗
const crashDialog = ref(null)

// Toast 通知
const toastMessage = ref('')
const toastVisible = ref(false)
let toastTimer = null

const isGuestLocked = computed(() => {
  return currentUser.value?.type === 'guest' && currentUser.value?.isLocked
})

const showDownloadBtn = computed(() => {
  return currentPage.value !== 'login' && currentPage.value !== 'migrate' && currentPage.value !== 'oobe'
})

const showUnlockBtn = computed(() => {
  return !['login', 'migrate', 'oobe'].includes(currentPage.value) && isGuestLocked.value
})

// 背景图片样式 - 使用 data URL
const bgStyle = computed(() => {
  const bg = backgroundImageURL.value || defaultBg
  return {
    backgroundImage: `url(${bg})`,
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    backgroundRepeat: 'no-repeat'
  }
})

// 访客在设置页点击锁定后，刷新当前用户锁定状态
async function onGuestLocked() {
  try {
    const user = await GetCurrentUser()
    if (user) {
      try { user.isLocked = await IsGuestLocked() } catch { user.isLocked = false }
      currentUser.value = user
    }
  } catch {}
  showToast(t('main.guestLocked'))
}

function showToast(msg, duration = 3000) {
  toastMessage.value = msg
  toastVisible.value = true
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toastVisible.value = false
  }, duration)
}

function copyError(msg) {
  navigator.clipboard.writeText(msg).then(() => {
    showToast(t('app.errorCopied'), 2000)
  }).catch(() => {
    // fallback: 用 textarea 复制
    const ta = document.createElement('textarea')
    ta.value = msg
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    showToast(t('app.errorCopied'), 2000)
  })
}

async function loadThemeAndBg() {
  // 主题和背景并行加载
  const [themeResult, bgResult] = await Promise.allSettled([
    GetThemeColor(),
    GetBackgroundImageDataURL()
  ])
  if (themeResult.status === 'fulfilled' && themeResult.value) {
    themeColor.value = themeResult.value
    document.documentElement.setAttribute('data-theme', themeColor.value)
  }
  if (bgResult.status === 'fulfilled' && bgResult.value) {
    backgroundImageURL.value = bgResult.value
  }
}

onMounted(async () => {
  // 设置全局弹窗引用
  nextTick(() => {
    if (qglDialog.value) {
      setQGLDialogRef(qglDialog.value)
    }
    if (crashDialog.value) {
      setCrashDialogRef(crashDialog.value)
    }
  })

  // 注册事件监听（不阻塞启动）
  let pendingCrash = false
  EventsOn('launchStatus', (status) => {
    if (status === 'fixing') {
      showToast(t('app.fixing'), 5000)
    } else if (status === 'launching') {
      showToast(t('app.launching'), 5000)
    } else if (status === 'success') {
      showToast(t('app.launchSuccess'))
    } else if (status === 'timeout') {
      // 失败只简单提示，详细信息进崩溃弹窗
      showToast(t('app.launchFailed'), 5000)
      showCrashDialog({ title: t('crash.titleTimeout'), reason: t('app.launchTimeout') })
    } else if (status === 'crashed') {
      showToast(t('app.launchFailed'), 5000)
      pendingCrash = true
    }
  })

  EventsOn('crashInfo', (info) => {
    if (info && pendingCrash) {
      pendingCrash = false
      showCrashDialog({ title: t('crash.titleCrashed'), reason: info })
    }
  })

  EventsOn('downloadListUpdated', (items) => {
    downloadList.value = items || []
    downloadCount.value = items ? items.length : 0
    // 从列表状态自愈 isDownloading：只要还有"下载中"的项就视为下载中，
    // 即使 downloadListCompleted 事件丢失也不会让按钮永久卡死
    if (Array.isArray(items)) {
      const anyDownloading = items.some(i => i.status === 'downloading')
      if (anyDownloading) {
        isDownloading.value = true
      } else if (isDownloading.value && items.every(i => i.status !== 'pending')) {
        isDownloading.value = false
      }
    }
  })

  EventsOn('downloadProgress', () => {
    // 列表与计数已由 downloadListUpdated 事件全量携带，这里不再重复调用后端
    // （原实现每个下载分片都触发 GetDownloadListCount + GetDownloadList 两次后端调用，高频下载时会卡 UI）
  })

  EventsOn('themeChanged', (color) => {
    themeColor.value = color || 'cyan'
    document.documentElement.setAttribute('data-theme', themeColor.value)
  })

  EventsOn('backgroundChanged', async () => {
    try {
      const url = await GetBackgroundImageDataURL()
      backgroundImageURL.value = url || ''
    } catch {}
  })

  EventsOn('downloadListCompleted', () => {
    isDownloading.value = false
  })

  // 并行加载：主题+背景 与 用户检查 同时进行
  const [, userCheckResult] = await Promise.allSettled([
    loadThemeAndBg(),
    (async () => {
      // OOBE 首次设置向导：总配置 oobe != true 时进入
      let oobeDone = false
      try { oobeDone = await GetOOBEDone() } catch { oobeDone = false }
      if (!oobeDone) {
        currentPage.value = 'oobe'
        return
      }
      const firstRun = await CheckFirstRun()
      isFirstRun.value = firstRun
      if (firstRun) {
        currentPage.value = 'login'
        return
      }
      const user = await GetCurrentUser()
      if (user && user.username) {
        if (user.type === 'guest') {
          try { user.isLocked = await IsGuestLocked() } catch { user.isLocked = false }
          currentUser.value = user
          currentPage.value = 'main'
        } else {
          user.isLocked = false
          if (user.hasPassword) {
            currentPage.value = 'login'
          } else if (user.type === 'premium' || user.type === 'external') {
            // 正版/外置用户自动登录：走 LoginUser 刷新令牌，检测是否过期
            try {
              const { LoginUser } = await import('../wailsjs/go/main/App.js')
              await LoginUser(user.dir || user.username, '')
              currentUser.value = user
              currentPage.value = 'main'
            } catch {
              // 令牌过期，进入登录页（登录页会弹窗引导重新登录）
              currentPage.value = 'login'
            }
          } else {
            currentUser.value = user
            currentPage.value = 'main'
          }
        }
      } else {
        currentPage.value = 'login'
      }
    })()
  ])

  // 延迟加载下载计数（非关键，不阻塞首屏）
  refreshDownloadCount()
})

onUnmounted(() => {
  if (toastTimer) clearTimeout(toastTimer)
})

async function refreshDownloadCount() {
  try { downloadCount.value = await GetDownloadListCount() } catch { downloadCount.value = 0 }
}

async function refreshDownloadList() {
  if (!showDownloadList.value) return
  try { downloadList.value = await GetDownloadList() || [] } catch {}
}

function onLoginSuccess(user) {
  currentUser.value = user
  transitionName.value = 'page-fade'
  refreshDownloadCount()
  loadThemeAndBg()
  refreshHelperMode()
  // 新用户（用户 config 的 oobe != true）先进入用户向导
  checkUserWizard()
}

// 检查当前用户是否需要用户向导（主题色/背景等个性化设置）
async function checkUserWizard() {
  let wizardDone = true
  try { wizardDone = await GetUserOOBEDone() } catch { wizardDone = true }
  if (!wizardDone) {
    currentPage.value = 'userwizard'
  } else {
    currentPage.value = 'main'
  }
}

function onUserWizardDone() {
  transitionName.value = 'page-right'
  currentPage.value = 'main'
}

function navigateTo(page) {
  // 根据目标页面决定过渡方向
  if (page === 'main' || page === 'login') {
    transitionName.value = 'page-right'
  } else {
    transitionName.value = 'page-left'
  }

  currentPage.value = page
}

function onLogout() {
  transitionName.value = 'page-right'
  currentUser.value = null
  currentPage.value = 'login'
}

function goToAddUser() {
  transitionName.value = 'page-right'
  currentUser.value = null
  currentPage.value = 'login'
}

function showLicensePage() {
  transitionName.value = 'page-left'
  currentPage.value = 'license'
}

function showMigratePage() {
  transitionName.value = 'page-left'
  currentPage.value = 'migrate'
}

function backFromMigrate() {
  transitionName.value = 'page-right'
  currentPage.value = 'login'
}

// OOBE 完成：进入登录页或主页
function onOobeFinished() {
  transitionName.value = 'page-fade'
  if (currentUser.value?.username) {
    currentPage.value = 'main'
  } else {
    currentPage.value = 'login'
  }
}

// OOBE 迁移中直接登录成功：先标记完成，再正常登录流程
async function onOobeLoginSuccess(user) {
  try { await SetOOBEDone() } catch {}
  onLoginSuccess(user)
}

function closeLicensePage() {
  transitionName.value = 'page-right'
  currentPage.value = 'settings'
}

async function openDownloadList() {
  if (isGuestLocked.value) return
  showDownloadList.value = true
  downloadListLoading.value = true
  try { downloadList.value = await GetDownloadList() || [] } catch { downloadList.value = [] }
  finally { downloadListLoading.value = false }
}

async function removeDownloadItem(item) {
  try {
    await RemoveFromDownloadList(item.customName)
    downloadList.value = await GetDownloadList() || []
    downloadCount.value = await GetDownloadListCount()
  } catch {}
}

async function startDownload() {
  // 任何时刻都可以点击：后端正在下载中时会静默忽略（循环继续处理剩余待下载项），
  // 只下载 pending 项，失败/已完成/下载中的不会重复下载
  try { await StartDownloadList(); isDownloading.value = true; showToast(t('app.downloadStarted')) }
  catch (e) { showToast(t('app.downloadFailed') + String(e).replace('Error: ', '')) }
}

function openUnlockModal() {
  unlockPassword.value = ''
  unlockError.value = ''
  showUnlockModal.value = true
}

async function handleUnlock() {
  if (!unlockPassword.value.trim()) { unlockError.value = t('app.enterSecurityPasswordError'); return }
  unlockLoading.value = true
  unlockError.value = ''
  try {
    await UnlockGuest(unlockPassword.value.trim())
    currentUser.value.isLocked = false
    showUnlockModal.value = false
    showToast(t('app.unlocked'))
  } catch (e) { unlockError.value = String(e).replace('Error: ', '') }
  finally { unlockLoading.value = false }
}
</script>

<template>
  <div class="app-container" :data-theme="themeColor">
    <!-- 背景图片层 -->
    <div class="bg-layer" :style="bgStyle"></div>
    <!-- 半透明遮罩层 -->
    <div class="bg-overlay"></div>

    <!-- 页面内容 + 过渡动画 -->
    <Transition :name="transitionName" mode="out-in">
      <LoginPage
        v-if="currentPage === 'login'"
        key="login"
        :isFirstRun="isFirstRun"
        @login-success="onLoginSuccess"
        @navigate-migrate="showMigratePage"
      />
      <MigratePage
        v-else-if="currentPage === 'migrate'"
        key="migrate"
        :currentUser="currentUser"
        @back="backFromMigrate"
        @finished="backFromMigrate"
        @login-success="onLoginSuccess"
      />
      <OobePage
        v-else-if="currentPage === 'oobe'"
        key="oobe"
        @finished="onOobeFinished"
        @login-success="onOobeLoginSuccess"
      />
      <UserWizard
        v-else-if="currentPage === 'userwizard'"
        key="userwizard"
        @done="onUserWizardDone"
      />
      <MainPage
        v-else-if="currentPage === 'main'"
        key="main"
        :currentUser="currentUser"
        :helperMode="helperMode"
        @navigate="navigateTo"
        @logout="onLogout"
        @add-user="goToAddUser"
        @start-helper-setup="startHelperSetup"
        @helper-exited="onHelperExited"
      />
      <DownloadPage
        v-else-if="currentPage === 'download'"
        key="download"
        :currentUser="currentUser"
        :helperMode="helperMode"
        :helperSetup="helperSetupMode"
        @navigate="navigateTo"
        @helper-entered="onHelperEntered"
      />
      <SettingsPage
        v-else-if="currentPage === 'settings'"
        key="settings"
        :currentUser="currentUser"
        @navigate="navigateTo"
        @logout="onLogout"
        @show-license="showLicensePage"
        @user-locked="onGuestLocked"
      />
      <ModPage
        v-else-if="currentPage === 'mod'"
        key="mod"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
      <LicensePage
        v-else-if="currentPage === 'license'"
        key="license"
        :currentUser="currentUser"
        @back="closeLicensePage"
      />
      <EasyQGLPage
        v-else-if="currentPage === 'easyqgl'"
        key="easyqgl"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
      <QGLPlusPage
        v-else-if="currentPage === 'qglplus'"
        key="qglplus"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
    </Transition>

    <!-- 全局下载列表按钮 -->
    <button v-if="showDownloadBtn" class="global-download-btn" :class="{ 'easy-orange-btn': easyQGL.active, 'helper-purple-btn': helperMode.active }" :disabled="isGuestLocked" :title="helperMode.active ? t('app.helperModeDownloadTitle') : (isGuestLocked ? t('app.guestLockedDownload') : t('app.downloadListTitle'))" @click="openDownloadList">
      <span class="download-icon">&#x2B07;</span>
      <span v-if="downloadCount > 0" class="download-badge">{{ downloadCount }}</span>
    </button>

    <!-- 全局解锁按钮 -->
    <button v-if="showUnlockBtn" class="global-unlock-btn" :title="t('app.unlockGuest')" @click="openUnlockModal">&#x1F512;</button>

    <!-- Toast 通知 -->
    <Transition name="toast">
      <div v-if="toastVisible" class="toast-notification">{{ toastMessage }}</div>
    </Transition>

    <!-- 下载列表弹窗 -->
    <div v-if="showDownloadList" class="modal-overlay" @click.self="showDownloadList = false">
      <div class="modal-content fade-in" :class="{ 'easy-orange': easyQGL.active, 'helper-purple': helperMode.active }" style="min-width: 420px;">
        <div class="modal-title">
          {{ t('app.downloadList') }}
          <span v-if="easyQGL.active" class="easy-badge">Easy QGL</span>
          <span v-if="helperMode.active" class="helper-mode-badge">{{ t('app.helperModeBadge') }}</span>
        </div>
        <div v-if="downloadListLoading" class="loading-hint">{{ t('app.loading') }}</div>
        <div v-else-if="downloadList.length === 0" class="empty-hint">{{ t('app.downloadListEmpty') }}</div>
        <div v-else class="dl-list">
          <div v-for="(item, index) in downloadList" :key="index" class="dl-item">
            <div class="dl-item-info">
              <div class="dl-item-name">{{ item.customName || item.id }}</div>
              <div class="dl-item-status">
                <span v-if="item.status === 'pending'" class="status-pending">{{ t('app.statusPending') }}</span>
                <span v-else-if="item.status === 'downloading'" class="status-downloading">{{ t('app.statusDownloading') }}</span>
                <span v-else-if="item.status === 'completed'" class="status-completed">{{ t('app.statusCompleted') }}</span>
                <span v-else-if="item.status === 'failed'" class="status-failed">{{ t('app.statusFailed') }}</span>
              </div>
              <div v-if="item.status === 'failed' && item.errorMsg" class="dl-error" :title="t('app.clickToCopyError')" @click="copyError(item.errorMsg)">{{ item.errorMsg }}</div>
              <div v-if="item.status === 'downloading'" class="dl-progress">
                <div class="progress-bar"><div class="progress-bar-fill" :style="{ width: (item.progress || 0) + '%' }"></div></div>
                <span class="dl-progress-text">{{ (item.progress || 0).toFixed(1) }}%</span>
              </div>
              <!-- 当前步骤小标题：进度条长时间不动时让用户知道实际在下载什么 -->
              <div v-if="item.status === 'downloading' && item.currentStep" class="dl-step">{{ item.currentStep }}</div>
            </div>
            <div class="dl-item-actions">
              <button v-if="item.status !== 'downloading'" class="btn-icon-sm" :title="t('app.remove')" @click="removeDownloadItem(item)">&#x2716;</button>
            </div>
          </div>
        </div>
        <div class="dl-footer">
          <button
            class="btn"
            :class="easyQGL.active ? 'btn-easy-orange' : 'btn-primary'"
            :disabled="downloadList.length === 0"
            @click="startDownload"
          >{{ isDownloading ? t('app.downloading') : t('app.startDownload') }}</button>
          <button class="btn btn-outline" @click="showDownloadList = false">{{ t('app.close') }}</button>
        </div>
      </div>
    </div>

    <!-- 解锁弹窗 -->
    <div v-if="showUnlockModal" class="modal-overlay" @click.self="showUnlockModal = false">
      <div class="modal-content fade-in" style="min-width: 360px;">
        <div class="modal-title">{{ t('app.unlockGuest') }}</div>
        <div v-if="unlockError" class="error-msg">{{ unlockError }}</div>
        <div class="form-group">
          <label>{{ t('app.securityPassword') }}</label>
          <input v-model="unlockPassword" type="password" class="input" :placeholder="t('app.enterSecurityPassword')" @keyup.enter="handleUnlock"/>
        </div>
        <div class="dl-footer">
          <button class="btn btn-primary" :disabled="unlockLoading" @click="handleUnlock">{{ unlockLoading ? t('app.unlocking') : t('app.unlock') }}</button>
          <button class="btn btn-outline" @click="showUnlockModal = false">{{ t('app.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- QGL 自定义弹窗 -->
    <QGLDialog ref="qglDialog" />
    <CrashDialog ref="crashDialog" />
  </div>
</template>

<style scoped>
.app-container {
  width: 100vw;
  height: 100vh;
  overflow: hidden;
  position: relative;
}

/* ====== 页面过渡动画 ====== */
.page-left-enter-active,
.page-right-enter-active,
.page-fade-enter-active {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
.page-left-leave-active,
.page-right-leave-active,
.page-fade-leave-active {
  transition: all 0.25s cubic-bezier(0.4, 0, 1, 1);
}

/* 从右侧滑入（前进：主页→设置/下载/MOD） */
.page-left-enter-from {
  opacity: 0;
  transform: translateX(40px);
}
.page-left-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}

/* 向右滑出（后退：设置/下载→主页） */
.page-right-enter-from {
  opacity: 0;
  transform: translateX(-40px);
}
.page-right-leave-to {
  opacity: 0;
  transform: translateX(20px);
}

/* 淡入淡出（登录↔主页） */
.page-fade-enter-from,
.page-fade-leave-to {
  opacity: 0;
  transform: scale(0.97);
}

/* ====== 背景层 ====== */
.bg-layer {
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  z-index: 0;
}

.bg-overlay {
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  z-index: 1;
  background: rgba(255, 255, 255, 0.15);
  pointer-events: none;
}

/* ====== 全局按钮 ====== */
.global-download-btn {
  position: fixed;
  bottom: 24px; right: 24px;
  width: 48px; height: 48px;
  background: var(--glass-bg-heavy);
  color: var(--primary);
  border: 1px solid var(--glass-border);
  border-radius: 50%;
  font-size: 20px;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  transition: all 0.2s;
  z-index: 100;
}
.global-download-btn:hover:not(:disabled) { background: var(--primary); color: white; transform: scale(1.05); }
.global-download-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.download-icon { font-size: 20px; line-height: 1; }
.download-badge {
  position: absolute; top: -4px; right: -4px;
  min-width: 18px; height: 18px;
  background: var(--danger); color: white;
  border-radius: 9px;
  font-size: 11px; font-weight: 600;
  display: flex; align-items: center; justify-content: center;
  padding: 0 4px;
}

.global-unlock-btn {
  position: fixed;
  bottom: 24px; right: 82px;
  width: 48px; height: 48px;
  background: var(--glass-bg-heavy);
  color: var(--warning);
  border: 1px solid var(--glass-border);
  border-radius: 50%;
  font-size: 20px;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  transition: all 0.2s;
  z-index: 100;
}
.global-unlock-btn:hover { background: var(--warning); color: white; transform: scale(1.05); }

/* Toast */
.toast-notification {
  position: fixed;
  top: 24px; left: 50%; transform: translateX(-50%);
  background: var(--glass-bg-heavy);
  color: var(--text);
  padding: 10px 24px; border-radius: 8px;
  font-size: 14px; font-weight: 500;
  z-index: 2000;
  box-shadow: 0 4px 16px rgba(0,0,0,0.15);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--glass-border);
  pointer-events: none;
}
.toast-enter-active { transition: all 0.3s ease; }
.toast-leave-active { transition: all 0.3s ease; }
.toast-enter-from { opacity: 0; transform: translateX(-50%) translateY(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-50%) translateY(-20px); }

/* 下载列表 */
.dl-list { max-height: 300px; overflow-y: auto; }
.dl-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 12px; border-radius: 8px; transition: background 0.15s;
}
.dl-item:hover { background: var(--primary-bg); }
.dl-item-info { flex: 1; min-width: 0; }
.dl-item-name { font-size: 14px; font-weight: 500; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dl-item-status { font-size: 12px; color: var(--text-light); margin-top: 2px; }
.status-pending { color: var(--text-light); }
.status-downloading { color: var(--primary); font-weight: 500; }
.status-completed { color: var(--success); font-weight: 500; }
.status-failed { color: var(--danger); font-weight: 500; }
.dl-progress { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.dl-progress .progress-bar { flex: 1; height: 4px; background: var(--bg-card); border-radius: 2px; overflow: hidden; }
.dl-progress .progress-bar-fill { height: 100%; background: var(--primary); border-radius: 2px; transition: width 0.3s; }
.dl-progress-text { font-size: 11px; color: var(--primary-dark); font-weight: 600; min-width: 40px; text-align: right; }
.dl-step {
  font-size: 12px;
  color: var(--text-light);
  margin-top: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dl-item-actions { display: flex; gap: 4px; margin-left: 12px; flex-shrink: 0; }
.btn-icon-sm {
  width: 28px; height: 28px; border: none; background: transparent;
  color: var(--text-light); border-radius: 50%; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; transition: all 0.15s;
}
.btn-icon-sm:hover { background: #FFEBEE; color: var(--danger); }
.dl-footer { display: flex; gap: 10px; margin-top: 16px; justify-content: flex-end; }
.loading-hint { text-align: center; color: var(--text-light); padding: 20px; font-size: 14px; }
.empty-hint { text-align: center; color: var(--text-light); padding: 20px; font-size: 14px; }
.error-msg { background: #FFF3F0; color: var(--danger); padding: 8px 12px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; border: 1px solid #FFCDD2; }
.dl-error {
  color: var(--danger);
  font-size: 12px;
  margin-top: 4px;
  padding: 6px 8px;
  background: rgba(255, 235, 238, 0.6);
  border-radius: 4px;
  border: 1px solid rgba(244, 67, 54, 0.15);
  word-break: break-all;
  line-height: 1.5;
  cursor: pointer;
  user-select: text;
  transition: background 0.15s;
}
.dl-error:hover { background: rgba(255, 235, 238, 0.95); }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-secondary); margin-bottom: 6px; }

/* Easy QGL 橙色主题 */
.easy-orange {
  border-color: rgba(255, 152, 0, 0.3) !important;
}

.easy-badge {
  display: inline-block;
  margin-left: 8px;
  padding: 2px 8px;
  background: #FF9800;
  color: white;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  vertical-align: middle;
}

.btn-easy-orange {
  background: #FF9800;
  border-color: #FF9800;
  color: white;
  padding: 8px 20px;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-easy-orange:hover:not(:disabled) {
  background: #F57C00;
}

.btn-easy-orange:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.easy-orange-btn {
  color: #FF9800 !important;
  border-color: rgba(255, 152, 0, 0.4) !important;
}

.easy-orange-btn:hover:not(:disabled) {
  background: #FF9800 !important;
  color: white !important;
}

.easy-orange .dl-progress .progress-bar-fill {
  background: #FF9800;
}

.easy-orange .dl-progress-text {
  color: #E65100;
}

/* 辅助模式紫色主题 */
.helper-purple {
  border-color: rgba(156, 39, 176, 0.3) !important;
}

.helper-mode-badge {
  display: inline-block;
  margin-left: 8px;
  padding: 2px 8px;
  background: #9C27B0;
  color: white;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  vertical-align: middle;
}

.helper-purple-btn {
  color: #9C27B0 !important;
  border-color: rgba(156, 39, 176, 0.4) !important;
}

.helper-purple-btn:hover:not(:disabled) {
  background: #9C27B0 !important;
  color: white !important;
}

.helper-purple .dl-progress .progress-bar-fill {
  background: #9C27B0;
}

.helper-purple .dl-progress-text {
  color: #7B1FA2;
}
</style>
