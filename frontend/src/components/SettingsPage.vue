<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import i18n from '../i18n/index.js'
import {
  GetGlobalConfig, SaveGlobalConfig, IsVersionIsolation,
  SetVersionIsolation, GetCurrentUser, GetUsers, LockGuest,
  SearchJava, GetJavaInfo, GetMinecraftDir,
  GetThemeColor, SetThemeColor, GetBackgroundImageDataURL, SetBackgroundImage, SelectBackgroundImage,
  GetBingDailyImage, GetCachedBingImage, GetLauncherVersion,
  IsPortableMode, SetPortableMode, GetPortableJavaPath, GetPortableJavaInfo,
  GetShowExportLaunchCommand, SetShowExportLaunchCommand,
  SetUserPassword, DeleteCurrentUser, GetGuestPermissions, SetGuestPermissions,
} from '../../wailsjs/go/main/App.js'
import { showQGLDialog } from '../composables/qglDialog.js'
import { useAvatars } from '../composables/avatar.js'
import logoImg from '../assets/images/logo.jpg'

const props = defineProps({
  currentUser: Object
})

const emit = defineEmits(['navigate', 'logout', 'show-license', 'user-locked'])

const { t } = useI18n()

const activeSection = ref('general')

const javaPath = ref('')
const javaInfo = ref(null)
const javaList = ref([])
const searchingJava = ref(false)
const maxMemory = ref(2)
const minMemory = ref(1)
const versionIsolation = ref(false)
const minecraftDir = ref('')
const saving = ref(false)
const saveMsg = ref('')
const users = ref([])
const themeColor = ref('cyan')
const backgroundImage = ref('')
const bingLoading = ref(false)
const launcherVersion = ref('')

// 真实头像（皮肤脸）
const { avatarMap, loadAvatar } = useAvatars()
watch(() => props.currentUser, (u) => { if (u) loadAvatar(u) }, { immediate: true })
watch(users, (list) => { (list || []).forEach(u => loadAvatar(u)) })

const sections = computed(() => [
  { id: 'general', label: t('settings.general'), icon: '&#x2699;' },
  { id: 'personalize', label: t('settings.personalize'), icon: '&#x1F3A8;' },
  { id: 'other', label: t('settings.other'), icon: '&#x1F4E6;' },
  { id: 'user', label: t('settings.user'), icon: '&#x1F464;' },
  { id: 'about', label: t('settings.about'), icon: '&#x2139;' },
])

// 便携版相关
const portableMode = ref(false)
const portableJavaPath = ref('')
const portableJavaInfo = ref(null)

// 语言切换
const currentLocale = ref(localStorage.getItem('qgl-locale') || 'zh-CN')
const languageOptions = [
  { value: 'zh-CN', label: '简体中文' },
  { value: 'zh-TW', label: '繁體中文' },
  { value: 'en-US', label: 'English' },
]

function changeLanguage(locale) {
  currentLocale.value = locale
  i18n.global.locale.value = locale
  localStorage.setItem('qgl-locale', locale)
}

// 导出启动命令按钮
const showExportLaunchCommand = ref(false)

async function toggleExportLaunchCommand() {
  try {
    await SetShowExportLaunchCommand(showExportLaunchCommand.value)
  } catch {
    showExportLaunchCommand.value = !showExportLaunchCommand.value
  }
}

onMounted(async () => {
  // 并行加载配置数据
  const [configResult, isolationResult, usersResult, themeResult, bgResult] = await Promise.allSettled([
    GetGlobalConfig(),
    IsVersionIsolation(),
    GetUsers(),
    GetThemeColor(),
    GetBackgroundImageDataURL()
  ])

  if (configResult.status === 'fulfilled' && configResult.value) {
    const config = configResult.value
    javaPath.value = config.javaPath || ''
    maxMemory.value = config.maxMemory || 2
    minMemory.value = config.minMemory || 1
    minecraftDir.value = config.minecraftDir || ''
  }

  if (isolationResult.status === 'fulfilled') {
    versionIsolation.value = isolationResult.value
  }

  if (usersResult.status === 'fulfilled' && usersResult.value) {
    users.value = usersResult.value
  }

  if (themeResult.status === 'fulfilled') {
    themeColor.value = themeResult.value
  }

  if (bgResult.status === 'fulfilled' && bgResult.value) {
    backgroundImage.value = bgResult.value
  }

  // 加载便携版设置
  try { portableMode.value = await IsPortableMode() } catch {}
  try { portableJavaPath.value = await GetPortableJavaPath() } catch {}
  try {
    const info = await GetPortableJavaInfo()
    portableJavaInfo.value = info
  } catch {}

  // 加载导出启动命令按钮设置
  try { showExportLaunchCommand.value = await GetShowExportLaunchCommand() } catch {}

  // 加载访客权限
  loadGuestPerms()

  // 加载启动器版本
  try { launcherVersion.value = await GetLauncherVersion() } catch {}

  // 延迟搜索 Java（最慢的操作，不阻塞页面显示）
  searchJavaList()

  // 检查当前设置的 Java 信息
  if (javaPath.value) {
    try {
      javaInfo.value = await GetJavaInfo(javaPath.value)
    } catch {}
  }
})

async function searchJavaList() {
  searchingJava.value = true
  try {
    javaList.value = await SearchJava() || []
  } catch {
    javaList.value = []
  } finally {
    searchingJava.value = false
  }
}

async function togglePortableMode() {
  try {
    await SetPortableMode(portableMode.value)
    // 刷新便携版 Java 信息
    try {
      const info = await GetPortableJavaInfo()
      portableJavaInfo.value = info
    } catch {
      portableJavaInfo.value = null
    }
  } catch (e) {
    portableMode.value = !portableMode.value // 恢复开关状态
  }
}

function selectJava(path) {
  javaPath.value = path
  // 更新 Java 信息
  const found = javaList.value.find(j => j.path === path)
  if (found) {
    javaInfo.value = found
  }
}

function clearJavaPath() {
  javaPath.value = ''
  javaInfo.value = null
}

function clearMinecraftDir() {
  minecraftDir.value = ''
}

async function resetMinecraftDir() {
  try {
    minecraftDir.value = await GetMinecraftDir()
  } catch {}
}

async function saveSettings() {
  saving.value = true
  saveMsg.value = ''
  try {
    const config = await GetGlobalConfig()
    config.javaPath = javaPath.value
    config.maxMemory = maxMemory.value
    config.minMemory = minMemory.value
    config.minecraftDir = minecraftDir.value
    await SaveGlobalConfig(config)
    await SetVersionIsolation(versionIsolation.value)
    saveMsg.value = t('settings.settingsSaved')
    setTimeout(() => { saveMsg.value = '' }, 2000)
  } catch (e) {
    saveMsg.value = t('settings.saveFailed') + String(e).replace('Error: ', '')
  } finally {
    saving.value = false
  }
}

const themeColors = [
  { id: 'blue', label: t('settings.blue'), color: '#2196F3' },
  { id: 'cyan', label: t('settings.cyan'), color: '#00BCD4' },
  { id: 'pink', label: t('settings.pink'), color: '#E91E63' },
  { id: 'purple', label: t('settings.purple'), color: '#9C27B0' },
  { id: 'orange', label: t('settings.orange'), color: '#FF9800' },
  { id: 'yellow', label: t('settings.yellow'), color: '#FDD835' },
  { id: 'green', label: t('settings.green'), color: '#4CAF50' },
]

async function changeThemeColor(color) {
  themeColor.value = color
  try { await SetThemeColor(color) } catch {}
  // Update parent data-theme attribute
  document.querySelector('[data-theme]')?.setAttribute('data-theme', color)
}

async function selectBgImage() {
  try {
    const path = await SelectBackgroundImage()
    if (path) {
      backgroundImage.value = path
      // 保存路径到用户配置，同时获取 data URL 用于显示
      await SetBackgroundImage(path)
      // 重新获取 data URL（后端会读取文件并返回 base64）
      const url = await GetBackgroundImageDataURL()
      if (url) backgroundImage.value = url
    }
  } catch {}
}

async function resetBgImage() {
  backgroundImage.value = ''
  try { await SetBackgroundImage('') } catch {}
}

async function fetchBingDailyImage() {
  bingLoading.value = true
  try {
    const url = await GetBingDailyImage()
    if (url) {
      backgroundImage.value = url
    }
  } catch (e) {
  } finally {
    bingLoading.value = false
  }
}

function handleLogout() {
  emit('logout')
}

// ===== 用户管理 =====
const pwdForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' })
const pwdSaving = ref(false)
const deletePassword = ref('')
const userManageMsg = ref('')

function setUserMsg(msg) {
  userManageMsg.value = msg
  setTimeout(() => { userManageMsg.value = '' }, 3000)
}

async function saveUserPassword() {
  if (props.currentUser?.hasPassword && !pwdForm.value.oldPassword) {
    setUserMsg(t('settings.needOldPassword'))
    return
  }
  if (!pwdForm.value.newPassword) {
    setUserMsg(t('settings.enterNewPassword'))
    return
  }
  if (pwdForm.value.newPassword !== pwdForm.value.confirmPassword) {
    setUserMsg(t('settings.passwordMismatch'))
    return
  }
  pwdSaving.value = true
  try {
    await SetUserPassword(pwdForm.value.oldPassword, pwdForm.value.newPassword)
    pwdForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' }
    // 密码已变更，回到切换用户界面重新进入
    emit('logout')
  } catch (e) {
    setUserMsg(String(e).replace('Error: ', ''))
  } finally {
    pwdSaving.value = false
  }
}

async function clearUserPassword() {
  if (!pwdForm.value.oldPassword) {
    setUserMsg(t('settings.needOldPasswordRemove'))
    return
  }
  pwdSaving.value = true
  try {
    await SetUserPassword(pwdForm.value.oldPassword, '')
    pwdForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' }
    // 密码已清除，回到切换用户界面重新进入
    emit('logout')
  } catch (e) {
    setUserMsg(String(e).replace('Error: ', ''))
  } finally {
    pwdSaving.value = false
  }
}

async function confirmDeleteAccount() {
  if (props.currentUser?.hasPassword && !deletePassword.value) {
    setUserMsg(t('settings.enterAccountPassword'))
    return
  }
  const btnIndex = await showQGLDialog({
    title: t('settings.deleteConfirmTitle'),
    content: t('settings.deleteConfirmContent').replace('{name}', props.currentUser?.username || ''),
    btn1Label: t('settings.deleteConfirmYes'),
    btn2Label: t('settings.deleteConfirmNo'),
  })
  if (btnIndex !== 1) return
  try {
    await DeleteCurrentUser(deletePassword.value)
    emit('logout') // 删除成功，回到登录页
  } catch (e) {
    setUserMsg(String(e).replace('Error: ', ''))
  }
}

// ===== 访客权限管理 =====
const guestPerms = ref({
  allowDownload: true, allowMod: true, allowEasyQGL: true, allowSettings: true, allowQGLPlus: true, allowHelper: true,
})
const guestPermItems = computed(() => [
  { key: 'allowDownload', label: t('settings.permDownload'), desc: t('settings.permDownloadDesc'), value: guestPerms.value.allowDownload },
  { key: 'allowMod', label: t('settings.permMod'), desc: t('settings.permModDesc'), value: guestPerms.value.allowMod },
  { key: 'allowEasyQGL', label: t('settings.permEasyQGL'), desc: t('settings.permEasyQGLDesc'), value: guestPerms.value.allowEasyQGL },
  { key: 'allowSettings', label: t('settings.permSettings'), desc: t('settings.permSettingsDesc'), value: guestPerms.value.allowSettings },
  { key: 'allowQGLPlus', label: t('settings.permQGLPlus'), desc: t('settings.permQGLPlusDesc'), value: guestPerms.value.allowQGLPlus },
  { key: 'allowHelper', label: t('settings.permHelper'), desc: t('settings.permHelperDesc'), value: guestPerms.value.allowHelper },
])

// 锁定访客（解锁后点击可重新锁定）
async function lockGuestUser() {
  try {
    await LockGuest()
    emit('user-locked')
  } catch (e) {
    setUserMsg(String(e).replace('Error: ', ''))
  }
}

async function loadGuestPerms() {
  if (props.currentUser?.type !== 'guest') return
  try {
    const perms = await GetGuestPermissions()
    if (perms) guestPerms.value = perms
  } catch {}
}

async function toggleGuestPerm(key) {
  const old = guestPerms.value[key]
  guestPerms.value[key] = !old
  try {
    await SetGuestPermissions(guestPerms.value)
  } catch {
    guestPerms.value[key] = old
  }
}

const currentUserType = computed(() => {
  if (props.currentUser?.type === 'guest') return t('main.guestMode')
  if (props.currentUser?.type === 'premium') return t('main.premiumMode')
  if (props.currentUser?.type === 'external') return t('main.externalMode')
  return t('main.offlineMode')
})

const javaVersionLabel = computed(() => {
  if (!javaInfo.value) return t('settings.javaNotDetected')
  const bitLabel = javaInfo.value.is64Bit ? t('settings.bit64') : t('settings.bit32')
  const typeLabel = javaInfo.value.isJDK ? 'JDK' : 'JRE'
  return `Java ${javaInfo.value.majorVer} (${javaInfo.value.version}) ${bitLabel} ${typeLabel}`
})
</script>

<template>
  <div class="settings-page">
    <!-- 顶部导航 -->
    <div class="top-bar">
      <button class="btn btn-outline" @click="emit('navigate', 'main')">
        {{ t('settings.backToMain') }}
      </button>
      <h2 class="page-title">{{ t('settings.title') }}</h2>
    </div>

    <div class="settings-body">
      <!-- 左侧分类导航 -->
      <div class="settings-nav">
        <div
          v-for="section in sections"
          :key="section.id"
          class="nav-item"
          :class="{ active: activeSection === section.id }"
          @click="activeSection = section.id"
        >
          <span class="nav-icon" v-html="section.icon"></span>
          <span class="nav-label">{{ section.label }}</span>
        </div>
      </div>

      <!-- 右侧内容区域 -->
      <div class="settings-content">
        <!-- 常规设置 -->
        <div v-if="activeSection === 'general'" class="content-panel fade-in">
          <h3 class="panel-title">{{ t('settings.generalTitle') }}</h3>

          <div class="setting-group">
            <div class="group-header">{{ t('settings.javaSettings') }}</div>

            <div class="form-group">
              <label>{{ t('settings.javaPath') }}</label>
              <div class="java-path-row">
                <input
                  v-model="javaPath"
                  class="input"
                  :placeholder="t('settings.javaPathPlaceholder')"
                />
                <button class="btn btn-outline btn-sm" @click="clearJavaPath" v-if="javaPath">{{ t('settings.clear') }}</button>
              </div>
              <div class="form-hint" v-if="javaInfo" style="color: #00897B;">
                {{ javaVersionLabel }}
              </div>
              <div class="form-hint" v-else-if="javaPath" style="color: #e53935;">
                {{ t('settings.invalidJava') }}
              </div>
              <div class="form-hint" v-else>
                {{ t('settings.autoSelectJava') }}
              </div>
            </div>

            <div class="form-group">
              <label>{{ t('settings.detectedJava') }}</label>
              <div class="java-search-bar">
                <button class="btn btn-outline btn-sm" @click="searchJavaList" :disabled="searchingJava">
                  {{ searchingJava ? t('settings.searching') : t('settings.refresh') }}
                </button>
                <span class="java-count">{{ t('settings.javaCount', { count: javaList.length }) }}</span>
              </div>
              <div class="java-list" v-if="javaList.length > 0">
                <div
                  v-for="j in javaList"
                  :key="j.path"
                  class="java-item"
                  :class="{ selected: javaPath === j.path }"
                  @click="selectJava(j.path)"
                >
                  <div class="java-item-info">
                    <span class="java-version-tag" :class="'java-' + j.majorVer">Java {{ j.majorVer }}</span>
                    <span class="java-detail">{{ j.version }} {{ j.is64Bit ? t('settings.bit64') : t('settings.bit32') }} {{ j.isJDK ? 'JDK' : 'JRE' }}</span>
                  </div>
                  <div class="java-item-path">{{ j.path }}</div>
                </div>
              </div>
              <div class="java-list-empty" v-else-if="!searchingJava">
                {{ t('settings.noJavaDetected') }}
              </div>
            </div>

            <div class="form-row">
              <div class="form-group half">
                <label>{{ t('settings.maxMemory') }}</label>
                <input
                  v-model.number="maxMemory"
                  class="input"
                  type="number"
                  min="1"
                  max="32"
                />
              </div>
              <div class="form-group half">
                <label>{{ t('settings.minMemory') }}</label>
                <input
                  v-model.number="minMemory"
                  class="input"
                  type="number"
                  min="1"
                  max="32"
                />
              </div>
            </div>
          </div>

          <div class="setting-group">
            <div class="group-header">{{ t('settings.gameSettings') }}</div>

            <div class="form-group">
              <label>{{ t('settings.minecraftDir') }}</label>
              <div class="java-path-row">
                <input
                  v-model="minecraftDir"
                  class="input"
                  :placeholder="t('settings.minecraftDirPlaceholder')"
                />
                <button class="btn btn-outline btn-sm" @click="clearMinecraftDir" v-if="minecraftDir">{{ t('settings.clear') }}</button>
                <button class="btn btn-outline btn-sm" @click="resetMinecraftDir">{{ t('settings.defaultBtn') }}</button>
              </div>
              <div class="form-hint">
                {{ t('settings.minecraftDirHint') }}
              </div>
            </div>

            <div class="setting-row">
              <div class="setting-text">
                <div class="setting-name">{{ t('settings.versionIsolation') }}</div>
                <!-- <div class="setting-desc">开启之后不同用户数据不互通，包括存档</div>-->
              </div>
              <label class="toggle">
                <input type="checkbox" v-model="versionIsolation" />
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div v-if="saveMsg" class="save-msg" :class="{ error: saveMsg.includes(t('settings.saveFailed')) }">
            {{ saveMsg }}
          </div>

          <button
            class="btn btn-primary btn-large"
            :disabled="saving"
            @click="saveSettings"
            style="margin-top: 16px;"
          >
            {{ saving ? t('settings.saving') : t('settings.saveSettings') }}
          </button>
        </div>

        <!-- 个性化 -->
        <div v-if="activeSection === 'personalize'" class="content-panel fade-in">
          <h3 class="panel-title">{{ t('settings.personalize') }}</h3>

          <div class="setting-group">
            <div class="group-header">{{ t('settings.themeColor') }}</div>
            <div class="theme-colors">
              <div
                v-for="tc in themeColors"
                :key="tc.id"
                class="theme-color-item"
                :class="{ active: themeColor === tc.id }"
                @click="changeThemeColor(tc.id)"
              >
                <div class="theme-color-circle" :style="{ background: tc.color }"></div>
                <span class="theme-color-label">{{ tc.label }}</span>
              </div>
            </div>
          </div>

          <div class="setting-group">
            <div class="group-header">{{ t('settings.backgroundImage') }}</div>
            <div class="bg-preview" v-if="backgroundImage">
              <div class="bg-preview-img" :style="{ backgroundImage: `url(${backgroundImage})` }"></div>
              <div class="bg-preview-info">
                <!-- <span class="bg-preview-path">{{ backgroundImage }}</span>-->
                <div class="bg-preview-actions">
                  <button class="btn btn-outline btn-sm" @click="selectBgImage">{{ t('settings.change') }}</button>
                  <button class="btn btn-outline btn-sm" @click="resetBgImage">{{ t('settings.resetDefault') }}</button>
                </div>
              </div>
            </div>
            <div v-else class="bg-no-custom">
              <div class="bg-default-hint">{{ t('settings.currentDefaultBg') }}</div>
              <button class="btn btn-outline btn-sm" @click="selectBgImage">{{ t('settings.selectCustomBg') }}</button>
            </div>
            <div class="bing-daily-section">
              <button
                class="btn bing-daily-btn"
                :disabled="bingLoading"
                @click="fetchBingDailyImage"
              >
                <span v-if="!bingLoading">&#x1F30D; {{ t('settings.getBingDaily') }}</span>
                <span v-else class="spin-inline">{{ t('settings.getting') }}</span>
              </button>
            </div>
          </div>
        </div>

        <!-- 其他 -->
        <div v-if="activeSection === 'other'" class="content-panel fade-in">
          <h3 class="panel-title">{{ t('settings.otherTitle') }}</h3>

          <!-- 语言切换 -->
          <div class="setting-group">
            <div class="group-header">{{ t('settings.language') }}</div>
            <div class="setting-row">
              <div class="setting-text">
                <div class="setting-name">{{ t('settings.language') }}</div>
                <div class="setting-desc">{{ t('settings.languageDesc') }}</div>
              </div>
              <select class="language-select" v-model="currentLocale" @change="changeLanguage(currentLocale)">
                <option v-for="lang in languageOptions" :key="lang.value" :value="lang.value">
                  {{ lang.label }}
                </option>
              </select>
            </div>
          </div>

          <!-- 导出启动命令按钮 -->
          <div class="setting-group">
            <div class="group-header">{{ t('settings.showExportLaunchCommand') }}</div>
            <div class="setting-row">
              <div class="setting-text">
                <div class="setting-name">{{ t('settings.showExportLaunchCommand') }}</div>
                <div class="setting-desc">{{ t('settings.showExportLaunchCommandDesc') }}</div>
              </div>
              <label class="toggle">
                <input type="checkbox" v-model="showExportLaunchCommand" @change="toggleExportLaunchCommand" />
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <!-- 便携版模式 -->
          <div class="setting-group">
            <div class="group-header">{{ t('settings.portableMode') }}</div>
            <div class="setting-row">
              <div class="setting-text">
                <div class="setting-name">{{ t('settings.enablePortable') }}</div>
                <div class="setting-desc">
                  {{ t('settings.portableDesc') }}
                </div>
              </div>
              <label class="toggle">
                <input type="checkbox" v-model="portableMode" @change="togglePortableMode" />
                <span class="toggle-slider"></span>
              </label>
            </div>

            <!-- 便携版 Java 状态 -->
            <div v-if="portableMode" class="portable-java-status">
              <div class="setting-row" style="flex-direction: column; align-items: flex-start;">
                <div class="setting-name">{{ t('settings.portableJavaPath') }}</div>
                <div class="portable-java-path">{{ portableJavaPath }}</div>
                <div v-if="portableJavaInfo" class="portable-java-info">
                  <span class="java-version-tag">Java {{ portableJavaInfo.majorVer }}</span>
                  <span class="java-version-detail">{{ portableJavaInfo.version }}</span>
                </div>
                <div v-else class="portable-java-missing">
                  {{ t('settings.portableJavaMissing') }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 用户 -->
        <div v-if="activeSection === 'user'" class="content-panel fade-in">
          <h3 class="panel-title">{{ t('settings.userTitle') }}</h3>

          <div class="current-user-card">
            <img v-if="avatarMap[currentUser?.username]" class="user-avatar-lg" :src="avatarMap[currentUser?.username]" alt="" />
            <div v-else class="user-avatar-lg">{{ currentUser?.username?.charAt(0).toUpperCase() || 'P' }}</div>
            <div class="user-detail">
              <div class="user-name-lg">{{ currentUser?.username || 'Player' }}</div>
              <div class="user-type-badge" :class="currentUser?.type">
                {{ currentUserType }}
              </div>
            </div>
            <button class="btn btn-outline" @click="handleLogout">{{ t('settings.switchAccount') }}</button>
          </div>

          <!-- 用户管理 -->
          <div class="user-list-section">
            <div class="group-header">{{ t('settings.userManage') }}</div>
            <div class="user-manage-panel">
              <div class="form-group">
                <label>{{ t('settings.setPassword') }}</label>
                <input
                  v-if="currentUser?.hasPassword"
                  v-model="pwdForm.oldPassword"
                  type="password"
                  class="input"
                  :placeholder="t('settings.oldPassword')"
                />
                <input
                  v-model="pwdForm.newPassword"
                  type="password"
                  class="input"
                  :placeholder="t('settings.newPassword')"
                />
                <input
                  v-model="pwdForm.confirmPassword"
                  type="password"
                  class="input"
                  :placeholder="t('settings.confirmNewPassword')"
                />
                <div class="pwd-btn-row">
                  <button
                    v-if="currentUser?.hasPassword"
                    class="btn btn-outline btn-sm"
                    @click="clearUserPassword"
                  >{{ t('settings.removePassword') }}</button>
                  <button class="btn btn-primary btn-sm" :disabled="pwdSaving" @click="saveUserPassword">
                    {{ pwdSaving ? t('settings.saving') : t('settings.savePwd') }}
                  </button>
                </div>
              </div>
              <div class="form-group user-delete-group">
                <label>{{ t('settings.deleteAccount') }}</label>
                <input
                  v-if="currentUser?.hasPassword"
                  v-model="deletePassword"
                  type="password"
                  class="input"
                  :placeholder="t('settings.enterAccountPassword')"
                />
                <button class="btn btn-danger btn-sm" @click="confirmDeleteAccount">
                  {{ t('settings.deleteAccountBtn') }}
                </button>
              </div>
              <div v-if="userManageMsg" class="user-manage-msg">{{ userManageMsg }}</div>
            </div>
          </div>

          <!-- 访客权限管理（解锁后显示） -->
          <div v-if="currentUser?.type === 'guest' && !currentUser?.isLocked" class="user-list-section">
            <div class="group-header guest-perm-header">
              <span>{{ t('settings.guestPermTitle') }}</span>
              <button class="btn btn-outline btn-sm" @click="lockGuestUser">
                {{ t('settings.lockGuestBtn') }}
              </button>
            </div>
            <div class="guest-perm-list">
              <div v-for="item in guestPermItems" :key="item.key" class="guest-perm-row">
                <div class="guest-perm-info">
                  <span class="guest-perm-label">{{ item.label }}</span>
                  <span class="guest-perm-desc">{{ item.desc }}</span>
                </div>
                <button class="perm-toggle" :class="{ on: item.value }" @click="toggleGuestPerm(item.key)">
                  {{ item.value ? t('settings.permShow') : t('settings.permHide') }}
                </button>
              </div>
            </div>
          </div>

          <div class="user-list-section">
            <div class="group-header">{{ t('settings.allUsers') }}</div>
            <div class="user-list">
              <div
                v-for="user in users"
                :key="user.username"
                class="user-list-item"
                :class="{ current: user.username === currentUser?.username }"
              >
                <img v-if="avatarMap[user.username]" class="user-list-avatar" :src="avatarMap[user.username]" alt="" />
                <div v-else class="user-list-avatar">{{ user.username.charAt(0).toUpperCase() }}</div>
                <div class="user-list-info">
                  <div class="user-list-name">{{ user.username }}</div>
                  <div class="user-list-meta">
                    <span class="type-tag" :class="user.type">
                      {{ user.type === 'guest' ? t('settings.guest') : (user.type === 'premium' ? t('settings.premium') : (user.type === 'external' ? t('settings.external') : t('settings.offline'))) }}
                    </span>
                    <span v-if="user.hasPassword" class="pwd-tag">{{ t('settings.passwordSet') }}</span>
                  </div>
                </div>
                <span v-if="user.username === currentUser?.username" class="current-tag">{{ t('settings.currentTag') }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 关于 -->
        <div v-if="activeSection === 'about'" class="content-panel fade-in">
          <h3 class="panel-title">{{ t('settings.aboutTitle') }}</h3>

          <div class="about-card">
            <img :src="logoImg" class="about-logo-img" alt="QingLongLuncher" />
            <div class="about-name">{{ t('settings.qinglongLuncher') }}</div>
            <div class="about-subtitle">{{ t('settings.qinglongLuncherCN') }}</div>
            <div class="about-version">{{ launcherVersion }}</div>
          </div>

          <div class="about-info-list">
            <div class="about-info-item">
              <span class="info-label">{{ t('settings.version') }}</span>
              <span class="info-value">{{ launcherVersion }}</span>
            </div>
            <div class="about-info-item">
              <span class="info-label">{{ t('settings.copyright') }}</span>
              <span class="info-value">{{ t('settings.copyrightValue') }}</span>
            </div>
            <div class="about-info-item">
              <span class="info-label">{{ t('settings.edition') }}</span>
              <span class="info-value">{{ t('settings.edition') }}</span>
            </div>
          </div>

          <!-- 开源协议 -->
          <div class="license-section">
            <button class="btn btn-outline license-btn" @click="$emit('show-license')">&#x1F4C4; {{ t('settings.openSourceLicense') }}</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 样式部分保持不变 */
.settings-page {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background: transparent;
  position: relative;
  z-index: 2;
}

.top-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--glass-border);
  flex-shrink: 0;
  background: rgba(255, 255, 255, 0.88);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

.page-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
}

.settings-body {
  flex: 1;
  display: flex;
  overflow: hidden;
}

/* 左侧导航 */
.settings-nav {
  width: 220px;
  min-width: 200px;
  background: rgba(255, 255, 255, 0.92);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border-right: 1px solid var(--border);
  padding: 16px 12px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s;
  margin-bottom: 4px;
  color: var(--text-secondary);
  font-size: 14px;
  font-weight: 500;
}

.nav-item:hover {
  background: var(--glass-bg);
  color: var(--primary-dark);
}

.nav-item.active {
  background: var(--glass-bg);
  color: var(--primary-dark);
  font-weight: 600;
}

.nav-icon {
  font-size: 18px;
  width: 24px;
  text-align: center;
}

.nav-label {
  white-space: nowrap;
}

/* 右侧内容 */
.settings-content {
  flex: 1;
  overflow-y: auto;
  padding: 28px 36px;
}

.content-panel {
  max-width: 640px;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.4);
  border-radius: 12px;
  padding: 24px;
}

.panel-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 24px;
}

/* 设置分组 */
.setting-group {
  background: rgba(255, 255, 255, 0.6);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 10px;
  padding: 16px;
  margin-bottom: 16px;
  border: 1px solid rgba(255, 255, 255, 0.3);
}

.group-header {
  font-size: 13px;
  font-weight: 600;
  color: var(--primary-dark);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 16px;
}

/* 表单 */
.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 6px;
}

.form-hint {
  font-size: 12px;
  color: var(--text-light);
  margin-top: 4px;
}

.form-row {
  display: flex;
  gap: 16px;
}

.form-group.half {
  flex: 1;
}

/* 设置行 */
.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
}

.setting-text {
  flex: 1;
}

.setting-name {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
  margin-bottom: 2px;
}

.setting-desc {
  font-size: 12px;
  color: var(--text-light);
}

/* 语言选择 */
.language-select {
  padding: 6px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: white;
  color: var(--text);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  outline: none;
  transition: border-color 0.15s;
  min-width: 120px;
}

.language-select:hover {
  border-color: var(--primary);
}

.language-select:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 2px var(--primary-bg);
}

/* 用户卡片 */
.current-user-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px;
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 12px;
  margin-bottom: 24px;
}

/* 真实头像（img）：无背景容器，透明显不规则形状 */
img.user-avatar-lg,
img.user-list-avatar {
  background: transparent;
  box-shadow: none;
  border: none;
}

.user-avatar-lg {
  width: 56px;
  height: 56px;
  background: var(--primary);
  color: white;
  border-radius: 10px;
  object-fit: cover;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  font-weight: 700;
  flex-shrink: 0;
}

.user-detail {
  flex: 1;
}

.user-name-lg {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
}

.user-type-badge {
  display: inline-block;
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 10px;
  font-weight: 500;
}

.user-type-badge.guest {
  background: #FFF3E0;
  color: #E65100;
}

.user-type-badge.offline {
  background: #E8F5E9;
  color: #2E7D32;
}

.user-type-badge.premium {
  background: #E8EAF6;
  color: #283593;
}

.user-type-badge.external {
  background: #E0F7FA;
  color: #00695C;
}

/* 用户列表 */
.user-list-section {
  margin-top: 8px;
}

/* 用户管理面板 */
.user-manage-panel {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px 18px;
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 12px;
}
.user-manage-panel .input {
  margin-bottom: 8px;
}
.pwd-btn-row {
  display: flex;
  gap: 10px;
}
.btn-danger {
  background: #e53935;
  color: #fff;
  border: none;
}
.btn-danger:hover {
  background: #c62828;
}
.user-delete-group .btn-danger {
  margin-top: 4px;
}
.user-manage-msg {
  margin-top: 6px;
  font-size: 12px;
  color: var(--primary-color, #00bcd4);
  word-break: break-all;
}

/* 访客权限管理 */
.guest-perm-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.guest-perm-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.guest-perm-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 16px;
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 10px;
}
.guest-perm-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.guest-perm-label {
  font-size: 14px;
  font-weight: 600;
  color: #333;
}
.guest-perm-desc {
  font-size: 12px;
  color: #888;
}
.perm-toggle {
  flex-shrink: 0;
  min-width: 76px;
  padding: 6px 14px;
  border-radius: 16px;
  border: 1px solid #ddd;
  background: #f2f2f2;
  color: #999;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.2s;
}
.perm-toggle.on {
  background: var(--primary-color, #00bcd4);
  border-color: var(--primary-color, #00bcd4);
  color: #fff;
}

.user-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.user-list-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 10px;
  transition: background 0.15s;
}

.user-list-item:hover {
  background: var(--bg-card);
}

.user-list-item.current {
  background: var(--primary-bg);
}

.user-list-avatar {
  width: 40px;
  height: 40px;
  background: var(--primary-light);
  color: var(--primary-dark);
  border-radius: 8px;
  object-fit: cover;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  font-weight: 600;
  flex-shrink: 0;
}

.user-list-info {
  flex: 1;
}

.user-list-name {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.user-list-meta {
  display: flex;
  gap: 8px;
  margin-top: 2px;
}

.type-tag {
  font-size: 11px;
  padding: 1px 8px;
  border-radius: 8px;
  font-weight: 500;
}

.type-tag.guest {
  background: #FFF3E0;
  color: #E65100;
}

.type-tag.offline {
  background: #E8F5E9;
  color: #2E7D32;
}

.type-tag.premium {
  background: #E8EAF6;
  color: #283593;
}

.type-tag.external {
  background: #E0F7FA;
  color: #00695C;
}

.pwd-tag {
  font-size: 11px;
  padding: 1px 8px;
  border-radius: 8px;
  background: #E3F2FD;
  color: #1565C0;
  font-weight: 500;
}

.current-tag {
  font-size: 11px;
  padding: 2px 10px;
  background: var(--primary-bg);
  color: var(--primary-dark);
  border-radius: 10px;
  font-weight: 600;
}

/* 关于页面 */
.about-card {
  text-align: center;
  padding: 32px 20px;
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 16px;
  margin-bottom: 28px;
}

.about-logo-img {
  width: 80px;
  height: 80px;
  border-radius: 20px;
  object-fit: cover;
  margin: 0 auto 16px;
  display: block;
}

.about-name {
  font-size: 20px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 4px;
}

.about-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.about-version {
  display: inline-block;
  font-size: 13px;
  padding: 3px 12px;
  background: white;
  color: var(--primary-dark);
  border-radius: 12px;
  font-weight: 600;
}

.about-info-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.about-info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
}

.about-info-item:last-child {
  border-bottom: none;
}

.info-label {
  font-size: 14px;
  color: var(--text-secondary);
}

.info-value {
  font-size: 14px;
  color: var(--text);
  font-weight: 500;
}

/* 保存消息 */
.save-msg {
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 13px;
  background: rgba(232, 245, 233, 0.85);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #2E7D32;
  margin-top: 12px;
  border: 1px solid rgba(46, 125, 50, 0.15);
}

.save-msg.error {
  background: rgba(255, 243, 240, 0.85);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: var(--danger);
  border-color: rgba(244, 67, 54, 0.15);
}

/* Java 设置相关 */
.java-path-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.java-path-row .input {
  flex: 1;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 12px;
  white-space: nowrap;
}

.java-search-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.java-count {
  font-size: 12px;
  color: var(--text-light);
}

.java-list {
  max-height: 240px;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
}

.java-item {
  padding: 10px 14px;
  cursor: pointer;
  border-bottom: 1px solid var(--border);
  transition: background 0.15s;
}

.java-item:last-child {
  border-bottom: none;
}

.java-item:hover {
  background: var(--primary-bg);
}

.java-item.selected {
  background: var(--primary-bg);
  border-left: 3px solid var(--primary);
}

.java-item-info {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 2px;
}

.java-version-tag {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  padding: 1px 8px;
  border-radius: 6px;
  color: white;
}

.java-version-tag.java-7 { background: #78909C; }
.java-version-tag.java-8 { background: #43A047; }
.java-version-tag.java-11 { background: #1E88E5; }
.java-version-tag.java-16 { background: #8E24AA; }
.java-version-tag.java-17 { background: #FB8C00; }
.java-version-tag.java-18 { background: #F4511E; }
.java-version-tag.java-19 { background: #D81B60; }
.java-version-tag.java-20 { background: #6D4C41; }
.java-version-tag.java-21 { background: #00897B; }
.java-version-tag.java-22 { background: #546E7A; }
.java-version-tag.java-23 { background: #3949AB; }
.java-version-tag.java-24 { background: #00838F; }

.java-detail {
  font-size: 12px;
  color: var(--text-secondary);
}

.java-item-path {
  font-size: 11px;
  color: var(--text-light);
  word-break: break-all;
}

.java-list-empty {
  padding: 20px;
  text-align: center;
  font-size: 13px;
  color: var(--text-light);
  border: 1px dashed var(--border);
  border-radius: 8px;
}

/* 个性化 */
.theme-colors {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.theme-color-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  padding: 8px;
  border-radius: 10px;
  transition: background 0.15s;
}

.theme-color-item:hover {
  background: var(--glass-bg);
}

.theme-color-item.active {
  background: var(--primary-bg);
}

.theme-color-circle {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  border: 3px solid transparent;
  transition: border-color 0.15s;
}

.theme-color-item.active .theme-color-circle {
  border-color: var(--text);
}

.theme-color-label {
  font-size: 12px;
  color: var(--text-secondary);
  font-weight: 500;
}

.bg-preview {
  display: flex;
  gap: 16px;
  align-items: center;
  padding: 16px;
  background: var(--glass-bg);
  border-radius: 12px;
  border: 1px solid var(--glass-border);
}

.bg-preview-img {
  width: 120px;
  height: 80px;
  border-radius: 8px;
  background-size: cover;
  background-position: center;
  flex-shrink: 0;
}

.bg-preview-info {
  flex: 1;
  min-width: 0;
}

.bg-preview-path {
  display: block;
  font-size: 12px;
  color: var(--text-light);
  word-break: break-all;
  margin-bottom: 8px;
}

.bg-preview-actions {
  display: flex;
  gap: 8px;
}

.bg-no-custom {
  text-align: center;
  padding: 24px;
  background: var(--glass-bg);
  border-radius: 12px;
  border: 1px dashed var(--border);
}

.bg-default-hint {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 12px;
}

.bing-daily-section {
  margin-top: 16px;
  text-align: center;
}

.bing-daily-btn {
  width: 100%;
  padding: 12px 20px;
  background: linear-gradient(135deg, #0078D4, #00BCD4);
  color: white;
  border: none;
  border-radius: 10px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.bing-daily-btn:hover:not(:disabled) {
  opacity: 0.9;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 120, 212, 0.3);
}

.bing-daily-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.spin-inline {
  display: inline-block;
  animation: spin 1s linear infinite;
}

/* 开源协议 */
.license-section {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
}

.license-btn {
  width: 100%;
  padding: 10px 20px;
  font-size: 14px;
  font-weight: 500;
}

/* 便携版模式 */
.portable-java-status {
  margin-top: 8px;
  padding: 12px 16px;
  background: rgba(255, 255, 255, 0.6);
  border-radius: 8px;
  border: 1px solid var(--glass-border);
}

.portable-java-path {
  font-size: 12px;
  color: var(--text-light);
  font-family: monospace;
  margin-top: 6px;
  word-break: break-all;
}

.portable-java-info {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

.java-version-tag {
  display: inline-block;
  padding: 2px 10px;
  background: var(--primary);
  color: white;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 600;
}

.java-version-detail {
  font-size: 12px;
  color: var(--text-secondary);
}

.portable-java-missing {
  margin-top: 8px;
  padding: 8px 12px;
  background: #FFF3E0;
  color: #E65100;
  border-radius: 6px;
  font-size: 12px;
  border: 1px solid #FFE0B2;
}
</style>