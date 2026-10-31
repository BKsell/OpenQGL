import { reactive } from 'vue'

// EasyQGL 全局状态
const easyQGLState = reactive({
  // 是否处于 EasyQGL 模式
  active: false,
  // 当前子模式: '' | 'mod-first' | 'version-first'
  mode: '',
  // 第一个选择的模组信息（用于锁定版本和加载器）
  firstMod: null,
  // 锁定的游戏版本
  lockedGameVersion: '',
  // 锁定的加载器
  lockedLoader: '',
  // 已选择的模组列表（下载列表中的）
  selectedMods: [],
  // 安装状态: 'idle' | 'installing-base' | 'installing-mods' | 'completed'
  installStatus: 'idle',
  // 安装进度消息
  installMessage: '',
})

export function useEasyQGL() {
  function enterModFirstMode() {
    easyQGLState.active = true
    easyQGLState.mode = 'mod-first'
    easyQGLState.firstMod = null
    easyQGLState.lockedGameVersion = ''
    easyQGLState.lockedLoader = ''
    easyQGLState.selectedMods = []
    easyQGLState.installStatus = 'idle'
    easyQGLState.installMessage = ''
  }

  function setFirstMod(mod, versionInfo) {
    easyQGLState.firstMod = mod

    // 优先从 versionInfo 提取（点击版本时传入的版本详情）
    if (versionInfo) {
      if (versionInfo.game_versions && versionInfo.game_versions.length > 0) {
        easyQGLState.lockedGameVersion = versionInfo.game_versions[0]
      }
      if (versionInfo.loaders && versionInfo.loaders.length > 0) {
        easyQGLState.lockedLoader = versionInfo.loaders[0].toLowerCase()
      }
      return
    }

    // 回退：从模组搜索结果中提取
    if (mod && mod.versions && mod.versions.length > 0) {
      const v = mod.versions[0]
      if (v.game_versions && v.game_versions.length > 0) {
        easyQGLState.lockedGameVersion = v.game_versions[0]
      }
      if (v.loaders && v.loaders.length > 0) {
        easyQGLState.lockedLoader = v.loaders[0].toLowerCase()
      }
    }
  }

  function addSelectedMod(mod) {
    easyQGLState.selectedMods.push(mod)
  }

  function exitMode() {
    easyQGLState.active = false
    easyQGLState.mode = ''
    easyQGLState.firstMod = null
    easyQGLState.lockedGameVersion = ''
    easyQGLState.lockedLoader = ''
    easyQGLState.selectedMods = []
    easyQGLState.installStatus = 'idle'
    easyQGLState.installMessage = ''
  }

  return {
    state: easyQGLState,
    enterModFirstMode,
    setFirstMod,
    addSelectedMod,
    exitMode,
  }
}
