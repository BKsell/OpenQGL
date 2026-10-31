// 用户头像（皮肤脸）缓存 composable
// 后端 GetUserAvatar(userDir) 返回 PNG data URL，仅正版/外置用户有值
// loadAvatar(user) 接收用户对象（含 username/dir），缓存键为显示用户名
import { reactive } from 'vue'
import { GetUserAvatar } from '../../wailsjs/go/main/App.js'

// username -> dataURL（'' 表示无真实头像，回退首字母）
const avatarMap = reactive({})
// 加载中的用户，防止并发重复请求
const pending = new Set()

async function loadAvatar(user) {
  const username = typeof user === 'string' ? user : user?.username
  const dir = typeof user === 'string' ? user : user?.dir
  if (!username || !dir || avatarMap[username] !== undefined || pending.has(username)) return
  pending.add(username)
  try {
    avatarMap[username] = (await GetUserAvatar(dir)) || ''
  } catch {
    avatarMap[username] = ''
  } finally {
    pending.delete(username)
  }
}

export function useAvatars() {
  return { avatarMap, loadAvatar }
}
