import { ref } from 'vue'

// 全局崩溃弹窗实例引用
const dialogRef = ref(null)

export function setCrashDialogRef(dialog) {
  dialogRef.value = dialog
}

/**
 * 显示 PCL 风格崩溃弹窗
 * @param {Object} options
 * @param {string} options.title 大标题（如"游戏崩溃了！"）
 * @param {string} [options.reason] 崩溃/失败原因
 */
export function showCrashDialog(options) {
  if (dialogRef.value) {
    return dialogRef.value.show(options)
  }
}
