import { ref } from 'vue'

// 全局弹窗实例引用
const dialogRef = ref(null)

export function setQGLDialogRef(dialog) {
  dialogRef.value = dialog
}

/**
 * 显示 QGL 自定义弹窗
 * @param {Object} options 弹窗配置
 * @param {'normal'|'error'} options.theme 主题，normal=主题色，error=红色
 * @param {string} options.title 弹窗标题
 * @param {string} options.content 弹窗内容（可单击复制）
 * @param {string} [options.btn1Label] 按钮1标题（不指定则不显示）
 * @param {string} [options.btn2Label] 按钮2标题（不指定则不显示）
 * @param {string} [options.btn3Label] 按钮3标题（不指定则不显示）
 * @returns {Promise<number>} 返回点击的按钮序号 (1, 2, 3)
 */
export function showQGLDialog(options) {
  if (dialogRef.value) {
    return dialogRef.value.show(options)
  }
  return Promise.resolve(0)
}
