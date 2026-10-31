import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN.js'
import zhTW from './locales/zh-TW.js'
import enUS from './locales/en-US.js'

const savedLocale = localStorage.getItem('qgl-locale') || 'zh-CN'

const i18n = createI18n({
  legacy: false, // 使用 Composition API 模式
  locale: savedLocale,
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
    'zh-TW': zhTW,
    'en-US': enUS,
  },
})

export default i18n
