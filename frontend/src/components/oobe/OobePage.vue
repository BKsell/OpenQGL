<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { SetOOBEDone } from '../../../wailsjs/go/main/App.js'
import StepWelcome from './StepWelcome.vue'
import StepMigrate from './StepMigrate.vue'
import StepCreateUser from './StepCreateUser.vue'
import StepMoreAccounts from './StepMoreAccounts.vue'
import StepDone from './StepDone.vue'
import MigratePage from '../MigratePage.vue'

const emit = defineEmits(['finished', 'login-success'])

const { t } = useI18n()

// 步骤: welcome → migrate-q
//   ├─ 迁移: MigratePage → done（迁移模式跳过创建用户页）
//   └─ 全新: create(initial) → more → (add-more → create(more) → more 循环 | finish) → done
const step = ref('welcome')
const createMode = ref('initial') // 'initial' | 'more'

// 记录迁移流程是否已选择迁移（迁移完成后直接到 done，不再显示创建用户页）
const choseMigrate = ref(false)

function goNext() {
  if (step.value === 'welcome') step.value = 'migrate-q'
}

function onMigrateChoice(choice) {
  if (choice === 'migrate') {
    choseMigrate.value = true
    step.value = 'migrate-ui'
  } else {
    choseMigrate.value = false
    createMode.value = 'initial'
    step.value = 'create'
  }
}

function onMigrationFinished() {
  // 迁移完成：继续询问是否需要其他账户
  step.value = 'more'
}

function onUserCreated() {
  step.value = 'more'
}

function onMoreChoice(choice) {
  if (choice === 'yes') {
    createMode.value = 'more'
    step.value = 'create'
  } else {
    step.value = 'done'
  }
}

async function onStart() {
  try { await SetOOBEDone() } catch {}
  emit('finished')
}

// 步骤返回：点错了可以退回上一步
function goBack(from) {
  if (from === 'migrate-q') {
    step.value = 'welcome'
  } else if (from === 'create') {
    step.value = createMode.value === 'more' ? 'more' : 'migrate-q'
  } else if (from === 'more') {
    createMode.value = 'more'
    step.value = 'create'
  } else if (from === 'done') {
    step.value = 'more'
  }
}

async function onMigrationLoginSuccess(user) {
  // 迁移中直接登录成功：标记 OOBE 完成并进入主界面
  try { await SetOOBEDone() } catch {}
  emit('login-success', user)
}
</script>

<template>
  <div class="oobe-page">
    <div class="oobe-glass">
      <!-- 欢迎页 -->
      <StepWelcome v-if="step === 'welcome'" @next="goNext" />

      <!-- 迁移询问页 -->
      <StepMigrate v-else-if="step === 'migrate-q'" @choose="onMigrateChoice" @back="goBack('migrate-q')" />

      <!-- 迁移界面（复用独立迁移页） -->
      <MigratePage
        v-else-if="step === 'migrate-ui'"
        @back="step = 'migrate-q'"
        @finished="onMigrationFinished"
        @login-success="onMigrationLoginSuccess"
      />

      <!-- 创建用户页 -->
      <StepCreateUser
        v-else-if="step === 'create'"
        :mode="createMode"
        @created="onUserCreated"
        @skip="onUserCreated"
        @back="goBack('create')"
      />

      <!-- 是否需要其他账户 -->
      <StepMoreAccounts v-else-if="step === 'more'" @choose="onMoreChoice" @back="goBack('more')" />

      <!-- 大功告成 -->
      <StepDone v-else-if="step === 'done'" @start="onStart" @back="goBack('done')" />
    </div>
  </div>
</template>

<style>
/* OOBE 共享样式已提取到 src/oobe.css 全局加载
   （UserWizard 单独进入时本组件 chunk 未加载，组件内样式会丢失） */
</style>
