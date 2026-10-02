<template>
  <router-view v-if="$route.meta.public" />
  <div v-else class="shell">
    <aside class="side" :class="{ open: menu }">
      <div class="brand">
        <img src="/favicon.svg" alt="" />
        <div><b>زرین</b><small>پنل تکمیلی طلا</small></div>
      </div>
      <nav class="nav" @click="menu = false">
        <router-link to="/"><span class="ico">◎</span>داشبورد</router-link>
        <router-link to="/online"><span class="ico">●</span>کاربران آنلاین</router-link>
        <router-link to="/users"><span class="ico">⌕</span>جستجوی کاربر</router-link>
        <router-link to="/nodes"><span class="ico">⬢</span>نودها</router-link>
        <router-link to="/backups"><span class="ico">⇅</span>بکاپ و ریستور</router-link>
        <router-link to="/settings"><span class="ico">⚙</span>تنظیمات</router-link>
        <router-link to="/security"><span class="ico">🔒</span>حساب و امنیت</router-link>
        <router-link to="/audit"><span class="ico">☰</span>گزارش فعالیت</router-link>
      </nav>
      <div class="foot">
        <div>{{ session.me?.username }}</div>
        <div class="mono small">v{{ session.me?.version }}</div>
        <button class="btn sm ghost mt" @click="logout">خروج</button>
      </div>
    </aside>
    <div v-if="menu" class="backdrop" @click="menu = false"></div>
    <div style="flex:1;min-width:0">
      <div class="topbar">
        <b>زرین</b>
        <button class="btn sm" @click="menu = true">☰ منو</button>
      </div>
      <main class="main"><router-view /></main>
    </div>
  </div>
  <div v-if="toast.text" class="toast">{{ toast.text }}</div>
</template>

<script setup>
import { ref, provide, reactive } from 'vue'
import { api, session } from './api'

const menu = ref(false)
const toast = reactive({ text: '' })
let timer = null
provide('toast', (text) => {
  toast.text = text
  clearTimeout(timer)
  timer = setTimeout(() => (toast.text = ''), 2600)
})

async function logout() {
  await api.post('/api/auth/logout').catch(() => {})
  session.me = null
  location.assign('/login')
}
</script>
