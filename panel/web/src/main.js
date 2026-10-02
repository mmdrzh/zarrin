import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import '@fontsource/vazirmatn/400.css'
import '@fontsource/vazirmatn/600.css'
import '@fontsource/vazirmatn/800.css'
import './style.css'
import App from './App.vue'
import { loadMe, session } from './api'

import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'
import Nodes from './views/Nodes.vue'
import Online from './views/Online.vue'
import Users from './views/Users.vue'
import Backups from './views/Backups.vue'
import Settings from './views/Settings.vue'
import Security from './views/Security.vue'
import Audit from './views/Audit.vue'

const routes = [
  { path: '/login', component: Login, meta: { public: true, title: 'ورود' } },
  { path: '/', component: Dashboard, meta: { title: 'داشبورد' } },
  { path: '/nodes', component: Nodes, meta: { title: 'نودها' } },
  { path: '/online', component: Online, meta: { title: 'کاربران آنلاین' } },
  { path: '/users', component: Users, meta: { title: 'جستجوی کاربر' } },
  { path: '/backups', component: Backups, meta: { title: 'بکاپ و ریستور' } },
  { path: '/settings', component: Settings, meta: { title: 'تنظیمات' } },
  { path: '/security', component: Security, meta: { title: 'حساب و امنیت' } },
  { path: '/audit', component: Audit, meta: { title: 'گزارش فعالیت' } },
  { path: '/:p(.*)*', redirect: '/' },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to) => {
  if (!session.checked) await loadMe()
  if (!to.meta.public && !session.me) return '/login'
  if (to.path === '/login' && session.me) return '/'
})

router.afterEach((to) => {
  document.title = `${to.meta.title || ''} · زرین`
})

createApp(App).use(router).mount('#app')
