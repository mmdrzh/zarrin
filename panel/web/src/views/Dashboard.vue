<template>
  <div>
    <div class="page-head"><h1>داشبورد</h1><span class="muted small">به‌روزرسانی خودکار هر ۱۰ ثانیه</span></div>
    <div v-if="d && !d.db_ok" class="alert bad">اتصال به دیتابیس پاسارگاد برقرار نیست.</div>
    <div v-if="d?.cert?.self_signed" class="alert warn">گواهی SSL پنل هنوز صادر نشده (موقت است). از «تنظیمات» صدور گواهی را بزنید.</div>
    <div v-if="d" class="grid k4">
      <div class="card stat"><div class="label">اتصال‌های آنلاین</div><div class="value">{{ num(d.online_total) }}</div>
        <div class="sub">{{ num(d.online_users) }} کاربر</div></div>
      <div class="card stat"><div class="label">کاربران فعال پاسارگاد</div><div class="value">{{ num(d.users.active) }}</div>
        <div class="sub">در انتظار: {{ num(d.users.on_hold) }}</div></div>
      <div class="card stat"><div class="label">منقضی / تمام‌حجم</div><div class="value">{{ num(d.users.expired) }} / {{ num(d.users.limited) }}</div>
        <div class="sub">غیرفعال: {{ num(d.users.disabled) }}</div></div>
      <div class="card stat"><div class="label">آخرین بکاپ</div><div class="value" style="font-size:18px">{{ d.last_backup ? ago(d.last_backup.at) : '—' }}</div>
        <div class="sub">{{ d.last_backup_telegram?.result || 'تلگرام: ارسال نشده' }}</div></div>
    </div>

    <div v-if="d" class="grid k2 mt">
      <div class="card">
        <h2>پروتکل‌ها</h2>
        <div v-if="!Object.keys(d.online_by_proto).length" class="empty">کسی آنلاین نیست</div>
        <table v-else>
          <tr v-for="(n, p) in d.online_by_proto" :key="p"><td>{{ PROTO[p] || p }}</td><td>{{ num(n) }} اتصال</td></tr>
        </table>
      </div>
      <div class="card">
        <h2>نودها</h2>
        <div v-if="!d.nodes.length" class="empty">نودی ثبت نشده</div>
        <table v-else>
          <tr v-for="n in d.nodes" :key="n.id">
            <td><span class="dot" :class="n.live ? 'ok' : 'bad'"></span>{{ n.name }}</td>
            <td class="mono small">{{ n.ip }}</td>
            <td>{{ num(n.online) }} آنلاین</td>
            <td><span v-if="n.legacy" class="badge warn">ایجنت قدیمی</span><span v-else class="badge info">v{{ n.agent_version || '?' }}</span></td>
          </tr>
        </table>
      </div>
    </div>
    <div v-if="!d" class="empty">در حال بارگذاری...</div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, num, ago, PROTO } from '../api'

const d = ref(null)
let timer
async function load() { d.value = await api.get('/api/dashboard') }
onMounted(() => { load(); timer = setInterval(load, 10000) })
onUnmounted(() => clearInterval(timer))
</script>
