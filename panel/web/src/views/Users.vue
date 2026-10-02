<template>
  <div>
    <div class="page-head"><h1>جستجوی کاربر</h1></div>
    <div class="card mb">
      <input v-model="q" class="ltr" placeholder="نام کاربری (حداقل ۲ حرف)..." @input="search" autofocus />
      <div class="hint">کاربرها در پاسارگاد ساخته و مدیریت می‌شوند؛ اینجا اطلاعات اتصال زرین هر کاربر را می‌بینید.</div>
    </div>
    <div v-if="loading" class="empty">...</div>
    <div v-else-if="q.length >= 2 && !results.length" class="empty">کاربری پیدا نشد</div>
    <div v-for="u in results" :key="u.id" class="card">
      <div class="row">
        <h2 class="mono" style="margin:0">{{ u.username }}</h2>
        <span class="badge" :class="statusClass(u.status)">{{ USER_STATUS[u.status] || u.status }}</span>
        <span v-if="u.allowed" class="badge ok">مجاز به اتصال</span>
        <span v-else class="badge bad">غیرمجاز</span>
        <span v-if="u.sessions.length" class="badge gold">{{ num(u.sessions.length) }} اتصال آنلاین</span>
      </div>
      <div class="grid k4 mt">
        <div><div class="muted small">رمز IKEv2 / L2TP / OpenVPN</div><div class="mono" style="font-size:20px;font-weight:800">{{ u.password || '—' }}
          <button v-if="u.password" class="btn sm" @click="doCopy(u.password)">کپی</button></div></div>
        <div><div class="muted small">مصرف</div><div>{{ bytes(u.used_traffic) }} <span class="muted">از</span> {{ u.data_limit ? bytes(u.data_limit) : 'نامحدود' }}</div></div>
        <div><div class="muted small">انقضا</div><div>{{ u.expire ? date(u.expire) : 'بدون انقضا' }}</div></div>
        <div><div class="muted small">آخرین اتصال</div><div>{{ ago(u.online_at) }}</div></div>
      </div>
      <table v-if="u.sessions.length" class="mt">
        <tr v-for="s in u.sessions" :key="s.node_id + s.id">
          <td><span class="badge gold">{{ PROTO[s.proto] || s.proto }}</span></td><td class="mono small">{{ s.remote }}</td>
          <td class="small">{{ duration(s.since) }}</td><td class="small">↑{{ bytes(s.up) }} ↓{{ bytes(s.down) }}</td>
        </tr>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { api, num, bytes, date, ago, duration, copy, PROTO, USER_STATUS } from '../api'

const toast = inject('toast')
const q = ref('')
const results = ref([])
const loading = ref(false)
let timer

function search() {
  clearTimeout(timer)
  timer = setTimeout(async () => {
    if (q.value.trim().length < 2) { results.value = []; return }
    loading.value = true
    try { results.value = await api.get(`/api/users?q=${encodeURIComponent(q.value.trim())}`) } finally { loading.value = false }
  }, 300)
}
const statusClass = (s) => ({ active: 'ok', on_hold: 'warn', expired: 'bad', limited: 'bad', disabled: 'bad' }[s] || '')
async function doCopy(t) { if (await copy(t)) toast('کپی شد') }
</script>
