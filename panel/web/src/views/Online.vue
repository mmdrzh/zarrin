<template>
  <div>
    <div class="page-head">
      <h1>کاربران آنلاین</h1>
      <div class="row">
        <input v-model="q" placeholder="جستجوی نام کاربری..." style="width:220px" class="ltr" />
        <select v-model="proto" style="width:140px">
          <option value="">همه‌ی پروتکل‌ها</option>
          <option v-for="(label, key) in PROTO" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>
    <div class="grid k4 mb">
      <div class="card stat"><div class="label">اتصال‌ها</div><div class="value">{{ num(filtered.length) }}</div></div>
      <div class="card stat"><div class="label">کاربران یکتا</div><div class="value">{{ num(uniqueUsers) }}</div></div>
      <div class="card stat"><div class="label">مسدود موقت</div><div class="value">{{ num(Object.keys(blocked).length) }}</div></div>
    </div>

    <div v-if="Object.keys(blocked).length" class="card mb">
      <h2>مسدودهای موقت</h2>
      <div class="row">
        <span v-for="(until, u) in blocked" :key="u" class="badge bad">
          <span class="mono">{{ u }}</span> تا {{ date(until) }}
          <a href="#" @click.prevent="unblock(u)">✕</a>
        </span>
      </div>
    </div>

    <div class="card">
      <div v-if="!filtered.length" class="empty">کسی آنلاین نیست</div>
      <div v-else class="table-wrap">
        <table>
          <thead><tr><th>کاربر</th><th>پروتکل</th><th>نود</th><th>IP کاربر</th><th>مدت</th><th>آپلود</th><th>دانلود</th><th></th></tr></thead>
          <tbody>
            <tr v-for="s in filtered" :key="s.node_id + s.id">
              <td class="mono"><b>{{ s.user }}</b></td>
              <td><span class="badge gold">{{ PROTO[s.proto] || s.proto }}</span></td>
              <td>{{ s.node }}</td>
              <td class="mono small">{{ s.remote }}</td>
              <td class="small">{{ duration(s.since) }}</td>
              <td class="small">{{ bytes(s.up) }}</td>
              <td class="small">{{ bytes(s.down) }}</td>
              <td class="row" style="flex-wrap:nowrap">
                <button class="btn sm" @click="kick(s, 0)">قطع</button>
                <button class="btn sm danger" @click="askBlock(s)">قطع و مسدود</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, inject } from 'vue'
import { api, num, bytes, duration, date, PROTO } from '../api'

const toast = inject('toast')
const sessions = ref([])
const blocked = ref({})
const q = ref('')
const proto = ref('')
let timer

const filtered = computed(() => sessions.value.filter((s) =>
  (!q.value || s.user.toLowerCase().includes(q.value.toLowerCase())) && (!proto.value || s.proto === proto.value)))
const uniqueUsers = computed(() => new Set(filtered.value.map((s) => s.user)).size)

async function load() {
  const r = await api.get('/api/online')
  sessions.value = r.sessions
  blocked.value = r.blocked
}
onMounted(() => { load(); timer = setInterval(load, 8000) })
onUnmounted(() => clearInterval(timer))

async function kick(s, minutes) {
  await api.post('/api/online/kick', { user: s.user, block_minutes: minutes })
  toast(minutes ? `${s.user} قطع و ${minutes} دقیقه مسدود شد` : `دستور قطع ${s.user} ارسال شد`)
  setTimeout(load, 3000)
}
function askBlock(s) {
  const m = prompt(`${s.user} چند دقیقه مسدود شود؟ (روی همه‌ی نودها و پروتکل‌های زرین)`, '60')
  if (m && Number(m) > 0) kick(s, Number(m))
}
async function unblock(u) {
  await api.del(`/api/online/blocked/${encodeURIComponent(u)}`)
  load()
}
</script>
