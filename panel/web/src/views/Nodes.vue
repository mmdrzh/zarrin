<template>
  <div>
    <div class="page-head">
      <h1>نودها</h1>
      <button class="btn primary" @click="openJoin">+ افزودن نود</button>
    </div>

    <div v-if="joinCmd" class="card mb">
      <h2>دستور نصب</h2>
      <p class="muted small">این دستور را روی سرور نود (با root) اجرا کنید. لینک تا ۲۴ ساعت معتبر است و نود با همان IP که دستور را اجرا کند ثبت می‌شود.</p>
      <div class="codebox"><code>{{ joinCmd }}</code><button class="btn" @click="doCopy(joinCmd)">کپی</button></div>
      <button class="btn sm ghost mt" @click="joinCmd = ''">بستن</button>
    </div>

    <div class="card">
      <div v-if="!nodes.length" class="empty">نودی ثبت نشده. «افزودن نود» را بزنید.</div>
      <div v-else class="table-wrap">
        <table>
          <thead><tr><th>نام</th><th>IP</th><th>وضعیت</th><th>آنلاین</th><th>نود پاسارگاد</th><th>IKEv2</th><th>ایجنت</th><th></th></tr></thead>
          <tbody>
            <tr v-for="n in nodes" :key="n.id">
              <td><b>{{ n.name }}</b></td>
              <td class="mono small">{{ n.ip }}</td>
              <td><span class="dot" :class="n.live ? 'ok' : 'bad'"></span>{{ n.live ? 'متصل' : 'قطع' }}
                <div class="muted small">{{ ago(n.last_seen) }}</div></td>
              <td>{{ num(n.online) }}</td>
              <td>
                <select :value="n.pg_node?.id ?? ''" @change="setPg(n, $event.target.value)" style="min-width:120px">
                  <option value="">— خودکار —</option>
                  <option v-for="p in pgNodes" :key="p.id" :value="p.id">{{ p.name }} ({{ p.address }})</option>
                </select>
              </td>
              <td>
                <label class="row small"><input type="checkbox" :checked="n.settings?.ikev2?.enabled !== false" :disabled="n.legacy"
                  @change="toggle(n, 'ikev2', $event.target.checked)" /> فعال</label>
              </td>
              <td><span v-if="n.legacy" class="badge warn">قدیمی (pg-ikev2)</span><span v-else class="badge info">v{{ n.agent_version || '?' }}</span></td>
              <td class="row" style="flex-wrap:nowrap">
                <button class="btn sm" @click="reinstall(n)">{{ n.legacy ? 'ارتقا' : 'نصب مجدد' }}</button>
                <button class="btn sm" @click="rename(n)">نام</button>
                <button class="btn sm danger" @click="remove(n)">حذف</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="showJoin" class="modal-bg" @click.self="showJoin = false">
      <form class="card modal" @submit.prevent="createJoin">
        <h2>افزودن نود جدید</h2>
        <label class="field"><span>نام نود</span><input v-model="joinName" placeholder="مثلاً Node5" required autofocus /></label>
        <p class="muted small">پیش‌نیاز: سرور تازه با اوبونتو ۲۲ یا ۲۴. دستور خودش داکر و ایجنت زرین را نصب می‌کند.</p>
        <div class="row"><button class="btn primary">ساخت دستور نصب</button><button type="button" class="btn ghost" @click="showJoin = false">انصراف</button></div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, inject } from 'vue'
import { api, num, ago, copy } from '../api'

const toast = inject('toast')
const nodes = ref([])
const pgNodes = ref([])
const joinCmd = ref('')
const showJoin = ref(false)
const joinName = ref('')
let timer

async function load() {
  nodes.value = await api.get('/api/nodes')
}
onMounted(async () => {
  load()
  pgNodes.value = await api.get('/api/pasarguard/nodes').catch(() => [])
  timer = setInterval(load, 10000)
})
onUnmounted(() => clearInterval(timer))

function openJoin() { joinName.value = ''; showJoin.value = true }
async function createJoin() {
  const r = await api.post('/api/nodes/join', { name: joinName.value })
  joinCmd.value = r.command
  showJoin.value = false
}
async function reinstall(n) {
  const r = await api.post(`/api/nodes/${n.id}/reinstall`)
  joinCmd.value = r.command
  window.scrollTo({ top: 0, behavior: 'smooth' })
}
async function setPg(n, value) {
  await api.patch(`/api/nodes/${n.id}`, value ? { pg_node_id: Number(value) } : { clear_pg_node: true })
  toast('ذخیره شد'); load()
}
async function toggle(n, proto, enabled) {
  await api.patch(`/api/nodes/${n.id}`, { settings: { [proto]: { ...(n.settings?.[proto] || {}), enabled } } })
  toast('ذخیره شد؛ تا چند ثانیه روی نود اعمال می‌شود'); load()
}
async function rename(n) {
  const name = prompt('نام جدید نود:', n.name)
  if (name && name.trim()) { await api.patch(`/api/nodes/${n.id}`, { name: name.trim() }); load() }
}
async function remove(n) {
  if (!confirm(`نود ${n.name} (${n.ip}) از زرین حذف شود؟\nسرویس‌های VPN روی خود سرور باید جدا حذف شوند.`)) return
  const r = await api.del(`/api/nodes/${n.id}`)
  joinCmd.value = ''
  alert(`حذف شد. برای پاک کردن ایجنت روی سرور این را بزنید:\n\n${r.uninstall}`)
  load()
}
async function doCopy(text) { if (await copy(text)) toast('کپی شد') }
</script>
