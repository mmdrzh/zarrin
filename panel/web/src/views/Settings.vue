<template>
  <div>
    <div class="page-head"><h1>تنظیمات</h1><button class="btn primary" :disabled="saving" @click="save">ذخیره</button></div>
    <div v-if="s" class="grid k2">
      <div class="card">
        <h2>اتصال کاربران</h2>
        <label class="field"><span>دامنه‌ی IKEv2 (همه‌ی نودها پشت این دامنه)</span>
          <input v-model="s.ikev2_domain" class="ltr" placeholder="ik.example.com" />
          <div class="hint">در کلودفلر با ابر خاکستری (DNS only) به IP همه‌ی نودها اشاره کند.</div></label>
        <label class="field"><span>DNS برای کاربران VPN</span>
          <input v-model="s.dns" class="ltr" placeholder="8.8.8.8,1.1.1.1" /></label>
        <label class="field"><span>کلید مشترک L2TP (Pre-shared key)</span>
          <input v-model="s.l2tp_psk" class="ltr mono" autocomplete="off" />
          <div class="hint">برای همه‌ی کاربران و نودها یکی است. با عوض کردنش، همه‌ی کاربران L2TP باید کلید را در دستگاهشان عوض کنند.</div></label>
        <div class="row">
          <label class="field" style="flex:1"><span>پورت OpenVPN UDP (۰ = خاموش)</span>
            <input v-model.number="s.ovpn_udp_port" type="number" min="0" max="65535" class="ltr" /></label>
          <label class="field" style="flex:1"><span>پورت OpenVPN TCP (۰ = خاموش)</span>
            <input v-model.number="s.ovpn_tcp_port" type="number" min="0" max="65535" class="ltr" /></label>
        </div>
        <div class="row">
          <label class="field" style="flex:1"><span>پورت‌های جایگزین UDP</span>
            <input v-model="s.ovpn_udp_alt_ports" class="ltr" placeholder="443,2408" /></label>
          <label class="field" style="flex:1"><span>پورت‌های جایگزین TCP</span>
            <input v-model="s.ovpn_tcp_alt_ports" class="ltr" placeholder="2053,2087" /></label>
        </div>
        <div class="hint mb">روی نودها به پورت اصلی هدایت می‌شوند؛ فایل «خودکار» همه را به ترتیب امتحان می‌کند. پورتی که روی نود در حال استفاده باشد (مثلاً اینباند پاسارگاد) خودکار رد می‌شود.</div>
        <div class="row mb">
          <a class="btn sm" href="/api/openvpn/auto.ovpn">فایل OpenVPN خودکار</a>
          <a class="btn sm" href="/api/openvpn/udp.ovpn">دانلود فایل OpenVPN UDP</a>
          <a class="btn sm" href="/api/openvpn/tcp.ovpn">دانلود فایل OpenVPN TCP</a>
        </div>
        <div class="row">
          <button class="btn" @click="applySubpage">به‌روزرسانی کارت صفحه‌ی ساب</button>
          <span v-if="subpage" class="small" :style="{ color: subpage.ok ? 'var(--ok)' : subpage.ok === false ? 'var(--bad)' : 'var(--muted)' }">
            {{ subpage.pending ? 'در حال اعمال...' : subpage.ok ? 'اعمال شد ' + ago(subpage.at) : subpage.ok === false ? subpage.message : '' }}</span>
        </div>
        <div class="hint">کارت IKEv2 و L2TP (سرور، کلید، یوزر، رمز و راهنما) در صفحه‌ی ساب پاسارگاد. با تغییر دامنه یا کلید خودکار به‌روز می‌شود.</div>
      </div>

      <div class="card">
        <h2>ربات تلگرام (بکاپ)</h2>
        <label class="field"><span>توکن ربات (از BotFather)</span>
          <input v-model="s.telegram_bot_token" class="ltr" placeholder="123456:ABC..." autocomplete="off" /></label>
        <label class="field"><span>Chat ID (آیدی عددی شما یا کانال)</span>
          <input v-model="s.telegram_chat_id" class="ltr" placeholder="123456789" /></label>
        <div class="row">
          <label class="field" style="flex:1"><span>هر چند ساعت بکاپ (۰ = خاموش)</span>
            <input v-model.number="s.backup_interval_hours" type="number" min="0" max="168" step="0.5" class="ltr" /></label>
          <label class="field" style="flex:1"><span>تعداد بکاپ نگه‌داشته‌شده روی سرور</span>
            <input v-model.number="s.backup_keep" type="number" min="1" max="500" class="ltr" /></label>
        </div>
        <label class="field"><span>پراکسی برای تلگرام (اختیاری)</span>
          <input v-model="s.telegram_proxy" class="ltr" placeholder="socks5://127.0.0.1:1080" /></label>
        <button class="btn" @click="testTelegram">ارسال پیام آزمایشی</button>
      </div>

      <div class="card">
        <h2>پاسارگاد</h2>
        <label class="field"><span>API Key پاسارگاد (pg_key_...)</span>
          <input v-model="s.pasarguard_api_key" class="ltr" autocomplete="off" />
          <div class="hint">برای ثبت خودکار نودهای جدید در پاسارگاد. در پنل پاسارگاد با ادمین sudo بسازید.</div></label>
        <button class="btn" @click="testPg">تست اتصال</button>
        <div v-if="pgTest" class="alert mt" :class="pgTest.ok ? 'ok' : 'bad'">
          {{ pgTest.ok ? `درست است — ادمین ${pgTest.admin} (${pgTest.role})` : pgTest.error }}</div>
      </div>

      <div class="card">
        <h2>کلودفلر و گواهی SSL</h2>
        <p class="muted small">برای هر حساب کلودفلر یک API Token با قالب «Edit zone DNS» بسازید و اینجا اضافه کنید.
          زرین برای هر دامنه خودش توکن درست را پیدا می‌کند (گواهی پنل، رکورد IKEv2 نودها).</p>
        <div v-for="t in cfTokens" :key="t.id" class="row mb" style="align-items:flex-start;border:1px solid var(--line);border-radius:var(--radius);padding:8px 10px">
          <div style="flex:1;min-width:0">
            <b>{{ t.label }}</b> <span class="mono muted small">{{ t.token }}</span>
            <span v-if="t.ok === false" class="badge bad">{{ t.error }}</span>
            <div class="small"><span class="muted">دامنه‌ها:</span> <span class="mono">{{ t.zones.join('، ') || '—' }}</span></div>
          </div>
          <button class="btn sm danger" @click="removeCf(t)">حذف</button>
        </div>
        <form class="row mb" @submit.prevent="addCf">
          <input v-model="cfNew.label" placeholder="نام (مثلاً حساب دوم)" style="flex:1;min-width:120px" />
          <input v-model="cfNew.token" class="ltr" placeholder="API Token" autocomplete="off" style="flex:2;min-width:180px" />
          <button class="btn primary" :disabled="cfBusy || !cfNew.token">{{ cfBusy ? '...' : 'افزودن' }}</button>
        </form>
        <div v-if="cfError" class="alert bad">{{ cfError }}</div>
        <div v-if="ikevNoToken" class="alert warn">هیچ‌کدام از توکن‌ها به دامنه‌ی IKEv2 (<span class="mono">{{ s.ikev2_domain }}</span>) دسترسی ندارند.</div>
        <button class="btn sm mb" @click="checkCf">بررسی دوباره‌ی همه</button>
        <div class="small mb">گواهی پنل (<span class="mono">{{ s.cert.domain }}</span>):
          <span v-if="s.cert.self_signed" class="badge warn">موقت (خودامضا)</span>
          <span v-else class="badge ok">معتبر — {{ num(Math.floor(s.cert.days_left)) }} روز مانده</span></div>
        <button class="btn" :disabled="issuing" @click="issue">{{ issuing ? 'در حال صدور...' : 'صدور / تمدید گواهی' }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, inject } from 'vue'
import { api, num, ago } from '../api'

const toast = inject('toast')
const s = ref(null)
const saving = ref(false)
const issuing = ref(false)
const cfTokens = ref([])
const cfNew = ref({ label: '', token: '' })
const cfBusy = ref(false)
const cfError = ref('')
const pgTest = ref(null)
const subpage = ref(null)

async function load() {
  s.value = await api.get('/api/settings')
  cfTokens.value = await api.get('/api/cloudflare/tokens')
}
onMounted(() => { load(); loadSubpage() })

const ikevNoToken = computed(() => {
  const d = (s.value?.ikev2_domain || '').toLowerCase()
  return d && cfTokens.value.length && !cfTokens.value.some((t) => t.zones.some((z) => d === z || d.endsWith('.' + z)))
})
async function addCf() {
  cfBusy.value = true; cfError.value = ''
  try {
    await api.post('/api/cloudflare/tokens', cfNew.value)
    cfNew.value = { label: '', token: '' }
    cfTokens.value = await api.get('/api/cloudflare/tokens')
    toast('توکن اضافه شد')
  } catch (e) { cfError.value = e.message } finally { cfBusy.value = false }
}
async function removeCf(t) {
  if (!confirm(`توکن «${t.label}» حذف شود؟`)) return
  await api.del(`/api/cloudflare/tokens/${t.id}`)
  cfTokens.value = await api.get('/api/cloudflare/tokens')
}
async function checkCf() {
  cfError.value = ''
  try { cfTokens.value = await api.post('/api/cloudflare/check'); toast('بررسی شد') } catch (e) { cfError.value = e.message }
}

async function save() {
  saving.value = true
  try {
    const { cert, ...body } = s.value
    await api.put('/api/settings', body)
    toast('ذخیره شد')
    load()
  } catch (e) { alert(e.message) } finally { saving.value = false }
}
async function testTelegram() {
  try { await save(); await api.post('/api/settings/telegram/test'); toast('پیام ارسال شد ✅') } catch (e) { alert(e.message) }
}
async function loadSubpage() { subpage.value = await api.get('/api/subpage/status').catch(() => null) }
async function applySubpage() {
  await api.post('/api/subpage/apply'); await loadSubpage()
  const t = setInterval(async () => { await loadSubpage(); if (!subpage.value?.pending) clearInterval(t) }, 2000)
}
async function testPg() {
  pgTest.value = null
  try { await save(); pgTest.value = await api.post('/api/settings/pasarguard/test') } catch (e) { pgTest.value = { ok: false, error: e.message } }
}
async function issue() {
  issuing.value = true
  try {
    await save()
    await api.post('/api/certs/issue')
    toast('گواهی صادر شد'); load()
  } catch (e) { alert('خطا در صدور گواهی:\n' + e.message) } finally { issuing.value = false }
}
</script>
