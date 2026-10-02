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
        <label class="field"><span>API Token کلودفلر (Zone → DNS → Edit)</span>
          <input v-model="s.cloudflare_token" class="ltr" autocomplete="off" />
          <div class="hint">برای گرفتن گواهی با DNS و اضافه/حذف خودکار IP نودها در رکورد IKEv2.</div></label>
        <div v-if="s.cloudflare_kind === 'global_key'" class="alert warn">
          این <b>Global API Key</b> است، نه API Token. Global Key کنترل کامل کل حساب کلودفلر (همه‌ی دامنه‌ها) را می‌دهد و اگر سرور یا یک بکاپ لو برود، همه‌ی دامنه‌ها در خطرند.
          زرین فقط به ویرایش DNS نیاز دارد؛ لطفاً یک API Token با قالب «Edit zone DNS» بسازید و جایگزین کنید.
          <label class="field mt"><span>ایمیل حساب کلودفلر (فقط برای Global Key لازم است)</span>
            <input v-model="s.cloudflare_email" class="ltr" autocomplete="off" /></label>
        </div>
        <div class="row mb">
          <button class="btn" @click="testCf">تست اتصال کلودفلر</button>
        </div>
        <div v-if="cfTest" class="alert" :class="cfTest.ok ? 'ok' : 'bad'">
          <template v-if="cfTest.ok">درست است ({{ cfTest.kind === 'token' ? 'API Token' : 'Global Key' }}) — دامنه‌های در دسترس:
            <span class="mono">{{ cfTest.zones.join('، ') || 'هیچ' }}</span></template>
          <template v-else>{{ cfTest.error }}</template>
        </div>
        <div class="small mb">گواهی پنل (<span class="mono">{{ s.cert.domain }}</span>):
          <span v-if="s.cert.self_signed" class="badge warn">موقت (خودامضا)</span>
          <span v-else class="badge ok">معتبر — {{ num(Math.floor(s.cert.days_left)) }} روز مانده</span></div>
        <button class="btn" :disabled="issuing" @click="issue">{{ issuing ? 'در حال صدور...' : 'صدور / تمدید گواهی' }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue'
import { api, num } from '../api'

const toast = inject('toast')
const s = ref(null)
const saving = ref(false)
const issuing = ref(false)
const cfTest = ref(null)
const pgTest = ref(null)

async function load() { s.value = await api.get('/api/settings') }
onMounted(load)

async function save() {
  saving.value = true
  try {
    const { cert, cloudflare_kind, ...body } = s.value
    await api.put('/api/settings', body)
    toast('ذخیره شد')
    load()
  } catch (e) { alert(e.message) } finally { saving.value = false }
}
async function testTelegram() {
  try { await save(); await api.post('/api/settings/telegram/test'); toast('پیام ارسال شد ✅') } catch (e) { alert(e.message) }
}
async function testCf() {
  cfTest.value = null
  try { await save(); cfTest.value = await api.post('/api/settings/cloudflare/test') } catch (e) { cfTest.value = { ok: false, error: e.message } }
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
