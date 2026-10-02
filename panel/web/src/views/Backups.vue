<template>
  <div>
    <div class="page-head">
      <h1>بکاپ و ریستور</h1>
      <div class="row">
        <button class="btn" :disabled="busy" @click="create(false)">بکاپ محلی</button>
        <button class="btn primary" :disabled="busy" @click="create(true)">{{ busy ? 'در حال بکاپ...' : 'بکاپ + ارسال به تلگرام' }}</button>
      </div>
    </div>

    <div v-if="restore.state && restore.state !== 'idle'" class="card mb">
      <h2>وضعیت ریستور: <span class="badge" :class="restoreClass">{{ restoreLabel }}</span></h2>
      <pre class="mono small" style="white-space:pre-wrap;margin:0;max-height:260px;overflow:auto">{{ (restore.log || []).join('\n') }}</pre>
    </div>

    <div class="grid k2">
      <div class="card">
        <h2>بکاپ‌ها</h2>
        <p class="muted small">شامل: دیتابیس پاسارگاد، تنظیمات و قالب‌های پاسارگاد، و اطلاعات زرین.
          زمان‌بندی و ربات تلگرام در «تنظیمات» است.</p>
        <div v-if="data.last_telegram" class="small mb">آخرین ارسال تلگرام: {{ ago(data.last_telegram.at) }} — {{ data.last_telegram.result }}</div>
        <div v-if="!data.items?.length" class="empty">بکاپی نیست</div>
        <table v-else>
          <tr v-for="b in data.items" :key="b.name">
            <td><div class="mono small">{{ b.name }}</div><div class="muted small">{{ date(b.created) }} · {{ bytes(b.size) }}</div></td>
            <td class="row" style="justify-content:flex-end">
              <a class="btn sm" :href="`/api/backups/${b.name}/download`">دانلود</a>
              <button class="btn sm" @click="askRestore('backup', b.name)">ریستور</button>
              <button class="btn sm danger" @click="remove(b.name)">حذف</button>
            </td>
          </tr>
        </table>
      </div>

      <div class="card">
        <h2>ریستور از فایل</h2>
        <p class="muted small">فایل <span class="mono">.tar.gz</span> بکاپ زرین را انتخاب کنید. اگر از تلگرام چند تکه (part01, part02, ...) دانلود کرده‌اید، <b>همه‌ی تکه‌ها را با هم</b> انتخاب کنید.</p>
        <input type="file" multiple @change="files = [...$event.target.files]" />
        <button class="btn mt" :disabled="!files.length || uploading" @click="upload">{{ uploading ? 'در حال آپلود...' : 'آپلود و بررسی' }}</button>
        <div v-if="uploaded" class="alert ok mt">
          فایل معتبر است: ساخته‌شده در {{ date(uploaded.manifest.created) }} روی <span class="mono">{{ uploaded.manifest.host }}</span>
          <div><button class="btn sm primary mt" @click="askRestore('upload', uploaded.upload)">ریستور این فایل</button></div>
        </div>
      </div>
    </div>

    <div v-if="dialog" class="modal-bg" @click.self="dialog = null">
      <form class="card modal" @submit.prevent="doRestore">
        <h2>ریستور</h2>
        <div class="alert warn">در زمان ریستور دیتابیس، پنل پاسارگاد چند دقیقه از دسترس خارج می‌شود (اتصال کاربرها به نودها معمولاً برقرار می‌ماند).
          قبل از ریستور، خودکار از وضعیت فعلی بکاپ گرفته می‌شود و دیتابیس فعلی هم با نام دیگری نگه داشته می‌شود.</div>
        <label class="row mb"><input type="checkbox" v-model="dialog.pasarguard" /> دیتابیس پاسارگاد (کاربرها، ادمین‌ها، نودها، ...)</label>
        <label class="row mb"><input type="checkbox" v-model="dialog.files" /> فایل‌های پاسارگاد (گواهی‌های SSL و قالب صفحه‌ی ساب)</label>
        <label class="row mb"><input type="checkbox" v-model="dialog.zarrin" /> اطلاعات زرین (ادمین زرین، نودها، تنظیمات)</label>
        <label class="row mb"><input type="checkbox" v-model="dialog.env" /> تنظیمات .env پاسارگاد، به‌جز دیتابیس (مسیر ساب، SSL، قالب‌ها، ...)</label>
        <p class="muted small">برای انتقال به سرور جدید هر چهار گزینه را بزنید. اطلاعات اتصال به دیتابیس (DB_*) همیشه مال همین سرور می‌ماند.</p>
        <label class="field"><span>برای تأیید عبارت RESTORE را بنویسید</span><input v-model="dialog.confirm" class="ltr" /></label>
        <div v-if="dialog.error" class="alert bad">{{ dialog.error }}</div>
        <div class="row"><button class="btn danger solid" :disabled="dialog.confirm !== 'RESTORE'">شروع ریستور</button>
          <button type="button" class="btn ghost" @click="dialog = null">انصراف</button></div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, inject } from 'vue'
import { api, bytes, date, ago } from '../api'

const toast = inject('toast')
const data = ref({})
const restore = ref({})
const busy = ref(false)
const files = ref([])
const uploading = ref(false)
const uploaded = ref(null)
const dialog = ref(null)
let timer

async function load() {
  data.value = await api.get('/api/backups')
  restore.value = data.value.restore || {}
}
onMounted(() => { load(); timer = setInterval(async () => { restore.value = await api.get('/api/restore/status') }, 4000) })
onUnmounted(() => clearInterval(timer))

const restoreLabel = computed(() => ({ requested: 'در صف', running: 'در حال اجرا', done: 'انجام شد', failed: 'ناموفق' }[restore.value.state] || restore.value.state))
const restoreClass = computed(() => ({ done: 'ok', failed: 'bad' }[restore.value.state] || 'warn'))

async function create(telegram) {
  busy.value = true
  try {
    const r = await api.post('/api/backups', { telegram })
    toast(telegram ? `بکاپ ساخته شد؛ تلگرام: ${r.telegram}` : 'بکاپ ساخته شد')
    load()
  } catch (e) { alert(e.message) } finally { busy.value = false }
}
async function remove(name) {
  if (!confirm(`${name} حذف شود؟`)) return
  await api.del(`/api/backups/${name}`); load()
}
async function upload() {
  uploading.value = true
  uploaded.value = null
  try {
    const form = new FormData()
    files.value.forEach((f) => form.append('files', f, f.name))
    uploaded.value = await api.upload('/api/restore/upload', form)
  } catch (e) { alert(e.message) } finally { uploading.value = false }
}
function askRestore(source, name) {
  dialog.value = { source, name, pasarguard: true, files: true, env: false, zarrin: false, confirm: '', error: '' }
}
async function doRestore() {
  try {
    const { source, name, pasarguard, files, env, zarrin, confirm } = dialog.value
    await api.post('/api/restore', { source, name, pasarguard, files, env, zarrin, confirm })
    dialog.value = null
    toast('ریستور شروع شد')
    load()
  } catch (e) { dialog.value.error = e.message }
}
</script>
