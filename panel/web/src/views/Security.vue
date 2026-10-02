<template>
  <div>
    <div class="page-head"><h1>حساب و امنیت</h1></div>
    <div class="grid k2">
      <form class="card" @submit.prevent="changePassword">
        <h2>تغییر رمز</h2>
        <label class="field"><span>رمز فعلی</span><input v-model="pw.current" type="password" class="ltr" autocomplete="current-password" required /></label>
        <label class="field"><span>رمز جدید (حداقل ۱۰ کاراکتر)</span><input v-model="pw.new" type="password" class="ltr" minlength="10" autocomplete="new-password" required /></label>
        <label class="field"><span>تکرار رمز جدید</span><input v-model="pw.again" type="password" class="ltr" autocomplete="new-password" required /></label>
        <div v-if="pwError" class="alert bad">{{ pwError }}</div>
        <button class="btn primary">تغییر رمز</button>
      </form>

      <div class="card">
        <h2>ورود دومرحله‌ای (2FA)</h2>
        <template v-if="session.me?.totp">
          <div class="alert ok">ورود دومرحله‌ای فعال است.</div>
          <form @submit.prevent="disable2fa">
            <label class="field"><span>رمز عبور</span><input v-model="off.password" type="password" class="ltr" required /></label>
            <label class="field"><span>کد ۶ رقمی</span><input v-model="off.code" class="ltr" inputmode="numeric" required /></label>
            <button class="btn danger">غیرفعال کردن</button>
          </form>
        </template>
        <template v-else>
          <div class="alert warn">ورود دومرحله‌ای خاموش است. فعال کردنش به‌شدت توصیه می‌شود.</div>
          <button v-if="!setup" class="btn primary" @click="start2fa">فعال کردن</button>
          <form v-else @submit.prevent="enable2fa">
            <p class="small">با Google Authenticator یا هر برنامه‌ی مشابه این کد را اسکن کنید:</p>
            <div class="qr mb" v-html="setup.qr"></div>
            <p class="small muted">یا کلید را دستی وارد کنید: <span class="mono">{{ setup.secret }}</span></p>
            <label class="field"><span>کد ۶ رقمی که برنامه نشان می‌دهد</span><input v-model="code" class="ltr" inputmode="numeric" required autofocus /></label>
            <button class="btn primary">تأیید و فعال‌سازی</button>
          </form>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, inject } from 'vue'
import { api, session, loadMe } from '../api'

const toast = inject('toast')
const pw = reactive({ current: '', new: '', again: '' })
const pwError = ref('')
const setup = ref(null)
const code = ref('')
const off = reactive({ password: '', code: '' })

async function changePassword() {
  pwError.value = ''
  if (pw.new !== pw.again) { pwError.value = 'تکرار رمز یکسان نیست'; return }
  try {
    await api.post('/api/auth/password', { current: pw.current, new: pw.new })
    Object.assign(pw, { current: '', new: '', again: '' })
    toast('رمز تغییر کرد')
  } catch (e) { pwError.value = e.message }
}
async function start2fa() { setup.value = await api.post('/api/auth/totp/setup') }
async function enable2fa() {
  try {
    await api.post('/api/auth/totp/enable', { code: code.value })
    setup.value = null; code.value = ''
    await loadMe(); toast('ورود دومرحله‌ای فعال شد')
  } catch (e) { alert(e.message) }
}
async function disable2fa() {
  try {
    await api.post('/api/auth/totp/disable', { password: off.password, code: off.code })
    Object.assign(off, { password: '', code: '' })
    await loadMe(); toast('غیرفعال شد')
  } catch (e) { alert(e.message) }
}
</script>
