<template>
  <div class="login-wrap">
    <form class="card login" @submit.prevent="submit">
      <div class="logo">
        <img src="/favicon.svg" alt="" />
        <h1 class="mt">زرین</h1>
        <div class="muted small">ورود به پنل مدیریت</div>
      </div>
      <div v-if="error" class="alert bad">{{ error }}</div>
      <template v-if="!needCode">
        <label class="field"><span>نام کاربری</span>
          <input v-model="username" class="ltr" autocomplete="username" autofocus required />
        </label>
        <label class="field"><span>رمز عبور</span>
          <input v-model="password" type="password" class="ltr" autocomplete="current-password" required />
        </label>
      </template>
      <label v-else class="field"><span>کد ۶ رقمی برنامه‌ی Authenticator</span>
        <input v-model="code" class="ltr center" inputmode="numeric" autocomplete="one-time-code" maxlength="8" autofocus required />
      </label>
      <button class="btn gold" style="width:100%" :disabled="busy">{{ busy ? '...' : 'ورود' }}</button>
      <button v-if="needCode" type="button" class="btn ghost sm mt" @click="needCode = false; code = ''">بازگشت</button>
    </form>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, loadMe } from '../api'

const router = useRouter()
const username = ref('')
const password = ref('')
const code = ref('')
const needCode = ref(false)
const busy = ref(false)
const error = ref('')

const messages = {
  invalid: 'نام کاربری یا رمز اشتباه است',
  totp_invalid: 'کد اشتباه است',
  too_many_attempts: 'تلاش‌های ناموفق زیاد بود؛ ۱۵ دقیقه‌ی دیگر امتحان کنید',
}

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await api.post('/api/auth/login', { username: username.value, password: password.value, code: code.value || null })
    await loadMe()
    router.replace('/')
  } catch (e) {
    const reason = e.data?.error
    if (reason === 'totp_required') needCode.value = true
    else error.value = messages[reason] || e.message
  } finally {
    busy.value = false
  }
}
</script>
