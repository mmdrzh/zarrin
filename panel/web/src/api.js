import { reactive } from 'vue'

export const session = reactive({ me: null, checked: false })

export class ApiError extends Error {
  constructor(status, data) {
    super((data && (data.detail || data.error)) || `HTTP ${status}`)
    this.status = status
    this.data = data
  }
}

async function request(method, path, body, { raw = false } = {}) {
  const opts = { method, credentials: 'same-origin', headers: {} }
  if (method !== 'GET') opts.headers['X-Zarrin'] = '1'
  if (body instanceof FormData) {
    opts.body = body
  } else if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(path, opts)
  if (raw) return res
  let data = null
  const text = await res.text()
  try { data = text ? JSON.parse(text) : null } catch { data = { detail: text } }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/auth/login')) {
      session.me = null
      if (location.pathname !== '/login') location.assign('/login')
    }
    throw new ApiError(res.status, data)
  }
  return data
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, b = {}) => request('POST', p, b),
  put: (p, b = {}) => request('PUT', p, b),
  patch: (p, b = {}) => request('PATCH', p, b),
  del: (p) => request('DELETE', p),
  upload: (p, form) => request('POST', p, form),
}

export async function loadMe() {
  try {
    session.me = await api.get('/api/auth/me')
  } catch {
    session.me = null
  }
  session.checked = true
  return session.me
}

// ---------------------------------------------------------------- format

const nf = new Intl.NumberFormat('fa-IR')
export const num = (n) => nf.format(n || 0)

export function bytes(n) {
  n = Number(n || 0)
  const units = ['بایت', 'کیلوبایت', 'مگابایت', 'گیگابایت', 'ترابایت']
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${new Intl.NumberFormat('fa-IR', { maximumFractionDigits: i ? 1 : 0 }).format(n)} ${units[i]}`
}

const df = new Intl.DateTimeFormat('fa-IR-u-ca-persian', { dateStyle: 'medium', timeStyle: 'short' })
export const date = (ts) => (ts ? df.format(new Date(ts * 1000)) : '—')

export function ago(ts) {
  if (!ts) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  if (s < 60) return `${num(s)} ثانیه پیش`
  if (s < 3600) return `${num(Math.floor(s / 60))} دقیقه پیش`
  if (s < 86400) return `${num(Math.floor(s / 3600))} ساعت پیش`
  return `${num(Math.floor(s / 86400))} روز پیش`
}

export function duration(ts) {
  if (!ts) return '—'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h ? `${num(h)} ساعت و ${num(m)} دقیقه` : `${num(m)} دقیقه`
}

export const PROTO = { ikev2: 'IKEv2', l2tp: 'L2TP', openvpn: 'OpenVPN', wireguard: 'WireGuard' }
export const USER_STATUS = { active: 'فعال', on_hold: 'در انتظار', limited: 'تمام‌حجم', expired: 'منقضی', disabled: 'غیرفعال' }

export async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  }
}
