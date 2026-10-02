<template>
  <div>
    <div class="page-head"><h1>گزارش فعالیت</h1></div>
    <div class="card">
      <div v-if="!rows.length" class="empty">چیزی ثبت نشده</div>
      <div v-else class="table-wrap">
        <table>
          <thead><tr><th>زمان</th><th>ادمین</th><th>IP</th><th>رویداد</th><th>جزئیات</th></tr></thead>
          <tbody>
            <tr v-for="r in rows" :key="r.id">
              <td class="small">{{ date(r.at) }}</td>
              <td class="mono small">{{ r.admin || '—' }}</td>
              <td class="mono small">{{ r.ip || '—' }}</td>
              <td><span class="badge" :class="r.action.includes('failed') ? 'bad' : ''">{{ r.action }}</span></td>
              <td class="mono small" style="max-width:420px;overflow-wrap:anywhere">{{ r.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api, date } from '../api'

const rows = ref([])
onMounted(async () => { rows.value = await api.get('/api/audit') })
</script>
