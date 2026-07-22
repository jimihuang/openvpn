<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <input
        v-model="search"
        class="input !w-64"
        :placeholder="t('hist.searchPh')"
        @keyup.enter="load(0)"
      />
      <span class="text-sm text-gray-400">{{ t('hist.total', { n: total }) }}</span>
    </div>

    <div class="card overflow-x-auto">
      <table class="w-full">
        <thead class="bg-gray-50 dark:bg-gray-900/40">
          <tr>
            <th class="th">{{ t('dash.account') }}</th>
            <th class="th">{{ t('dash.client') }}</th>
            <th class="th">{{ t('dash.srcIp') }}</th>
            <th class="th">{{ t('dash.tunIp') }}</th>
            <th class="th">{{ t('hist.download') }}</th>
            <th class="th">{{ t('hist.upload') }}</th>
            <th class="th">{{ t('hist.onlineAt') }}</th>
            <th class="th">{{ t('hist.duration') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <tr v-for="h in rows" :key="h.id">
            <td class="td font-medium">{{ h.username || '-' }}</td>
            <td class="td">{{ h.common_name }}</td>
            <td class="td">{{ h.rip }}</td>
            <td class="td">{{ h.vip }}</td>
            <td class="td">{{ fmtMaybeBytes(h.bytes_received) }}</td>
            <td class="td">{{ fmtMaybeBytes(h.bytes_sent) }}</td>
            <td class="td">{{ fmtMaybeUnix(h.time_unix) }}</td>
            <td class="td">{{ fmtMaybeDuration(h.time_duration) }}</td>
          </tr>
          <tr v-if="rows.length === 0">
            <td colspan="8" class="td py-10 text-center text-gray-400">{{ t('hist.emptyList') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="flex items-center justify-end gap-2">
      <button class="btn-secondary" :disabled="offset === 0" @click="load(offset - limit)">
        {{ t('hist.prev') }}
      </button>
      <span class="text-sm text-gray-500">{{ page }} / {{ pages }}</span>
      <button class="btn-secondary" :disabled="offset + limit >= total" @click="load(offset + limit)">
        {{ t('hist.next') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { getHistory, type HistoryRecord } from '../api';
import { formatBytes, formatDuration, formatUnix } from '../utils/format';

const { t } = useI18n();

const rows = ref<HistoryRecord[]>([]);
const total = ref(0);
const offset = ref(0);
const limit = 20;
const search = ref('');

const page = computed(() => Math.floor(offset.value / limit) + 1);
const pages = computed(() => Math.max(1, Math.ceil(total.value / limit)));

// 后端 MarshalJSON 可能已把数值格式化为字符串,原样展示;是数字才本地格式化
const fmtMaybeBytes = (v: number | string) => (typeof v === 'number' ? formatBytes(v) : v);
const fmtMaybeUnix = (v: number | string) => (typeof v === 'number' ? formatUnix(v) : v);
const fmtMaybeDuration = (v: number | string) => (typeof v === 'number' ? formatDuration(v) : v);

async function load(newOffset = offset.value) {
  offset.value = Math.max(0, newOffset);
  const { data } = await getHistory({
    draw: 1,
    offset: offset.value,
    limit,
    orderColumn: 'id',
    order: 'desc',
    search: search.value.trim(),
  });
  rows.value = data.data;
  total.value = data.recordsFiltered;
}

onMounted(() => load(0));
</script>
