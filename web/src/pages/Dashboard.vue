<template>
  <div class="space-y-6">
    <!-- 服务端状态卡片 -->
    <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <div class="card p-5">
        <div class="text-xs font-medium uppercase tracking-wide text-gray-400">{{ t('dash.status') }}</div>
        <div class="mt-2 flex items-center gap-2">
          <span
            class="h-2.5 w-2.5 rounded-full"
            :class="server?.Status === 'CONNECTED' ? 'bg-emerald-500' : 'bg-red-500'"
          ></span>
          <span class="text-lg font-semibold text-gray-900 dark:text-gray-100">
            {{ server?.Status === 'CONNECTED' ? t('dash.running') : server?.Status || t('dash.unknown') }}
          </span>
        </div>
        <div class="hint">{{ t('dash.startedAt') }} {{ server?.RunDate || '-' }}</div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium uppercase tracking-wide text-gray-400">{{ t('dash.online') }}</div>
        <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {{ server?.Nclients ?? '-' }}
        </div>
        <div class="hint">{{ server?.Mode || '' }} {{ server?.Address || '' }}</div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium uppercase tracking-wide text-gray-400">{{ t('dash.down') }}</div>
        <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {{ formatBytes(server?.BytesIn ?? 0) }}
        </div>
        <div class="hint">{{ t('dash.sinceStart') }}</div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium uppercase tracking-wide text-gray-400">{{ t('dash.up') }}</div>
        <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-gray-100">
          {{ formatBytes(server?.BytesOut ?? 0) }}
        </div>
        <div class="hint">{{ server?.Version || '' }}</div>
      </div>
    </div>

    <!-- 在线客户端 -->
    <div class="card">
      <div
        class="flex items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-700"
      >
        <h2 class="font-semibold text-gray-900 dark:text-gray-100">{{ t('dash.onlineUsers') }}</h2>
        <span class="hint !mt-0">{{ t('dash.autoRefresh') }}</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-50 dark:bg-gray-900/40">
            <tr>
              <th class="th">{{ t('dash.account') }}</th>
              <th class="th">{{ t('dash.client') }}</th>
              <th class="th">{{ t('dash.srcIp') }}</th>
              <th class="th">{{ t('dash.tunIp') }}</th>
              <th class="th">{{ t('dash.recv') }}</th>
              <th class="th">{{ t('dash.sent') }}</th>
              <th class="th">{{ t('dash.connectedAt') }}</th>
              <th class="th">{{ t('dash.duration') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
            <tr v-for="c in clients" :key="c.id">
              <td class="td font-medium">{{ c.username || '-' }}</td>
              <td class="td">{{ c.commonName }}</td>
              <td class="td">{{ c.rip }}</td>
              <td class="td">{{ c.vip }}</td>
              <td class="td">{{ formatBytes(c.recvBytes) }}</td>
              <td class="td">{{ formatBytes(c.sendBytes) }}</td>
              <td class="td">{{ c.connDate }}</td>
              <td class="td">{{ c.onlineTime }}</td>
            </tr>
            <tr v-if="clients.length === 0">
              <td colspan="8" class="td py-10 text-center text-gray-400">{{ t('dash.noOnline') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { getOnline, type OnlineClient, type ServerInfo } from '../api';
import { formatBytes } from '../utils/format';

const { t } = useI18n();

const server = ref<ServerInfo>();
const clients = ref<OnlineClient[]>([]);
let timer: number;

async function load() {
  try {
    const { data } = await getOnline();
    server.value = data.server;
    clients.value = data.clients;
  } catch {
    /* 会话过期由拦截器处理 */
  }
}

onMounted(() => {
  load();
  timer = window.setInterval(load, 10000);
});
onUnmounted(() => clearInterval(timer));
</script>
