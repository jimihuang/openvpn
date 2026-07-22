<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <p class="text-sm text-gray-500 dark:text-gray-400">
        {{ t('client.tip') }}
      </p>
      <button class="btn-primary" @click="addOpen = true">+ {{ t('client.addTitle') }}</button>
    </div>

    <div class="card overflow-x-auto">
      <table class="w-full">
        <thead class="bg-gray-50 dark:bg-gray-900/40">
          <tr>
            <th class="th">{{ t('client.name') }}</th>
            <th class="th">{{ t('client.file') }}</th>
            <th class="th">{{ t('client.createdAt') }}</th>
            <th class="th">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <tr v-for="c in clients" :key="c.fullName">
            <td class="td font-medium">
              <span>{{ c.name }}</span>
              <span
                v-if="c.isDefault"
                class="badge ml-2 bg-primary-100 text-primary-700 dark:bg-primary-600/20 dark:text-primary-100"
              >
                {{ t('client.default') }}
              </span>
            </td>
            <td class="td">{{ c.fullName }}</td>
            <td class="td">{{ c.date }}</td>
            <td class="td space-x-2 whitespace-nowrap">
              <a class="text-primary-600 hover:underline" :href="downloadUrl(c.fullName)"
                >{{ t('client.downloadCfg') }}</a
              >
              <button class="text-primary-600 hover:underline" @click="openFile(c.name, 'ccd')">
                {{ t('client.ccdBtn') }}
              </button>
              <button class="text-primary-600 hover:underline" @click="openFile(c.name, 'config')">
                {{ t('client.clientCfg') }}
              </button>
              <button
                v-if="!c.isDefault"
                class="text-primary-600 hover:underline"
                @click="onSetDefault(c)"
              >
                {{ t('client.setDefault') }}
              </button>
              <button class="text-red-500 hover:underline" @click="onDelete(c)">{{ t('common.delete') }}</button>
            </td>
          </tr>
          <tr v-if="clients.length === 0">
            <td colspan="4" class="td py-10 text-center text-gray-400">
              {{ t('client.emptyList') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 添加客户端 -->
    <Modal :open="addOpen" :title="t('client.addTitle')" wide @close="addOpen = false">
      <form class="space-y-4" @submit.prevent="onCreate">
        <div>
          <label class="label">{{ t('client.name') }} <span class="text-red-500">*</span></label>
          <input v-model="form.name" class="input" :placeholder="t('client.namePh')" required />
          <p class="hint">{{ t('client.nameHint') }}</p>
        </div>
        <div class="grid grid-cols-3 gap-3">
          <div class="col-span-2">
            <label class="label">{{ t('client.server') }} <span class="text-red-500">*</span></label>
            <input v-model="form.serverAddr" class="input" :placeholder="t('client.serverPh')" required />
            <p class="mt-2 text-xs leading-5 text-gray-400 dark:text-gray-500">{{ t('client.remoteHint') }}</p>
          </div>
          <div>
            <label class="label">{{ t('client.port') }} <span class="text-red-500">*</span></label>
            <input v-model="form.serverPort" class="input" placeholder="1194" required />
          </div>
        </div>
        <div>
          <label class="label">{{ t('client.ccd') }}</label>
          <textarea
            v-model="form.ccdConfig"
            class="input h-20 font-mono text-xs"
            placeholder="ifconfig-push 10.8.0.111 255.255.255.0&#10;iroute 192.168.0.0 255.255.0.0"
          ></textarea>
          <p class="hint">
            {{ t('client.ccdHint') }}
          </p>
        </div>
        <div>
          <label class="label">{{ t('client.custom') }}</label>
          <textarea
            v-model="form.config"
            class="input h-20 font-mono text-xs"
            placeholder="route 192.168.8.0 255.255.255.0&#10;redirect-gateway def1 ipv6 bypass-dhcp"
          ></textarea>
          <p class="hint">{{ t('client.customHint') }}</p>
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="form.mfa" type="checkbox" class="rounded" />
          {{ t('client.mfaOpt') }}
        </label>
        <p v-if="error" class="text-sm text-red-500">{{ error }}</p>
      </form>
      <template #footer>
        <button class="btn-secondary" @click="addOpen = false">{{ t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="saving" @click="onCreate">
          {{ saving ? t('client.creating') : t('client.create') }}
        </button>
      </template>
    </Modal>

    <!-- 查看/编辑 CCD 或客户端配置 -->
    <Modal
      :open="fileOpen"
      :title="`${fileType === 'ccd' ? t('client.ccdEditTitle') : t('client.cfgEditTitle')} - ${fileName}`"
      wide
      @close="fileOpen = false"
    >
      <textarea v-model="fileContent" class="input h-72 font-mono text-xs"></textarea>
      <p class="hint">
        {{
          fileType === 'ccd'
            ? t('client.ccdSaveHint')
            : t('client.cfgSaveHint')
        }}
      </p>
      <template #footer>
        <button class="btn-secondary" @click="fileOpen = false">{{ t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="saving" @click="onSaveFile">{{ t('common.save') }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import Modal from '../components/Modal.vue';
import {
  createClient,
  deleteClient,
  downloadUrl,
  getClientFile,
  listClients,
  putClientFile,
  setDefaultClient,
  type ClientConfig,
} from '../api';

const { t } = useI18n();

const clients = ref<ClientConfig[]>([]);
const addOpen = ref(false);
const saving = ref(false);
const error = ref('');

const form = reactive({ name: '', serverAddr: '', serverPort: '1194', ccdConfig: '', config: '', mfa: false });

const fileOpen = ref(false);
const fileName = ref('');
const fileType = ref<'ccd' | 'config'>('ccd');
const fileContent = ref('');

async function load() {
  const { data } = await listClients();
  clients.value = data;
}

async function onCreate() {
  error.value = '';
  saving.value = true;
  try {
    await createClient({
      name: form.name,
      serverAddr: form.serverAddr,
      serverPort: form.serverPort,
      ccdConfig: form.ccdConfig,
      config: form.config,
      mfa: form.mfa ? 'true' : 'false',
    });
    addOpen.value = false;
    Object.assign(form, { name: '', serverAddr: '', serverPort: '1194', ccdConfig: '', config: '', mfa: false });
    await load();
  } catch (e: any) {
    error.value = e.response?.data?.message ?? t('client.createFail');
  } finally {
    saving.value = false;
  }
}

async function openFile(name: string, type: 'ccd' | 'config') {
  fileName.value = name;
  fileType.value = type;
  const { data } = await getClientFile(name, type);
  fileContent.value = typeof data === 'string' ? data : (data.data ?? data.content ?? '');
  fileOpen.value = true;
}

async function onSaveFile() {
  saving.value = true;
  try {
    await putClientFile(fileName.value, fileType.value, fileContent.value);
    fileOpen.value = false;
  } finally {
    saving.value = false;
  }
}

async function onSetDefault(c: ClientConfig) {
  await setDefaultClient(c.fullName);
  await load();
}

async function onDelete(c: ClientConfig) {
  if (
    !confirm(
      t('client.deleteConfirm', { name: c.name })
    )
  )
    return;
  await deleteClient(c.name);
  await load();
}

onMounted(load);
</script>
