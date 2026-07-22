<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('cert.manageHint') }}</p>
      <div class="flex flex-wrap gap-2">
        <button class="btn-secondary" @click="renewOpen = true">{{ t('cert.renewTitle') }}</button>
        <button class="btn-secondary" :disabled="!!actionBusy" @click="onRestart">
          {{ actionBusy === 'restart' ? t('common.loading') : t('cert.restart') }}
        </button>
        <button class="btn-primary" @click="openMaterial">{{ t('cert.materialTitle') }}</button>
      </div>
    </div>

    <p
      v-if="actionMessage"
      class="rounded-lg px-3 py-2 text-sm"
      :class="actionOk ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-600'"
    >
      {{ actionMessage }}
    </p>

    <div class="card overflow-x-auto">
      <table class="w-full">
        <thead class="bg-gray-50 dark:bg-gray-900/40">
          <tr>
            <th class="th">{{ t('cert.name') }}</th>
            <th class="th">{{ t('cert.type') }}</th>
            <th class="th">{{ t('cert.subject') }}</th>
            <th class="th">{{ t('cert.issuer') }}</th>
            <th class="th">{{ t('cert.notAfter') }}</th>
            <th class="th">{{ t('cert.expiresIn') }}</th>
            <th class="th">{{ t('cert.status') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <tr v-for="c in certs" :key="c.name + c.type">
            <td class="td font-medium">{{ c.name }}</td>
            <td class="td">{{ c.type }}</td>
            <td class="td">{{ c.subject }}</td>
            <td class="td">{{ c.issuer }}</td>
            <td class="td">{{ c.notAfter }}</td>
            <td class="td">{{ c.expiresIn }}</td>
            <td class="td">
              <span class="badge" :class="statusClass(c.status)">{{ c.status }}</span>
            </td>
          </tr>
          <tr v-if="certs.length === 0">
            <td colspan="7" class="td py-10 text-center text-gray-400">{{ t('common.empty') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <Modal :open="materialOpen" :title="t('cert.materialTitle')" wide @close="materialOpen = false">
      <div class="space-y-4">
        <div>
          <label class="label">{{ t('cert.materialType') }}</label>
          <select v-model="materialType" class="input" @change="loadMaterial">
            <option value="ca">{{ t('cert.typeCa') }}</option>
            <option value="crl">{{ t('cert.typeCrl') }}</option>
            <option value="server">{{ t('cert.typeServerCert') }}</option>
            <option value="client">{{ t('cert.typeClientCert') }}</option>
          </select>
        </div>

        <div v-if="materialType === 'client'">
          <label class="label">{{ t('cert.clientName') }}</label>
          <select v-model="clientName" class="input" @change="loadMaterial">
            <option v-for="client in clients" :key="client.name" :value="client.name">
              {{ client.name }}
            </option>
          </select>
          <p v-if="clients.length === 0" class="hint !text-amber-600">{{ t('cert.noClients') }}</p>
        </div>

        <div>
          <label class="label">
            {{ materialType === 'crl' ? t('cert.crlPem') : t('cert.certPem') }}
          </label>
          <textarea
            v-model="materialContent"
            class="input h-64 font-mono text-xs"
            spellcheck="false"
            :placeholder="materialType === 'crl' ? '-----BEGIN X509 CRL-----' : '-----BEGIN CERTIFICATE-----'"
          ></textarea>
        </div>

        <div v-if="materialType === 'server' || materialType === 'client'">
          <label class="label">{{ t('cert.keyPem') }}</label>
          <textarea
            v-model="privateKey"
            class="input h-40 font-mono text-xs"
            spellcheck="false"
            placeholder="-----BEGIN PRIVATE KEY-----"
          ></textarea>
          <p class="hint">{{ t('cert.keyOptionalHint') }}</p>
        </div>

        <p class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-500/10">
          {{ t('cert.replaceWarning') }}
        </p>
        <p v-if="materialMessage" class="text-sm" :class="materialOk ? 'text-emerald-600' : 'text-red-500'">
          {{ materialMessage }}
        </p>
      </div>
      <template #footer>
        <button class="btn-secondary" @click="materialOpen = false">{{ t('common.cancel') }}</button>
        <button
          class="btn-primary"
          :disabled="materialBusy || !materialContent || (materialType === 'client' && !clientName)"
          @click="onReplace"
        >
          {{ materialBusy ? t('common.loading') : t('cert.replace') }}
        </button>
      </template>
    </Modal>

    <Modal :open="renewOpen" :title="t('cert.renewTitle')" @close="renewOpen = false">
      <div class="space-y-4">
        <div>
          <label class="label">{{ t('cert.renewDays') }}</label>
          <input v-model.number="renewDays" type="number" min="1" max="36500" class="input" />
        </div>
        <p class="hint">{{ t('cert.renewHint') }}</p>
      </div>
      <template #footer>
        <button class="btn-secondary" @click="renewOpen = false">{{ t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="!!actionBusy || renewDays < 1" @click="onRenew">
          {{ actionBusy === 'renew' ? t('common.loading') : t('common.confirm') }}
        </button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import Modal from '../components/Modal.vue';
import {
  getCertMaterial,
  listCerts,
  listClients,
  renewCertificates,
  replaceCertMaterial,
  restartOpenVPN,
  type CertItem,
  type ClientConfig,
} from '../api';

const { t } = useI18n();

const certs = ref<CertItem[]>([]);
const clients = ref<ClientConfig[]>([]);
const materialOpen = ref(false);
const materialType = ref<'ca' | 'crl' | 'server' | 'client'>('ca');
const clientName = ref('');
const materialContent = ref('');
const privateKey = ref('');
const materialBusy = ref(false);
const materialMessage = ref('');
const materialOk = ref(false);

const renewOpen = ref(false);
const renewDays = ref(365);
const actionBusy = ref('');
const actionMessage = ref('');
const actionOk = ref(false);

async function load() {
  const [certResponse, clientResponse] = await Promise.all([listCerts(), listClients()]);
  certs.value = certResponse.data;
  clients.value = clientResponse.data;
  if (!clientName.value && clients.value.length > 0) clientName.value = clients.value[0].name;
}

function statusClass(status: string) {
  if (status === '正常' || status.toLowerCase() === 'valid') {
    return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300';
  }
  if (status.includes('即将') || status.toLowerCase().includes('expiring')) {
    return 'bg-amber-100 text-amber-700 dark:bg-amber-500/20 dark:text-amber-300';
  }
  return 'bg-red-100 text-red-600 dark:bg-red-500/20 dark:text-red-300';
}

async function openMaterial() {
  materialType.value = 'ca';
  privateKey.value = '';
  materialMessage.value = '';
  materialOpen.value = true;
  await loadMaterial();
}

async function loadMaterial() {
  materialContent.value = '';
  privateKey.value = '';
  materialMessage.value = '';
  if (materialType.value === 'client' && !clientName.value) return;
  materialBusy.value = true;
  try {
    const { data } = await getCertMaterial(materialType.value, clientName.value || undefined);
    materialContent.value = data.content;
  } catch (e: any) {
    materialMessage.value = e.response?.data?.message ?? t('cert.loadFail');
    materialOk.value = false;
  } finally {
    materialBusy.value = false;
  }
}

async function onReplace() {
  if (!confirm(t('cert.replaceConfirm'))) return;
  materialBusy.value = true;
  materialMessage.value = '';
  try {
    const { data } = await replaceCertMaterial({
      type: materialType.value,
      name: materialType.value === 'client' ? clientName.value : undefined,
      content: materialContent.value,
      privateKey: privateKey.value || undefined,
    });
    materialOk.value = true;
    materialMessage.value = data.message;
    privateKey.value = '';
    await load();
  } catch (e: any) {
    materialOk.value = false;
    materialMessage.value = e.response?.data?.message ?? t('cert.replaceFail');
  } finally {
    materialBusy.value = false;
  }
}

async function onRenew() {
  actionBusy.value = 'renew';
  actionMessage.value = '';
  try {
    const { data } = await renewCertificates(renewDays.value);
    actionOk.value = true;
    actionMessage.value = data.message;
    renewOpen.value = false;
    await load();
  } catch (e: any) {
    actionOk.value = false;
    actionMessage.value = e.response?.data?.message ?? t('cert.renewFail');
  } finally {
    actionBusy.value = '';
  }
}

async function onRestart() {
  if (!confirm(t('cert.restartConfirm'))) return;
  actionBusy.value = 'restart';
  actionMessage.value = '';
  try {
    const { data } = await restartOpenVPN();
    actionOk.value = true;
    actionMessage.value = data.message;
  } catch (e: any) {
    actionOk.value = false;
    actionMessage.value = e.response?.data?.message ?? t('cert.restartFail');
  } finally {
    actionBusy.value = '';
  }
}

onMounted(load);
</script>
