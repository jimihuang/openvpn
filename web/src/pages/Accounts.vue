<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <select v-model.number="gid" class="input !w-48" @change="loadUsers">
          <option v-for="g in groups" :key="g.id" :value="g.id">{{ g.name }}</option>
        </select>
        <input v-model="keyword" class="input !w-56" :placeholder="t('acct.searchPh')" />
      </div>
      <button class="btn-primary" @click="openAdd">+ {{ t('acct.addTitle') }}</button>
    </div>

    <div class="card overflow-x-auto">
      <table class="w-full">
        <thead class="bg-gray-50 dark:bg-gray-900/40">
          <tr>
            <th class="th">{{ t('acct.username') }}</th>
            <th class="th">{{ t('acct.name') }}</th>
            <th class="th">{{ t('acct.email') }}</th>
            <th class="th">{{ t('acct.config') }}</th>
            <th class="th">{{ t('acct.fixedIp') }}</th>
            <th class="th">{{ t('acct.expire') }}</th>
            <th class="th">{{ t('acct.status') }}</th>
            <th class="th">{{ t('acct.mfa') }}</th>
            <th class="th">{{ t('common.actions') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <tr v-for="u in filtered" :key="u.id">
            <td class="td font-medium">{{ u.username }}</td>
            <td class="td">{{ u.name || '-' }}</td>
            <td class="td">{{ u.email || '-' }}</td>
            <td class="td">{{ u.ovpnConfig || '-' }}</td>
            <td class="td">{{ u.ipAddr || t('common.auto') }}</td>
            <td class="td">{{ u.expireDate || t('common.forever') }}</td>
            <td class="td">
              <button
                class="badge"
                :class="
                  u.isEnable
                    ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300'
                    : 'bg-gray-200 text-gray-500 dark:bg-gray-600 dark:text-gray-300'
                "
                :title="u.isEnable ? t('acct.enableTip') : t('acct.disableTip')"
                @click="toggleEnable(u)"
              >
                {{ u.isEnable ? t('common.enabled') : t('common.disabled') }}
              </button>
            </td>
            <td class="td">
              <span
                v-if="u.mfaSecret"
                class="badge bg-primary-100 text-primary-700 dark:bg-primary-600/20 dark:text-primary-100"
                >{{ t('acct.mfaSet') }}</span
              >
              <span v-else class="text-gray-400">-</span>
            </td>
            <td class="td space-x-2 whitespace-nowrap">
              <button class="text-primary-600 hover:underline" @click="openEdit(u)">
                {{ t('common.edit') }}
              </button>
              <button class="text-red-500 hover:underline" @click="onDelete(u)">
                {{ t('common.delete') }}
              </button>
            </td>
          </tr>
          <tr v-if="filtered.length === 0">
            <td colspan="9" class="td py-10 text-center text-gray-400">{{ t('acct.emptyList') }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 添加/编辑弹窗 -->
    <Modal
      :open="modalOpen"
      :title="editing ? t('acct.editTitle') : t('acct.addTitle')"
      @close="modalOpen = false"
    >
      <form class="space-y-4" @submit.prevent="onSave">
        <div>
          <label class="label">{{ t('acct.username') }} <span class="text-red-500">*</span></label>
          <input v-model="form.username" class="input" :disabled="!!editing" required />
        </div>
        <div>
          <label class="label">
            {{ editing ? t('acct.resetPass') : t('acct.password') }}
            <span v-if="!editing" class="text-red-500">*</span>
          </label>
          <div class="flex gap-2">
            <input v-model="form.password" class="input" :required="!editing" />
            <button type="button" class="btn-secondary shrink-0" @click="genPass">
              {{ t('common.generate') }}
            </button>
          </div>
          <p class="hint">{{ passwordHint }}</p>
        </div>
        <div>
          <label class="label">{{ t('acct.name') }}</label>
          <input v-model="form.name" class="input" />
        </div>
        <div>
          <label class="label">{{ t('acct.email') }}({{ t('common.optional') }})</label>
          <input v-model="form.email" type="email" class="input" :placeholder="t('acct.emailPh')" />
        </div>
        <div>
          <label class="label">{{ t('acct.config') }} <span class="text-red-500">*</span></label>
          <select v-model="form.ovpnConfig" class="input" required>
            <option v-for="c in clients" :key="c.fullName" :value="c.fullName">{{ c.name }}</option>
          </select>
          <p v-if="clients.length === 0" class="hint !text-amber-500">{{ t('acct.noConfig') }}</p>
        </div>
        <div>
          <label class="label">{{ t('acct.fixedIp') }}({{ t('common.optional') }})</label>
          <input v-model="form.ipAddr" class="input" :placeholder="t('acct.fixedIpPh')" />
          <p class="hint">{{ t('acct.fixedIpHint') }}</p>
        </div>
        <div>
          <label class="label">
            {{ editing ? t('acct.expire') + ' / ' + t('acct.renew') : t('acct.expire') }}
            ({{ t('common.optional') }})
          </label>
          <!-- 快速选择: 30/60/90 天、1 年;编辑时从当前到期时间(未过期)或现在起顺延 -->
          <div class="mb-2 flex flex-wrap gap-2">
            <button
              v-for="d in [30, 60, 90]"
              :key="d"
              type="button"
              class="btn-secondary !px-2.5 !py-1 text-xs"
              @click="quickExpire(d)"
            >
              +{{ d }} {{ t('acct.days') }}
            </button>
            <button type="button" class="btn-secondary !px-2.5 !py-1 text-xs" @click="quickExpire(365)">
              +{{ t('acct.oneYear') }}
            </button>
            <button type="button" class="btn-secondary !px-2.5 !py-1 text-xs" @click="form.expireDate = ''">
              {{ t('common.forever') }}
            </button>
          </div>
          <input v-model="form.expireDate" type="datetime-local" class="input" />
          <p class="hint">{{ t('acct.expireHint') }}</p>
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="form.isFirstLogin" type="checkbox" class="rounded" />
          {{ t('acct.firstLogin') }}
        </label>
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="form.sendNotifyEmail" type="checkbox" class="rounded" :disabled="!form.email" />
          {{ t('acct.notify') }}
        </label>
        <p v-if="error" class="text-sm text-red-500">{{ error }}</p>
      </form>
      <template #footer>
        <button class="btn-secondary" @click="modalOpen = false">{{ t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="saving" @click="onSave">
          {{ saving ? t('common.loading') : t('common.save') }}
        </button>
      </template>
    </Modal>

    <Modal :open="credentialOpen" :title="t('acct.credentialTitle')" @close="closeCredentials">
      <div class="space-y-4">
        <p class="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-700 dark:bg-amber-500/10">
          {{ t('acct.credentialWarning') }}
        </p>
        <div>
          <label class="label">{{ t('acct.username') }}</label>
          <div class="flex gap-2">
            <input :value="credentials.username" class="input font-mono" readonly />
            <button class="btn-secondary shrink-0" @click="copyCredential(credentials.username, 'username')">
              {{ copiedField === 'username' ? t('acct.copied') : t('acct.copy') }}
            </button>
          </div>
        </div>
        <div>
          <label class="label">{{ t('acct.initialPassword') }}</label>
          <div class="flex gap-2">
            <input :value="credentials.password" class="input font-mono" readonly />
            <button class="btn-secondary shrink-0" @click="copyCredential(credentials.password, 'password')">
              {{ copiedField === 'password' ? t('acct.copied') : t('acct.copy') }}
            </button>
          </div>
        </div>
        <div>
          <label class="label">{{ t('acct.webLoginUrl') }}</label>
          <div class="flex gap-2">
            <input :value="credentials.loginUrl" class="input font-mono" readonly />
            <button class="btn-secondary shrink-0" @click="copyCredential(credentials.loginUrl, 'url')">
              {{ copiedField === 'url' ? t('acct.copied') : t('acct.copy') }}
            </button>
          </div>
        </div>
        <button class="btn-primary w-full justify-center" @click="copyAllCredentials">
          {{ copiedField === 'all' ? t('acct.copiedAll') : t('acct.copyAll') }}
        </button>
      </div>
      <template #footer>
        <button class="btn-primary" @click="closeCredentials">{{ t('common.confirm') }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import Modal from '../components/Modal.vue';
import {
  createUser,
  deleteUser,
  getPasswordPolicy,
  listClients,
  listGroups,
  listGroupUsers,
  randomPassword,
  passwordValid,
  updateUser,
  type ClientConfig,
  type VpnGroup,
  type VpnUser,
} from '../api';

const { t } = useI18n();

const groups = ref<VpnGroup[]>([]);
const users = ref<VpnUser[]>([]);
const clients = ref<ClientConfig[]>([]);
const gid = ref(1);
const keyword = ref('');

const modalOpen = ref(false);
const editing = ref<VpnUser | null>(null);
const saving = ref(false);
const error = ref('');
const passwordPolicyEnforced = ref(true);
const passwordHint = computed(() =>
  t(passwordPolicyEnforced.value ? 'acct.passHint' : 'acct.passHintRelaxed')
);

const credentialOpen = ref(false);
const copiedField = ref('');
const credentials = reactive({ username: '', password: '', loginUrl: '' });

const emptyForm = () => ({
  username: '',
  password: '',
  name: '',
  email: '',
  ovpnConfig: '',
  ipAddr: '',
  expireDate: '',
  isFirstLogin: true,
  sendNotifyEmail: false,
});
const form = reactive(emptyForm());

const filtered = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  if (!k) return users.value;
  return users.value.filter((u) =>
    [u.username, u.name, u.email].some((f) => f?.toLowerCase().includes(k))
  );
});

const genPass = () => (form.password = randomPassword());

// 到期时间快速顺延:基准取"当前表单里的到期时间(未过期)"或现在,加 N 天
function quickExpire(days: number) {
  const base =
    form.expireDate && new Date(form.expireDate) > new Date()
      ? new Date(form.expireDate)
      : new Date();
  base.setDate(base.getDate() + days);
  const pad = (n: number) => String(n).padStart(2, '0');
  form.expireDate = `${base.getFullYear()}-${pad(base.getMonth() + 1)}-${pad(base.getDate())}T${pad(base.getHours())}:${pad(base.getMinutes())}`;
}

async function loadUsers() {
  const { data } = await listGroupUsers(gid.value);
  users.value = data.users;
}

function openAdd() {
  editing.value = null;
  Object.assign(form, emptyForm());
  form.password = randomPassword();
  const defaultClient = clients.value.find((client) => client.isDefault) ?? clients.value[0];
  if (defaultClient) form.ovpnConfig = defaultClient.fullName;
  error.value = '';
  modalOpen.value = true;
}

function openEdit(u: VpnUser) {
  editing.value = u;
  Object.assign(form, emptyForm(), {
    username: u.username,
    password: '',
    name: u.name,
    email: u.email,
    ovpnConfig: u.ovpnConfig,
    ipAddr: u.ipAddr ?? '',
    expireDate: u.expireDate ? u.expireDate.replace('/', 'T').slice(0, 16) : '',
    isFirstLogin: u.isFirstLogin,
  });
  error.value = '';
  modalOpen.value = true;
}

// 后端到期时间格式: 2025-12-01/00:00:00
const toExpireDate = (v: string) => (v ? `${v.slice(0, 10)}/${v.slice(11)}:00` : '');

async function onSave() {
  error.value = '';
  if (!editing.value && !form.username) {
    error.value = t('acct.usernameRequired');
    return;
  }
  if (form.password && !passwordValid(form.password, passwordPolicyEnforced.value)) {
    error.value = passwordHint.value;
    return;
  }
  saving.value = true;
  try {
    const editingUser = editing.value;
    const creating = !editingUser;
    const createdUsername = form.username;
    const createdPassword = form.password;
    const payload: Record<string, unknown> = {
      username: form.username,
      name: form.name,
      email: form.email,
      gid: gid.value,
      ovpnConfig: form.ovpnConfig,
      ipAddr: form.ipAddr,
      expireDate: toExpireDate(form.expireDate),
      isFirstLogin: form.isFirstLogin,
      sendNotifyEmail: form.sendNotifyEmail ? 'true' : 'false',
    };
    if (form.password) payload.password = form.password;

    if (editingUser) {
      payload.id = editingUser.id;
      await updateUser(payload);
    } else {
      await createUser(payload);
    }
    modalOpen.value = false;
    await loadUsers();
    if (creating) {
      Object.assign(credentials, {
        username: createdUsername,
        password: createdPassword,
        loginUrl: new URL('/login', window.location.origin).toString(),
      });
      copiedField.value = '';
      credentialOpen.value = true;
    }
  } catch (e: any) {
    error.value = e.response?.data?.message ?? t('common.saveFail');
  } finally {
    saving.value = false;
  }
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // HTTP deployments may not expose the Clipboard API; fall back below.
    }
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
}

async function copyCredential(value: string, field: string) {
  await copyText(value);
  copiedField.value = field;
  setTimeout(() => (copiedField.value = ''), 1500);
}

async function copyAllCredentials() {
  await copyText(
    `${t('acct.username')}: ${credentials.username}\n${t('acct.initialPassword')}: ${credentials.password}\n${t('acct.webLoginUrl')}: ${credentials.loginUrl}`
  );
  copiedField.value = 'all';
  setTimeout(() => (copiedField.value = ''), 1500);
}

function closeCredentials() {
  credentialOpen.value = false;
  credentials.password = '';
  copiedField.value = '';
}

async function toggleEnable(u: VpnUser) {
  await updateUser({ id: u.id, isEnable: !u.isEnable });
  await loadUsers();
}

async function onDelete(u: VpnUser) {
  if (!confirm(t('acct.deleteConfirm', { name: u.username }))) return;
  await deleteUser(u.id);
  await loadUsers();
}

onMounted(async () => {
  const [g, c, policy] = await Promise.all([listGroups(), listClients(), getPasswordPolicy()]);
  groups.value = g.data;
  clients.value = c.data;
  passwordPolicyEnforced.value = policy.data.enforced;
  if (groups.value.length > 0) gid.value = groups.value[0].id;
  await loadUsers();
});
</script>
