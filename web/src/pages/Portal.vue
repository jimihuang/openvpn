<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <header
      class="flex h-16 items-center justify-between border-b border-gray-200 bg-white px-6 dark:border-gray-700 dark:bg-gray-800"
    >
      <div class="flex items-center gap-2.5">
        <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-primary-600 font-bold text-white">O</div>
        <span class="font-semibold text-gray-900 dark:text-gray-100">{{ t('portal.title') }}</span>
      </div>
      <div class="flex items-center gap-2">
        <button
          class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-gray-500 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
          @click="switchLang"
        >
          {{ locale === 'zh' ? 'EN' : '中' }}
        </button>
        <button class="btn-secondary" @click="onLogout">{{ t('nav.logout') }}</button>
      </div>
    </header>

    <main class="mx-auto max-w-3xl space-y-6 p-6">
      <p v-if="user" class="text-lg font-medium text-gray-900 dark:text-gray-100">
        {{ t('portal.welcome', { name: user.name || user.username }) }}
      </p>

      <!-- 账号信息 -->
      <div class="card p-6">
        <h2 class="mb-4 font-semibold text-gray-900 dark:text-gray-100">{{ t('portal.account') }}</h2>
        <dl v-if="user" class="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div>
            <dt class="text-gray-400">{{ t('portal.username') }}</dt>
            <dd class="mt-0.5 font-medium text-gray-800 dark:text-gray-200">{{ user.username }}</dd>
          </div>
          <div>
            <dt class="text-gray-400">{{ t('portal.name') }}</dt>
            <dd class="mt-0.5 font-medium text-gray-800 dark:text-gray-200">{{ user.name || '-' }}</dd>
          </div>
          <div>
            <dt class="text-gray-400">{{ t('portal.email') }}</dt>
            <dd class="mt-0.5 font-medium text-gray-800 dark:text-gray-200">{{ user.email || '-' }}</dd>
          </div>
          <div>
            <dt class="text-gray-400">{{ t('portal.expire') }}</dt>
            <dd class="mt-0.5 font-medium text-gray-800 dark:text-gray-200">
              {{ user.expireDate || t('common.forever') }}
            </dd>
          </div>
        </dl>
      </div>

      <!-- 配置文件下载 -->
      <div class="card p-6">
        <h2 class="mb-2 font-semibold text-gray-900 dark:text-gray-100">{{ t('portal.config') }}</h2>
        <p class="mb-4 text-sm text-gray-500 dark:text-gray-400">{{ t('portal.downloadHint') }}</p>
        <button class="btn-primary" :disabled="downloading" @click="onDownload">
          ⇩ {{ t('portal.downloadCfg') }}
        </button>
        <p v-if="downloadError" class="mt-2 text-sm text-red-500">{{ downloadError }}</p>
      </div>

      <!-- 修改密码 -->
      <div class="card p-6">
        <h2 class="mb-2 font-semibold text-gray-900 dark:text-gray-100">{{ t('portal.changePass') }}</h2>
        <p v-if="isFirst" class="mb-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-600 dark:bg-amber-500/10">
          {{ t('portal.firstLoginTip') }}
        </p>
        <form class="max-w-sm space-y-3" @submit.prevent="onChangePass">
          <div v-if="!isFirst">
            <label class="label">{{ t('portal.currentPass') }}</label>
            <input v-model="pass.current" type="password" class="input" required />
          </div>
          <div>
            <label class="label">{{ t('portal.newPass') }}</label>
            <div class="flex gap-2">
              <input v-model="pass.next" :type="showGeneratedPassword ? 'text' : 'password'" class="input" required />
              <button type="button" class="btn-secondary shrink-0" @click="generatePass">
                {{ t('portal.randomPass') }}
              </button>
            </div>
            <p class="hint">{{ t(passwordPolicyEnforced ? 'portal.passRule' : 'portal.passRuleRelaxed') }}</p>
          </div>
          <div>
            <label class="label">{{ t('portal.confirmPass') }}</label>
            <input v-model="pass.confirm" type="password" class="input" required />
          </div>
          <p v-if="passError" class="text-sm text-red-500">{{ passError }}</p>
          <p v-if="passOk" class="text-sm text-emerald-600">{{ t('portal.passOk') }}</p>
          <button class="btn-primary" :disabled="passSaving">{{ t('common.save') }}</button>
        </form>
      </div>

      <!-- MFA -->
      <div class="card p-6">
        <div class="mb-3 flex items-center justify-between">
          <h2 class="font-semibold text-gray-900 dark:text-gray-100">{{ t('portal.mfa') }}</h2>
          <span
            class="badge"
            :class="
              mfaEnable
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300'
                : 'bg-gray-200 text-gray-500 dark:bg-gray-600 dark:text-gray-300'
            "
          >
            {{ mfaEnable ? t('portal.mfaOn') : t('portal.mfaOff') }}
          </span>
        </div>

        <div v-if="!mfaEnable && mfaSecret" class="space-y-3">
          <div v-if="qrCode" class="flex justify-center sm:justify-start">
            <img :src="qrCode" :alt="t('portal.mfaQr')" class="h-52 w-52 rounded-lg bg-white p-2" />
          </div>
          <div>
            <label class="label">{{ t('portal.mfaSecret') }}</label>
            <div class="flex gap-2">
              <input :value="mfaSecret" class="input font-mono" readonly />
              <button class="btn-secondary shrink-0" @click="copy(mfaSecret)">{{ copied ? t('portal.copied') : '⧉' }}</button>
            </div>
            <p class="hint">{{ t('portal.mfaUri') }}: <code class="break-all">{{ otpauthUri }}</code></p>
          </div>
          <div class="max-w-sm">
            <label class="label">{{ t('portal.mfaCode') }}</label>
            <div class="flex gap-2">
              <input v-model="mfaCode" class="input" maxlength="6" />
              <button class="btn-primary shrink-0" :disabled="mfaCode.length !== 6" @click="onEnableMfa">
                {{ t('portal.mfaEnable') }}
              </button>
            </div>
          </div>
          <p v-if="mfaError" class="text-sm text-red-500">{{ mfaError }}</p>
        </div>

        <button v-if="mfaEnable" class="btn-danger" @click="onDisableMfa">{{ t('portal.mfaDisable') }}</button>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import {
  disableMfa,
  enableMfa,
  getMfa,
  getPasswordPolicy,
  getUserConfig,
  getUserInfo,
  logout,
  modifyPass,
  passwordValid,
  randomPassword,
  type VpnUser,
} from '../api';
import { setLang } from '../i18n';

const { t, locale } = useI18n();
const route = useRoute();
const router = useRouter();

const user = ref<VpnUser>();
const isFirst = ref(route.query.first === '1');

const downloading = ref(false);
const downloadError = ref('');

const pass = reactive({ current: '', next: '', confirm: '' });
const passError = ref('');
const passOk = ref(false);
const passSaving = ref(false);
const showGeneratedPassword = ref(false);
const passwordPolicyEnforced = ref(true);

const mfaEnable = ref(false);
const mfaSecret = ref('');
const mfaCode = ref('');
const mfaError = ref('');
const copied = ref(false);

const qrCode = ref('');
const serverOtpauthUri = ref('');

const otpauthUri = computed(
	() => serverOtpauthUri.value || `otpauth://totp/openvpn-web:${user.value?.username}?secret=${mfaSecret.value}&issuer=openvpn-web`
);

const switchLang = () => setLang(locale.value === 'zh' ? 'en' : 'zh');

function generatePass() {
  const generated = randomPassword();
  pass.next = generated;
  pass.confirm = generated;
  showGeneratedPassword.value = true;
  passError.value = '';
  passOk.value = false;
}

async function copy(text: string) {
  await navigator.clipboard.writeText(text);
  copied.value = true;
  setTimeout(() => (copied.value = false), 1500);
}

async function onDownload() {
  downloading.value = true;
  downloadError.value = '';
  try {
    const { data } = await getUserConfig();
    const blob = new Blob([data.content], { type: 'application/x-openvpn-profile' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = data.filename;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e: any) {
    downloadError.value = e.response?.data?.message ?? t('portal.noConfig');
  } finally {
    downloading.value = false;
  }
}

async function onChangePass() {
  passError.value = '';
  passOk.value = false;
  if (pass.next !== pass.confirm) {
    passError.value = t('portal.passMismatch');
    return;
  }
  if (!passwordValid(pass.next, passwordPolicyEnforced.value)) {
    passError.value = t(passwordPolicyEnforced.value ? 'portal.passRule' : 'portal.passRuleRelaxed');
    return;
  }
  passSaving.value = true;
  try {
    const payload: Record<string, unknown> = {
      id: user.value?.id,
      password: pass.next,
      isFirstLogin: 'false',
    };
    if (!isFirst.value) payload.currentPass = pass.current;
    await modifyPass(payload);
    passOk.value = true;
    isFirst.value = false;
    Object.assign(pass, { current: '', next: '', confirm: '' });
    showGeneratedPassword.value = false;
  } catch (e: any) {
    passError.value = e.response?.data?.message ?? t('common.saveFail');
  } finally {
    passSaving.value = false;
  }
}

async function loadMfa() {
  const { data } = await getMfa();
  mfaEnable.value = data.mfaEnable;
  mfaSecret.value = data.user.mfaSecret;
  qrCode.value = data.qrCode ?? '';
  serverOtpauthUri.value = data.otpauthUri ?? '';
}

async function onEnableMfa() {
  mfaError.value = '';
  try {
    await enableMfa(user.value!.id, mfaSecret.value, mfaCode.value);
    mfaCode.value = '';
    await loadMfa();
  } catch (e: any) {
    mfaError.value = e.response?.data?.message ?? t('common.saveFail');
  }
}

async function onDisableMfa() {
  if (!confirm(t('portal.mfaDisableConfirm'))) return;
  await disableMfa(user.value!.id);
  await loadMfa();
}

async function onLogout() {
  try {
    await logout();
  } finally {
    localStorage.removeItem('role');
    router.push('/login');
  }
}

onMounted(async () => {
  const [userResponse, policyResponse] = await Promise.all([getUserInfo(), getPasswordPolicy()]);
  user.value = userResponse.data;
  passwordPolicyEnforced.value = policyResponse.data.enforced;
  if (userResponse.data.isFirstLogin) isFirst.value = true;
  await loadMfa();
});
</script>
