<template>
  <div
    class="flex min-h-screen items-center justify-center bg-gradient-to-br from-primary-50 via-white to-indigo-100 p-4 dark:from-gray-900 dark:via-gray-900 dark:to-gray-800"
  >
    <div class="card w-full max-w-sm p-8">
      <div class="mb-2 flex justify-end">
        <button class="text-xs text-gray-400 hover:text-primary-600" @click="switchLang">
          {{ locale === 'zh' ? 'English' : '中文' }}
        </button>
      </div>
      <div class="mb-8 text-center">
        <div
          class="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary-600 text-xl font-bold text-white"
        >
          O
        </div>
        <h1 class="text-xl font-semibold text-gray-900 dark:text-gray-100">{{ t('login.title') }}</h1>
        <p class="mt-1 text-sm text-gray-400">{{ t('login.subtitle') }}</p>
      </div>

      <form class="space-y-4" @submit.prevent="onSubmit">
        <div>
          <label class="label">{{ t('login.username') }}</label>
          <input v-model="form.username" class="input" autocomplete="username" required />
        </div>
        <div>
          <label class="label">{{ t('login.password') }}</label>
          <input
            v-model="form.password"
            type="password"
            class="input"
            autocomplete="current-password"
            required
          />
        </div>
        <div v-if="needMfa">
          <label class="label">{{ t('login.mfaCode') }}</label>
          <input v-model="passcode" class="input" :placeholder="t('login.mfaPlaceholder')" required />
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <input v-model="remember" type="checkbox" class="rounded" /> {{ t('login.remember') }}
        </label>
        <p v-if="error" class="text-sm text-red-500">{{ error }}</p>
        <button class="btn-primary w-full justify-center" :disabled="loading">
          {{ loading ? t('login.submitting') : needMfa ? t('login.mfaSubmit') : t('login.submit') }}
        </button>
      </form>
    </div>

    <CaptchaModal :open="captchaOpen" @close="captchaOpen = false" @done="onCaptcha" />
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import CaptchaModal from '../components/CaptchaModal.vue';
import { login } from '../api';
import { setLang } from '../i18n';

const { t, locale } = useI18n();
const router = useRouter();
const form = reactive({ username: '', password: '' });
const remember = ref(false);
const passcode = ref('');
const needMfa = ref(false);
const captchaOpen = ref(false);
const loading = ref(false);
const error = ref('');

const switchLang = () => setLang(locale.value === 'zh' ? 'en' : 'zh');

async function doLogin(extra: Record<string, string> = {}) {
  loading.value = true;
  error.value = '';
  try {
    const payload: Record<string, string> = {
      username: form.username,
      password: form.password,
      ...extra,
    };
    if (remember.value) payload.remember7d = 'on';
    if (needMfa.value && passcode.value) payload.passcode = passcode.value;

    const { data } = await login(payload);
    if (data.message === '需要MFA验证') {
      needMfa.value = true;
      return;
    }
    // 后端 redirect: "/admin" = 管理员,"/" = 普通账号(自助页)
    if (data.redirect === '/admin') {
      localStorage.setItem('role', 'admin');
      router.push('/dashboard');
    } else {
      localStorage.setItem('role', 'user');
      const first = data.user?.isFirstLogin ? '?first=1' : '';
      router.push('/portal' + first);
    }
  } catch (e: any) {
    const resp = e.response?.data;
    if (resp?.needCaptcha) {
      captchaOpen.value = true;
      return;
    }
    error.value = resp?.message ?? t('login.failed');
  } finally {
    loading.value = false;
  }
}

const onSubmit = () => doLogin();
function onCaptcha(key: string, dots: string) {
  captchaOpen.value = false;
  doLogin({ c_key: key, c_dots: dots });
}
</script>
