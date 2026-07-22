<template>
  <div class="flex min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- 侧边栏 -->
    <aside
      class="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800"
    >
      <div class="flex h-16 items-center gap-2.5 border-b border-gray-200 px-5 dark:border-gray-700">
        <div
          class="flex h-9 w-9 items-center justify-center rounded-lg bg-primary-600 font-bold text-white"
        >
          O
        </div>
        <div>
          <div class="text-sm font-semibold text-gray-900 dark:text-gray-100">OpenVPN</div>
          <div class="text-xs text-gray-400">{{ t('nav.title') }}</div>
        </div>
      </div>
      <nav class="flex-1 space-y-1 px-3 py-4">
        <router-link
          v-for="item in menu"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
          active-class="!bg-primary-50 !text-primary-700 dark:!bg-primary-600/20 dark:!text-primary-100"
        >
          <span class="text-base">{{ item.icon }}</span>
          {{ t(item.label) }}
        </router-link>
      </nav>
      <div class="border-t border-gray-200 p-3 dark:border-gray-700">
        <button
          class="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
          @click="onLogout"
        >
          <span class="text-base">⏻</span> {{ t('nav.logout') }}
        </button>
      </div>
    </aside>

    <!-- 主区域 -->
    <div class="ml-60 flex flex-1 flex-col">
      <header
        class="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-gray-200 bg-white/80 px-6 backdrop-blur dark:border-gray-700 dark:bg-gray-800/80"
      >
        <h1 class="text-lg font-semibold text-gray-900 dark:text-gray-100">{{ pageTitle }}</h1>
        <div class="flex items-center gap-2">
          <button
            class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-gray-500 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"
            @click="switchLang"
          >
            {{ locale === 'zh' ? 'EN' : '中' }}
          </button>
          <button
            class="flex h-9 w-9 items-center justify-center rounded-lg text-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            @click="toggleDark"
          >
            {{ isDark ? '☀' : '☾' }}
          </button>
          <span
            class="flex h-9 w-9 items-center justify-center rounded-full bg-primary-100 text-sm font-semibold text-primary-700 dark:bg-primary-600/30 dark:text-primary-100"
            >A</span
          >
        </div>
      </header>
      <main class="flex-1 p-6">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { logout } from '../api';
import { setLang } from '../i18n';

const { t, locale } = useI18n();

const menu = [
  { path: '/dashboard', label: 'nav.dashboard', icon: '▦' },
  { path: '/accounts', label: 'nav.accounts', icon: '♟' },
  { path: '/clients', label: 'nav.clients', icon: '⎙' },
  { path: '/history', label: 'nav.history', icon: '≡' },
  { path: '/certs', label: 'nav.certs', icon: '⛨' },
  { path: '/system', label: 'nav.system', icon: '⚙' },
];

const route = useRoute();
const router = useRouter();
const pageTitle = computed(() => {
  const m = menu.find((m) => m.path === route.path);
  return m ? t(m.label) : '';
});

const switchLang = () => setLang(locale.value === 'zh' ? 'en' : 'zh');

const isDark = ref(document.documentElement.classList.contains('dark'));
function toggleDark() {
  isDark.value = !isDark.value;
  document.documentElement.classList.toggle('dark', isDark.value);
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light');
}

async function onLogout() {
  try {
    await logout();
  } finally {
    localStorage.removeItem('role');
    router.push('/login');
  }
}
</script>
