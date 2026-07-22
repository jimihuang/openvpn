<template>
  <Modal :open="open" :title="t('login.captchaTitle')" @close="$emit('close')">
    <p class="mb-3 text-sm text-gray-500 dark:text-gray-400">
      {{ t('login.captchaTip') }}
    </p>
    <div v-if="master" class="space-y-3">
      <div class="relative inline-block">
        <img :src="imgSrc(master)" class="rounded-lg" @click="onClick" />
        <span
          v-for="(d, i) in dots"
          :key="i"
          class="pointer-events-none absolute flex h-6 w-6 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full bg-primary-600 text-xs font-bold text-white"
          :style="{ left: d.x + 'px', top: d.y + 'px' }"
          >{{ i + 1 }}</span
        >
      </div>
      <div class="flex items-center gap-3">
        <img v-if="thumb" :src="imgSrc(thumb)" class="h-10 rounded" />
        <button class="btn-secondary" @click="refresh">{{ t('login.captchaRefresh') }}</button>
        <button class="btn-secondary" @click="dots = []">{{ t('login.captchaReset') }}</button>
      </div>
    </div>
    <template #footer>
      <button class="btn-secondary" @click="$emit('close')">{{ t('common.cancel') }}</button>
      <button class="btn-primary" :disabled="dots.length === 0" @click="confirm">{{ t('common.confirm') }}</button>
    </template>
  </Modal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import Modal from './Modal.vue';
import { getCaptcha } from '../api';

const { t } = useI18n();
const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{ close: []; done: [key: string, dots: string] }>();

const key = ref('');
const master = ref('');
const thumb = ref('');
const dots = ref<{ x: number; y: number }[]>([]);

const imgSrc = (b64: string) => (b64.startsWith('data:') ? b64 : `data:image/png;base64,${b64}`);

async function refresh() {
  dots.value = [];
  const { data } = await getCaptcha();
  key.value = data.key;
  master.value = data.master;
  thumb.value = data.thumb;
}

function onClick(e: MouseEvent) {
  const rect = (e.target as HTMLImageElement).getBoundingClientRect();
  dots.value.push({ x: Math.round(e.clientX - rect.left), y: Math.round(e.clientY - rect.top) });
}

function confirm() {
  emit('done', key.value, JSON.stringify(dots.value));
}

watch(
  () => props.open,
  (v) => v && refresh()
);
</script>
