<template>
  <router-view />
</template>

<script setup lang="ts">
import { onMounted } from 'vue';

// 跟随本地偏好初始化暗色模式
onMounted(() => {
  const saved = localStorage.getItem('theme');
  const dark = saved ? saved === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.classList.toggle('dark', dark);
});
</script>
