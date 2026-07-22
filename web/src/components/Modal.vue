<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div class="absolute inset-0 bg-black/50" @click="$emit('close')"></div>
        <div
          class="card relative z-10 w-full overflow-hidden"
          :class="wide ? 'max-w-2xl' : 'max-w-md'"
        >
          <div
            class="flex items-center justify-between border-b border-gray-200 px-5 py-4 dark:border-gray-700"
          >
            <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">{{ title }}</h3>
            <button
              class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              @click="$emit('close')"
            >
              ✕
            </button>
          </div>
          <div class="max-h-[70vh] overflow-y-auto px-5 py-4">
            <slot />
          </div>
          <div
            v-if="$slots.footer"
            class="flex justify-end gap-2 border-t border-gray-200 px-5 py-3.5 dark:border-gray-700"
          >
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
defineProps<{ open: boolean; title: string; wide?: boolean }>();
defineEmits<{ close: [] }>();
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.15s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
