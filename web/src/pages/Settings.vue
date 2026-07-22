<template>
  <div v-if="conf" class="max-w-3xl space-y-6">
    <!-- 基础设置 -->
    <section class="card p-6">
      <h2 class="mb-4 font-semibold text-gray-900 dark:text-gray-100">{{ t('sys.base') }}</h2>
      <div class="space-y-4">
        <div>
          <label class="label">{{ t('sys.siteUrl') }}</label>
          <input v-model="base.site_url" class="input" />
          <p class="hint">{{ t('sys.siteUrlHint') }}</p>
        </div>
        <div class="rounded-lg border border-gray-200 p-4 dark:border-gray-700">
          <label class="flex items-center gap-2 text-sm font-medium text-gray-700 dark:text-gray-200">
            <input v-model="base.https_enabled" type="checkbox" class="rounded" />
            {{ t('sys.httpsEnable') }}
          </label>
          <p class="hint ml-6">{{ t('sys.httpsHint') }}</p>
          <div v-if="base.https_enabled" class="mt-4 space-y-4">
            <div
              v-if="base.https_certificate_configured"
              class="rounded-lg bg-emerald-50 px-3 py-2 text-xs leading-5 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300"
            >
              <div>{{ t('sys.httpsConfigured') }}</div>
              <div v-if="base.https_certificate_subject">{{ t('sys.httpsSubject') }}: {{ base.https_certificate_subject }}</div>
              <div v-if="base.https_certificate_not_after">{{ t('sys.httpsNotAfter') }}: {{ base.https_certificate_not_after }}</div>
            </div>
            <div>
              <label class="label">{{ t('sys.httpsCertificate') }}</label>
              <textarea
                v-model="httpsCertificate"
                class="input h-36 font-mono text-xs leading-5"
                spellcheck="false"
                placeholder="-----BEGIN CERTIFICATE-----"
              ></textarea>
              <p class="hint">{{ t('sys.httpsCertificateHint') }}</p>
            </div>
            <div>
              <label class="label">{{ t('sys.httpsPrivateKey') }}</label>
              <textarea
                v-model="httpsPrivateKey"
                class="input h-36 font-mono text-xs leading-5"
                spellcheck="false"
                autocomplete="off"
                placeholder="-----BEGIN PRIVATE KEY-----"
              ></textarea>
              <p class="hint">{{ t('sys.httpsPrivateKeyHint') }}</p>
            </div>
            <p class="rounded-lg bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">
              {{ t('sys.httpsRestartHint') }}
            </p>
          </div>
        </div>
        <div>
          <label class="label">{{ t('sys.adminPass') }}</label>
          <input v-model="adminPass" type="password" class="input" :placeholder="t('sys.adminPassPh')" />
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="label">{{ t('sys.maxDup') }}</label>
            <input v-model.number="base.max_duplicate_login" type="number" class="input" />
            <p class="hint">{{ t('sys.maxDupHint') }}</p>
          </div>
          <div>
            <label class="label">{{ t('sys.historyDays') }}</label>
            <input v-model.number="base.history_max_days" type="number" class="input" />
          </div>
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="base.auto_update_ovpn_config" type="checkbox" class="rounded" />
          {{ t('sys.autoUpdate') }}
        </label>
        <div>
          <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
            <input v-model="base.enforce_password_policy" type="checkbox" class="rounded" />
            {{ t('sys.enforcePasswordPolicy') }}
          </label>
          <p class="hint ml-6">{{ t('sys.enforcePasswordPolicyHint') }}</p>
        </div>
      </div>
      <SectionSave :busy="busy === 'base'" :ok="okSection === 'base'" @save="saveBase" />
    </section>

    <!-- OpenVPN 设置 -->
    <section class="card p-6">
      <h2 class="mb-4 font-semibold text-gray-900 dark:text-gray-100">{{ t('sys.openvpn') }}</h2>
      <div class="space-y-4">
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="label">{{ t('sys.port') }}</label>
            <input v-model.number="ovpn.ovpn_port" type="number" class="input" />
          </div>
          <div>
            <label class="label">{{ t('sys.proto') }}</label>
            <select v-model="ovpn.ovpn_proto" class="input">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
            <p class="mt-2 text-xs leading-5 text-gray-400 dark:text-gray-500">
              {{ t('sys.protoHint') }}
            </p>
          </div>
        </div>
        <div>
          <label class="label">{{ t('sys.subnet') }}</label>
          <input v-model="ovpn.ovpn_subnet" class="input" placeholder="10.8.0.0/24" />
          <p class="hint">{{ t('sys.subnetHint') }}</p>
        </div>
        <div class="grid grid-cols-3 gap-4">
          <div>
            <label class="label">{{ t('sys.maxClients') }}</label>
            <input v-model.number="ovpn.ovpn_max_clients" type="number" class="input" />
          </div>
          <div>
            <label class="label">{{ t('sys.dns1') }}</label>
            <input v-model="ovpn.ovpn_push_dns1" class="input" />
          </div>
          <div>
            <label class="label">{{ t('sys.dns2') }}</label>
            <input v-model="ovpn.ovpn_push_dns2" class="input" />
          </div>
        </div>
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="ovpn.ovpn_gateway" type="checkbox" class="rounded" />
          {{ t('sys.gateway') }}
        </label>
        <div class="flex flex-wrap gap-2">
          <button class="btn-secondary" @click="openServerConfig">{{ t('sys.editServerConfig') }}</button>
          <button class="btn-secondary" :disabled="serverActionBusy" @click="onRestartOpenVPN">
            {{ serverActionBusy ? t('common.loading') : t('sys.restartOpenVPN') }}
          </button>
        </div>
        <p v-if="serverActionMessage" class="text-sm text-emerald-600">{{ serverActionMessage }}</p>
        <p class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-600 dark:bg-amber-500/10">
          {{ t('sys.restartHint') }}
        </p>
      </div>
      <SectionSave :busy="busy === 'ovpn'" :ok="okSection === 'ovpn'" @save="saveOvpn" />
    </section>

    <!-- SMTP 设置 -->
    <section class="card p-6">
      <h2 class="mb-4 font-semibold text-gray-900 dark:text-gray-100">{{ t('sys.smtp') }}</h2>
      <div class="space-y-4">
        <div class="grid grid-cols-3 gap-4">
          <div class="col-span-2">
            <label class="label">{{ t('sys.smtpHost') }}</label>
            <input v-model="email.host" class="input" placeholder="smtp.example.com" />
          </div>
          <div>
            <label class="label">{{ t('sys.smtpPort') }}</label>
            <input v-model.number="email.port" type="number" class="input" placeholder="465" />
          </div>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="label">{{ t('sys.smtpUser') }}</label>
            <input v-model="email.username" class="input" />
          </div>
          <div>
            <label class="label">{{ t('sys.smtpPass') }}</label>
            <input v-model="smtpPass" type="password" class="input" :placeholder="t('sys.adminPassPh')" />
          </div>
        </div>
        <div class="grid grid-cols-3 gap-4">
          <div>
            <label class="label">{{ t('sys.smtpSecurity') }}</label>
            <select v-model="email.security" class="input">
              <option value="ssl">SSL</option>
              <option value="tls">STARTTLS</option>
              <option value="">None</option>
            </select>
          </div>
          <div>
            <label class="label">{{ t('sys.smtpFrom') }}</label>
            <input v-model="email.send_from" class="input" />
          </div>
          <div>
            <label class="label">{{ t('sys.smtpPrefix') }}</label>
            <input v-model="email.send_subject_prefix" class="input" />
          </div>
        </div>
        <div class="flex items-end gap-2">
          <div class="flex-1">
            <label class="label">{{ t('sys.smtpTest') }}</label>
            <input v-model="testEmail" class="input" :placeholder="t('sys.smtpTestPh')" />
          </div>
          <button class="btn-secondary" :disabled="!testEmail || busy === 'test'" @click="onTestEmail">
            {{ busy === 'test' ? t('common.loading') : t('sys.smtpTest') }}
          </button>
        </div>
        <p v-if="testResult" class="text-sm" :class="testResult.ok ? 'text-emerald-600' : 'text-red-500'">
          {{ testResult.msg }}
        </p>
      </div>
      <SectionSave :busy="busy === 'email'" :ok="okSection === 'email'" @save="saveEmail" />
    </section>

    <!-- LDAP 设置 -->
    <section class="card p-6">
      <h2 class="mb-4 font-semibold text-gray-900 dark:text-gray-100">{{ t('sys.ldap') }}</h2>
      <div class="space-y-4">
        <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300">
          <input v-model="ldap.ldap_auth" type="checkbox" class="rounded" />
          {{ t('sys.ldapEnable') }}
        </label>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="label">LDAP URL</label>
            <input v-model="ldap.ldap_url" class="input" placeholder="ldaps://example.org:636" />
          </div>
          <div>
            <label class="label">Base DN</label>
            <input v-model="ldap.ldap_base_dn" class="input" placeholder="dc=example,dc=org" />
          </div>
          <div>
            <label class="label">User Attribute</label>
            <input v-model="ldap.ldap_user_attribute" class="input" placeholder="uid / sAMAccountName" />
          </div>
          <div>
            <label class="label">Bind User DN</label>
            <input v-model="ldap.ldap_bind_user_dn" class="input" />
          </div>
          <div>
            <label class="label">Bind Password</label>
            <input v-model="ldap.ldap_bind_password" type="password" class="input" />
          </div>
          <div>
            <label class="label">User Group DN</label>
            <input v-model="ldap.ldap_user_group_dn" class="input" />
          </div>
        </div>
      </div>
      <SectionSave :busy="busy === 'ldap'" :ok="okSection === 'ldap'" @save="saveLdap" />
    </section>

    <Modal :open="serverConfigOpen" :title="t('sys.serverConfigTitle')" wide @close="serverConfigOpen = false">
      <div class="space-y-3">
        <textarea
          v-model="serverConfig"
          class="input h-[55vh] font-mono text-xs leading-5"
          spellcheck="false"
        ></textarea>
        <p class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-500/10">
          {{ t('sys.serverConfigHint') }}
        </p>
        <p v-if="serverConfigError" class="text-sm text-red-500">{{ serverConfigError }}</p>
      </div>
      <template #footer>
        <button class="btn-secondary" @click="serverConfigOpen = false">{{ t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="serverConfigBusy || !serverConfig.trim()" @click="saveServerConfig">
          {{ serverConfigBusy ? t('common.loading') : t('common.save') }}
        </button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { defineComponent, h, onMounted, reactive, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import Modal from '../components/Modal.vue';
import {
  getServerConfig,
  getSettings,
  restartOpenVPN,
  saveSettings,
  sendTestEmail,
  updateServerConfig,
} from '../api';

const { t } = useI18n();

const conf = ref(false);
const base = reactive<Record<string, any>>({});
const ovpn = reactive<Record<string, any>>({});
const email = reactive<Record<string, any>>({});
const ldap = reactive<Record<string, any>>({});
const adminPass = ref('');
const httpsCertificate = ref('');
const httpsPrivateKey = ref('');
const smtpPass = ref('');
const testEmail = ref('');
const testResult = ref<{ ok: boolean; msg: string } | null>(null);
const serverConfigOpen = ref(false);
const serverConfig = ref('');
const serverConfigBusy = ref(false);
const serverConfigError = ref('');
const serverActionBusy = ref(false);
const serverActionMessage = ref('');

const busy = ref('');
const okSection = ref('');

// 每节独立保存按钮
const SectionSave = defineComponent({
  props: { busy: Boolean, ok: Boolean },
  emits: ['save'],
  setup(props, { emit }) {
    return () =>
      h('div', { class: 'mt-5 flex items-center justify-end gap-3' }, [
        props.ok ? h('span', { class: 'text-sm text-emerald-600' }, t('common.saveOk')) : null,
        h(
          'button',
          { class: 'btn-primary', disabled: props.busy, onClick: () => emit('save') },
          () => (props.busy ? t('common.loading') : t('sys.saveSection'))
        ),
      ]);
  },
});

async function doSave(section: string, kv: Record<string, unknown>): Promise<boolean> {
  busy.value = section;
  okSection.value = '';
  try {
    await saveSettings(kv);
    okSection.value = section;
    setTimeout(() => (okSection.value = ''), 2500);
    return true;
  } catch (e: any) {
    alert(e.response?.data?.message ?? t('common.saveFail'));
    return false;
  } finally {
    busy.value = '';
  }
}

async function saveBase() {
  const hasCertificate = Boolean(httpsCertificate.value.trim());
  const hasPrivateKey = Boolean(httpsPrivateKey.value.trim());
  if (hasCertificate !== hasPrivateKey) {
    alert(t('sys.httpsPairRequired'));
    return;
  }
  if (base.https_enabled && !base.https_certificate_configured && !hasCertificate) {
    alert(t('sys.httpsRequired'));
    return;
  }

  const kv: Record<string, unknown> = {
    'system.base.site_url': base.site_url ?? '',
    'system.base.https_enabled': base.https_enabled ? 'true' : 'false',
    'system.base.max_duplicate_login': String(base.max_duplicate_login ?? 0),
    'system.base.history_max_days': String(base.history_max_days ?? 0),
    'system.base.auto_update_ovpn_config': base.auto_update_ovpn_config ? 'true' : 'false',
    'system.base.enforce_password_policy': base.enforce_password_policy ? 'true' : 'false',
  };
  if (hasCertificate && hasPrivateKey) {
    kv.https_certificate = httpsCertificate.value;
    kv.https_private_key = httpsPrivateKey.value;
  }
  if (adminPass.value) kv['system.base.admin_password'] = adminPass.value;
  if (await doSave('base', kv)) {
    adminPass.value = '';
    if (hasCertificate) {
      base.https_certificate_configured = true;
      httpsCertificate.value = '';
      httpsPrivateKey.value = '';
    }
  }
}

async function openServerConfig() {
  serverConfigOpen.value = true;
  serverConfigBusy.value = true;
  serverConfigError.value = '';
  try {
    const { data } = await getServerConfig();
    serverConfig.value = data.content;
  } catch (e: any) {
    serverConfigError.value = e.response?.data?.message ?? t('sys.serverConfigLoadFail');
  } finally {
    serverConfigBusy.value = false;
  }
}

async function saveServerConfig() {
  if (!confirm(t('sys.serverConfigSaveConfirm'))) return;
  serverConfigBusy.value = true;
  serverConfigError.value = '';
  try {
    await updateServerConfig(serverConfig.value);
    serverConfigOpen.value = false;
    serverActionMessage.value = t('sys.serverConfigSaved');
  } catch (e: any) {
    serverConfigError.value = e.response?.data?.message ?? t('common.saveFail');
  } finally {
    serverConfigBusy.value = false;
  }
}

async function onRestartOpenVPN() {
  if (!confirm(t('sys.restartOpenVPNConfirm'))) return;
  serverActionBusy.value = true;
  serverActionMessage.value = '';
  try {
    await restartOpenVPN();
    serverActionMessage.value = t('sys.restartOpenVPNOk');
  } catch (e: any) {
    alert(e.response?.data?.message ?? t('sys.restartOpenVPNFail'));
  } finally {
    serverActionBusy.value = false;
  }
}

function saveOvpn() {
  doSave('ovpn', {
    'openvpn.ovpn_port': String(ovpn.ovpn_port ?? 1194),
    'openvpn.ovpn_proto': ovpn.ovpn_proto ?? 'tcp',
    'openvpn.ovpn_subnet': ovpn.ovpn_subnet ?? '10.8.0.0/24',
    'openvpn.ovpn_max_clients': String(ovpn.ovpn_max_clients ?? 200),
    'openvpn.ovpn_gateway': ovpn.ovpn_gateway ? 'true' : 'false',
    'openvpn.ovpn_push_dns1': ovpn.ovpn_push_dns1 ?? '',
    'openvpn.ovpn_push_dns2': ovpn.ovpn_push_dns2 ?? '',
  });
}

function saveEmail() {
  const kv: Record<string, unknown> = {
    'system.email.host': email.host ?? '',
    'system.email.port': String(email.port ?? 465),
    'system.email.username': email.username ?? '',
    'system.email.security': email.security ?? 'ssl',
    'system.email.send_from': email.send_from ?? '',
    'system.email.send_subject_prefix': email.send_subject_prefix ?? '',
  };
  if (smtpPass.value) kv['system.email.password'] = smtpPass.value;
  doSave('email', kv);
  smtpPass.value = '';
}

function saveLdap() {
  doSave('ldap', {
    'system.ldap.ldap_auth': ldap.ldap_auth ? 'true' : 'false',
    'system.ldap.ldap_url': ldap.ldap_url ?? '',
    'system.ldap.ldap_base_dn': ldap.ldap_base_dn ?? '',
    'system.ldap.ldap_user_attribute': ldap.ldap_user_attribute ?? '',
    'system.ldap.ldap_bind_user_dn': ldap.ldap_bind_user_dn ?? '',
    'system.ldap.ldap_bind_password': ldap.ldap_bind_password ?? '',
    'system.ldap.ldap_user_group_dn': ldap.ldap_user_group_dn ?? '',
  });
}

async function onTestEmail() {
  busy.value = 'test';
  testResult.value = null;
  try {
    await sendTestEmail(testEmail.value);
    testResult.value = { ok: true, msg: t('sys.smtpTestOk') };
  } catch (e: any) {
    testResult.value = { ok: false, msg: e.response?.data?.message ?? 'failed' };
  } finally {
    busy.value = '';
  }
}

onMounted(async () => {
  const { data } = await getSettings();
  Object.assign(base, data.system.base);
  Object.assign(ovpn, data.openvpn);
  Object.assign(email, data.system.email);
  Object.assign(ldap, data.system.ldap);
  // 密码字段不回显密文
  smtpPass.value = '';
  httpsCertificate.value = '';
  httpsPrivateKey.value = '';
  conf.value = true;
});
</script>
