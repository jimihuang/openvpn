import http from './http';

// ---- 类型定义(与 Go 后端 JSON 结构一一对应) ----

export interface VpnUser {
  id: number;
  username: string;
  password?: string;
  isEnable: boolean;
  name: string;
  email: string;
  gid: number;
  expireDate: string | null;
  ipAddr: string | null;
  ovpnConfig: string;
  mfaSecret: string;
  isFirstLogin: boolean;
  lastLoginAt?: string;
  createdAt?: string;
}

export interface VpnGroup {
  id: number;
  name: string;
  parent_id: number | null;
  config: string | null;
}

export interface ClientConfig {
  name: string;
  fullName: string;
  file: string;
  date: string;
  isDefault: boolean;
}

export interface PasswordPolicy {
  enforced: boolean;
  minLength: number;
}

export interface OnlineClient {
  id: string;
  rip: string;
  vip: string;
  vip6: string;
  recvBytes: number;
  sendBytes: number;
  connDate: string;
  onlineTime: string;
  username: string;
  commonName: string;
}

export interface ServerInfo {
  RunDate: string;
  Status: string;
  StatusDesc: string;
  Address: string;
  Nclients: string;
  BytesIn: string;
  BytesOut: string;
  Mode: string;
  Version: string;
}

export interface HistoryRecord {
  id: number;
  vip: string;
  rip: string;
  common_name: string;
  username: string;
  bytes_received: number | string;
  bytes_sent: number | string;
  time_unix: number | string;
  time_duration: number | string;
}

export interface CertItem {
  name: string;
  type: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  expiresIn: string;
  status: string;
}

// 系统设置(与 config.json 同构,POST 时用点分路径键)
export interface SysConfig {
  system: {
    base: Record<string, unknown>;
    ldap: Record<string, unknown>;
    email: Record<string, unknown>;
  };
  openvpn: Record<string, unknown>;
}

// ---- 认证 ----

export const login = (form: Record<string, string>) => http.post('/login', form);
export const logout = () => http.get('/logout');
export const getCaptcha = () =>
  http.get<{ key: string; master: string; thumb: string }>('/captcha');

// ---- 分组 / 账号 ----

export const listGroups = () => http.get<VpnGroup[]>('/ovpn/group');
export const listGroupUsers = (gid: number) =>
  http.get<{ users: VpnUser[]; authUser: boolean }>(`/ovpn/group/${gid}/users`);
export const createUser = (u: Record<string, unknown>) => http.post('/ovpn/user', u);
export const updateUser = (u: Record<string, unknown>) => http.patch('/ovpn/user', u);
export const deleteUser = (id: number) => http.delete(`/ovpn/user/${id}`);

// ---- 客户端(证书 + 配置模板) ----

export const listClients = () => http.get<ClientConfig[]>('/ovpn/client');
export const createClient = (c: Record<string, string>) => http.post('/ovpn/client', c);
export const setDefaultClient = (name: string) =>
  http.put(`/ovpn/client/${encodeURIComponent(name)}/default`);
export const deleteClient = (name: string) =>
  http.delete(`/ovpn/client/${encodeURIComponent(name)}`);
export const getClientFile = (name: string, type: 'ccd' | 'config') =>
  http.get(`/ovpn/client/${encodeURIComponent(name)}/${type}`);
export const putClientFile = (name: string, type: 'ccd' | 'config', content: string) =>
  http.put(`/ovpn/client/${encodeURIComponent(name)}/${type}`, { content });
export const downloadUrl = (fullName: string) =>
  `/ovpn/download/${encodeURIComponent(fullName)}`;

// ---- 在线状态 / 历史 ----

export const getOnline = () =>
  http.get<{ server: ServerInfo; clients: OnlineClient[] }>('/ovpn/online-client');
export const getHistory = (params: Record<string, unknown>) =>
  http.get<{ draw: number; recordsTotal: number; recordsFiltered: number; data: HistoryRecord[] }>(
    '/ovpn/history',
    { params }
  );

// ---- 系统设置 / 证书 ----

export const getSettings = () => http.get<SysConfig>('/settings');
// 以点分路径提交,如 { "openvpn.ovpn_proto": "tcp" }
export const saveSettings = (kv: Record<string, unknown>) => http.post('/settings', kv);
export const sendTestEmail = (email: string) =>
  http.post('/email/send', { email, subject: 'OpenVPN SMTP Test', content: 'SMTP configuration works.' });

export const listCerts = () => http.get<CertItem[]>('/ovpn/certs');
export const getCertMaterial = (type: 'ca' | 'crl' | 'server' | 'client', name?: string) =>
  http.get<{ content: string }>('/ovpn/certs/material', { params: { type, name } });
export const replaceCertMaterial = (form: {
  type: 'ca' | 'crl' | 'server' | 'client';
  name?: string;
  content: string;
  privateKey?: string;
}) => http.put('/ovpn/certs/material', form);
export const renewCertificates = (day: number) =>
  http.post('/ovpn/server', { action: 'renewCert', day });
export const restartOpenVPN = () => http.post('/ovpn/server', { action: 'restartSrv' });
export const getServerConfig = () =>
  http.post<{ content: string }>('/ovpn/server', { action: 'getConfig' });
export const updateServerConfig = (content: string) =>
  http.post('/ovpn/server', { action: 'updateConfig', content });

// ---- 自助服务(普通账号) ----

export const getUserInfo = () => http.get<VpnUser>('/client/userinfo');
export const getPasswordPolicy = () => http.get<PasswordPolicy>('/client/password-policy');
export const getUserConfig = () =>
  http.get<{ filename: string; content: string }>('/client/userConfig');
export const modifyPass = (form: Record<string, unknown>) => http.post('/client/modifyPass', form);
export const getMfa = () =>
  http.get<{
    mfaEnable: boolean;
    user: VpnUser;
    otpauthUri?: string;
    qrCode?: string;
  }>('/client/mfa');
export const enableMfa = (id: number, mfaSecret: string, passcode: string) =>
  http.post('/client/mfa', { id, mfaSecret, passcode });
export const disableMfa = (id: number) => http.delete(`/client/mfa/${id}`);

// ---- 工具 ----

// 生成 12 位随机密码:大小写字母 + 数字 + 特殊字符(满足后端密码策略)
export function randomPassword(len = 12): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const digit = '23456789';
  const special = '!@#$%^&*';
  const all = upper + lower + digit + special;
  const randomIndex = (max: number) => {
    if (!Number.isSafeInteger(max) || max <= 0 || max > 256) throw new Error('invalid random range');
    const limit = 256 - (256 % max);
    const value = new Uint8Array(1);
    do crypto.getRandomValues(value); while (value[0] >= limit);
    return value[0] % max;
  };
  const pick = (s: string) => s[randomIndex(s.length)];
  const chars = [pick(upper), pick(lower), pick(digit), pick(special)];
  while (chars.length < len) chars.push(pick(all));
  // 洗牌
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

export const passwordValid = (p: string, enforced = true) => {
  if (!enforced) return Array.from(p).length >= 6;
  return Array.from(p).length >= 12 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
};
