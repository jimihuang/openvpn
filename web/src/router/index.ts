import { createRouter, createWebHistory } from 'vue-router';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: () => import('../pages/Login.vue') },
    // 普通账号自助页(独立页面,不进管理布局)
    { path: '/portal', component: () => import('../pages/Portal.vue') },
    {
      path: '/',
      component: () => import('../layouts/AdminLayout.vue'),
      children: [
        // 根路径按登录时记录的角色分流
        {
          path: '',
          redirect: () =>
            localStorage.getItem('role') === 'user' ? '/portal' : '/dashboard',
        },
        { path: 'dashboard', component: () => import('../pages/Dashboard.vue') },
        { path: 'accounts', component: () => import('../pages/Accounts.vue') },
        { path: 'clients', component: () => import('../pages/Clients.vue') },
        { path: 'history', component: () => import('../pages/History.vue') },
        { path: 'certs', component: () => import('../pages/Certs.vue') },
        // 注意: 后端已占用 GET /settings 返回配置 JSON,前端路由用 /system
        { path: 'system', component: () => import('../pages/Settings.vue') },
        { path: 'admin', redirect: '/dashboard' },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  if (to.path === '/login') return true;

  let role = localStorage.getItem('role');
  if (role !== 'admin' && role !== 'user') {
    try {
      const response = await fetch('/session', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) return '/login';
      const session = (await response.json()) as { role: 'admin' | 'user' };
      role = session.role;
      localStorage.setItem('role', role);
    } catch {
      return '/login';
    }
  }

  if (role === 'user' && to.path !== '/portal') return '/portal';
  if (role === 'admin' && to.path === '/portal') return '/dashboard';
  return true;
});

export default router;
