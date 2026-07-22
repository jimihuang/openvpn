import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// 开发环境把后端接口代理到测试服务器(OrbStack 虚拟机)
// 生产环境 SPA 由 Go 后端 embed 同源托管,无需代理
const BACKEND = process.env.VITE_BACKEND ?? 'http://192.168.139.144:8833';

// GET /login /settings 是 SPA 页面路由,其余方法/路径才是后端接口
const apiPaths = ['/ovpn', '/client', '/user', '/email', '/captcha', '/logout', '/settings', '/login'];

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      apiPaths.map((p) => [
        p,
        {
          target: BACKEND,
          changeOrigin: true,
          bypass(req: any) {
            // 浏览器直接导航(GET + accept html)到 /login 等页面时交给 SPA
            if (req.method === 'GET' && String(req.headers.accept).includes('text/html')) {
              return '/index.html';
            }
          },
        },
      ])
    ),
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 800,
  },
});
