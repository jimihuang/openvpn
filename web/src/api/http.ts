import axios from 'axios';
import router from '../router';

// SPA 由 Go 后端同源托管,直接访问后端根路径接口
const http = axios.create({
  baseURL: '',
  timeout: 30000,
  // 后端接口全部使用表单编码
  transformRequest: [
    (data, headers) => {
      if (data instanceof FormData || typeof data === 'string' || data == null) return data;
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const p = new URLSearchParams();
      Object.entries(data).forEach(([k, v]) => {
        if (v !== undefined && v !== null) p.append(k, String(v));
      });
      return p.toString();
    },
  ],
});

http.interceptors.response.use(
  (res) => res,
  (err) => {
    // 会话过期统一跳登录页;登录接口自身的 401 由页面处理
    if (err.response?.status === 401 && !String(err.config?.url).includes('/login')) {
      localStorage.removeItem('role');
      router.push('/login');
    }
    return Promise.reject(err);
  }
);

export default http;
