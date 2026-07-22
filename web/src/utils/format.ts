export function formatBytes(n: number | string): string {
  const v = Number(n);
  if (!isFinite(v) || v < 0) return String(n);
  if (v < 1024) return `${v.toFixed(0)} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
  return `${(v / 1024 ** 3).toFixed(2)} GB`;
}

export function formatDuration(sec: number | string): string {
  const v = Number(sec);
  if (!isFinite(v) || v < 0) return String(sec);
  const h = Math.floor(v / 3600);
  const m = Math.floor((v % 3600) / 60);
  const s = Math.floor(v % 60);
  if (h > 0) return `${h}时${m}分${s}秒`;
  if (m > 0) return `${m}分${s}秒`;
  return `${s}秒`;
}

export function formatUnix(ts: number | string): string {
  const v = Number(ts);
  if (!isFinite(v) || v <= 0) return String(ts);
  return new Date(v * 1000).toLocaleString('zh-CN', { hour12: false });
}
