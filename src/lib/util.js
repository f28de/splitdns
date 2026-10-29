/**
 * SplitDNS - 通用工具函数
 * 纯函数模块，无 chrome.* 依赖，方便在 Service Worker / 页面 / 测试中共用。
 */

/** 截断到 [min, max] 区间 */
export function clamp(n, min, max) {
  const v = Number(n);
  if (!Number.isFinite(v)) return min;
  return Math.min(max, Math.max(min, v));
}

/** 防抖 */
export function debounce(fn, ms = 300) {
  let timer = null;
  return function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, ms);
  };
}

/** 生成短随机 id */
export function uid(prefix = '') {
  return prefix + Math.random().toString(36).slice(2, 10);
}

/** 从 URL 中取主机名，失败返回空串 */
export function hostFromUrl(url) {
  try {
    return new URL(String(url)).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** 是否 http(s) 页面 */
export function isHttpUrl(url) {
  return /^https?:\/\//i.test(String(url || ''));
}

/** HTML 转义，UI 拼字符串时统一使用 */
export function escapeHtml(input) {
  return String(input ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

/** 时间戳 -> HH:mm:ss */
export function formatClock(ts) {
  const d = new Date(ts || Date.now());
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 时间戳 -> YYYY-MM-DD HH:mm */
export function formatDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 人类可读的相对时间 */
export function formatAgo(ts) {
  if (!ts) return '从未';
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  return `${Math.floor(diff / 86_400_000)} 天前`;
}

/** 会改写原型链的键，合并时必须跳过 */
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * 深合并：仅合并普通对象，数组与标量直接覆盖。
 *
 * 跳过 __proto__ / constructor / prototype：JSON.parse 会把 "__proto__" 变成
 * 自有属性，直接 `out[key] = value` 会改写 out 的原型（原型链污染/替换），
 * 之后 migrate() 通过原型链就能读到本该被白名单挡掉的字段。
 */
export function deepMerge(base, patch) {
  if (Array.isArray(patch)) return patch.slice();
  if (patch === null || typeof patch !== 'object') return patch;
  const out = (base && typeof base === 'object' && !Array.isArray(base)) ? { ...base } : {};
  for (const [k, v] of Object.entries(patch)) {
    if (UNSAFE_KEYS.has(k)) continue;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = deepMerge(out[k], v);
    } else if (Array.isArray(v)) {
      out[k] = v.slice();
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** 读取存储（带默认值） */
export async function storageGet(area, key, fallback) {
  const store = chrome.storage[area];
  const raw = await store.get(key);
  return raw[key] === undefined ? fallback : raw[key];
}

/** 写入存储 */
export async function storageSet(area, key, value) {
  await chrome.storage[area].set({ [key]: value });
}

/** 简单的并发上限执行器 */
export async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

/* ------------------------------------------------------------------ */
/* 网络安全约束                                                        */
/* ------------------------------------------------------------------ */

/** 回环地址：允许使用明文 http 的唯一场景（本地调试自建 DoH） */
export function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost');
}

/**
 * 校验对外请求地址：默认只允许 https，明文 http 仅限回环地址。
 * 这样既挡住"配了个 http DoH 导致查询域名明文外泄"，又保留本地调试能力。
 * @returns {{ok:boolean, url?:string, insecure?:boolean, reason?:string}}
 */
export function checkEndpoint(input) {
  let parsed;
  try {
    parsed = new URL(String(input));
  } catch {
    return { ok: false, reason: '地址格式不正确' };
  }
  if (parsed.protocol === 'https:') return { ok: true, url: parsed.href };
  if (parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname)) {
    return { ok: true, url: parsed.href, insecure: true };
  }
  return { ok: false, reason: '仅允许 https 地址（明文 http 仅限本机回环地址）' };
}

/**
 * 校验重定向后的最终地址。
 *
 * 只校验最终地址是不够的：`checkEndpoint()` 对回环 http 返回 ok，
 * 于是"https 订阅 → 302 到 http://127.0.0.1/..."这种降级会被放过。
 * 规则：初始地址是 https 时，最终地址也必须是 https（不接受任何 http，含回环）。
 * @returns {{ok:boolean, reason?:string}}
 */
export function checkRedirectTarget(initialUrl, finalUrl) {
  const initial = checkEndpoint(initialUrl);
  if (!initial.ok) return initial;
  if (!finalUrl) return { ok: true };

  const final = checkEndpoint(finalUrl);
  if (!final.ok) return { ok: false, reason: `重定向目标不被允许：${final.reason}` };

  // 初始是 https 而最终落到明文 http（哪怕是回环），视为降级
  if (!initial.insecure && final.insecure) {
    return { ok: false, reason: '重定向把 https 降级为明文 http，已拒绝' };
  }
  return { ok: true };
}

/**
 * 带字节上限的响应体读取。
 * 不能先 res.text() 再检查长度——那时内容已经全部进内存了。
 * @param {Response} res
 * @param {number} maxBytes
 */
export async function readTextCapped(res, maxBytes) {
  const limit = Math.max(1024, Number(maxBytes) || 1024 * 1024);
  const declared = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > limit) {
    throw new Error(`响应过大（声明 ${declared} 字节，上限 ${limit} 字节）`);
  }

  if (!res.body || typeof res.body.getReader !== 'function') {
    // 兜底路径（老环境）：至少做一次编码后长度校验
    const text = await res.text();
    if (new TextEncoder().encode(text).byteLength > limit) throw new Error(`响应超过上限 ${limit} 字节`);
    return text;
  }

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      // eslint-disable-next-line no-await-in-loop
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        throw new Error(`响应超过上限 ${limit} 字节`);
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock?.();
    } catch {
      /* cancel 之后锁可能已释放，忽略 */
    }
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8').decode(merged);
}
