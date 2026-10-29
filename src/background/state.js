/**
 * SplitDNS - 状态模型与持久化
 *
 * 所有用户数据都保存在 chrome.storage.local，键名统一带 splitdns. 前缀；
 * 运行期信息（规则同步结果、代理状态）放在 splitdns.runtime.* 下，便于 UI 只读展示。
 */

import { deepMerge } from '../lib/util.js';

export const STATE_KEY = 'splitdns.state';
/**
 * 状态总预算。
 *
 * chrome.storage.local 默认配额 10 MB，而 migrate() 允许的上限加起来是
 * 4×2MB（规则列表）+ 20×2MB（订阅缓存）= 48 MB，远超配额。
 * 一旦超限，storage.set 会抛 QUOTA_BYTES，而每次保存都是"整份重写"，
 * 结果是连切换总开关都存不进去。这里在写入前拦住，留 2 MB 余量。
 */
export const STATE_BUDGET_BYTES = 8 * 1024 * 1024;
const QUOTA_HINT = '规则总量超过浏览器存储上限（约 8 MB），请删除部分订阅或精简规则列表';

function byteLength(text) {
  return new TextEncoder().encode(text).length;
}

/** 估算状态序列化后的字节数（供 UI 展示占用） */
export function estimateStateSize(state) {
  return byteLength(JSON.stringify({ [STATE_KEY]: state }));
}
export const RUNTIME_KEY = 'splitdns.runtime';
export const LOG_KEY = 'splitdns.log';
export const SCHEMA_VERSION = 1;

const DEFAULT_BLOCK = `# ===== 拦截列表 =====
# 语法：domain:example.com / full:www.example.com / keyword:ads / regexp:^ad\\d+\\.
# 也兼容 hosts（0.0.0.0 example.com）与 Adblock 域名语法（||example.com^）
# 以 @@ 开头表示例外（白名单），优先级高于拦截。

||doubleclick.net^
||googleadservices.com^
||googlesyndication.com^
||adservice.google.com^

# 示例：放行某个被误拦的子域
# @@||img.doubleclick.net^
`;

const DEFAULT_DIRECT = `# ===== 直连（白名单）=====
# 命中此列表的域名：不拦截、不走分流代理，并覆盖其它列表的拦截结果。
# 适合内网、支付、银行等需要走本地网络或直连的域名。

# domain:corp.example.com
# domain:192.168.0.10
`;

const DEFAULT_PROXY = `# ===== 分流代理列表 =====
# 命中此列表的域名在"分流代理"开启后走你配置的代理，其余直连。
# 仅支持 domain / full / keyword 三种类型（PAC 脚本不支持正则）。

# domain:google.com
# domain:githubusercontent.com
# keyword:telegram
`;

const DEFAULT_REDIRECT = `# ===== 重定向列表 =====
# 语法：<匹配规则> => <新主机或完整地址>
# 只重写协议/主机部分，路径与查询串保持不变。

# domain:old.example.com => new.example.com
# full:cdn.example.com => https://cdn.example.net
`;

/** 默认状态 */
export function defaultState() {
  return {
    schemaVersion: SCHEMA_VERSION,
    enabled: true,
    lists: {
      block: { enabled: true, text: DEFAULT_BLOCK },
      direct: { enabled: true, text: DEFAULT_DIRECT },
      proxy: { enabled: true, text: DEFAULT_PROXY },
      redirect: { enabled: true, text: DEFAULT_REDIRECT },
    },
    dns: {
      defaultUpstream: 'alidns',
      customUpstreams: [],
      split: [],
      timeoutMs: 5000,
      cache: { enabled: true, minTtl: 60, maxTtl: 3600, maxEntries: 1000 },
    },
    proxy: {
      enabled: false,
      mode: 'list',
      type: 'PROXY',
      server: '127.0.0.1',
      port: 7890,
    },
    builtinRuleset: false,
    log: { enabled: true, max: 100 },
    subscriptions: [],
    security: {
      // 订阅来源的正则规则默认禁用：订阅内容不可信，而 JS 正则存在灾难性回溯风险
      allowSubRegex: false,
      // 订阅写入「直连 / 重定向」列表默认禁用：这会解除拦截或改写主机
      allowSubTrust: false,
    },
    ui: { lastTab: 'general' },
  };
}

/* ------------------------------------------------------------------ */
/* 类型安全的迁移                                                      */
/* ------------------------------------------------------------------ */

export const LIST_KEYS = ['block', 'direct', 'proxy', 'redirect'];
const SUB_TARGETS = new Set(LIST_KEYS);
const PROXY_MODES = new Set(['list', 'global', 'direct']);
const PROXY_TYPES = new Set(['PROXY', 'HTTPS', 'SOCKS5', 'SOCKS4', 'QUIC']);
const UI_TABS = new Set(['general', 'rules', 'upstream', 'proxy', 'subs', 'data', 'about']);

const MAX_LIST_BYTES = 2 * 1024 * 1024;   // 单个规则列表上限 2MB
const MAX_SUB_BYTES = 2 * 1024 * 1024;    // 单个订阅缓存上限 2MB
const MAX_SUBS = 20;
const MAX_CUSTOM_UPSTREAMS = 20;
const MAX_SPLIT_RULES = 200;

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function asString(value, fallback = '') {
  return typeof value === 'string' ? value : fallback;
}

function asBool(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

function asNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/**
 * 代理服务器地址只允许主机名 / IPv4 / [IPv6]。
 * 含引号、空格、分号时会生成非法的 `PROXY host:port` 串，PAC 引擎解析失败后
 * 因为 mandatory:false 会静默回退直连 —— 用户以为在走代理，实际没有。
 */
function sanitizeProxyServer(value) {
  const raw = asString(value, '').trim().slice(0, 120);
  if (!raw) return '127.0.0.1';
  if (/^[a-z0-9._-]+$/i.test(raw)) return raw;
  if (/^\[[0-9a-f:.]+\]$/i.test(raw)) return raw;
  return '127.0.0.1';
}

function asText(value, fallback, maxBytes) {
  if (typeof value !== 'string') return fallback;
  // 按字符截断（ASCII 场景字符数≈字节数，作为硬上限足够）
  return value.length > maxBytes ? value.slice(0, maxBytes) : value;
}

/**
 * 补齐缺失字段、校验类型、收敛取值范围。
 *
 * 这是唯一的状态入口：getState / saveState / import 都会经过它，
 * 因此畸形配置（如 lists: null、target 为任意字符串、超长文本）不会进入运行期。
 */
export function migrate(raw) {
  const base = defaultState();
  if (!isPlainObject(raw)) return base;

  // ---- 规则列表 ----
  const lists = {};
  for (const key of LIST_KEYS) {
    const source = isPlainObject(raw.lists?.[key]) ? raw.lists[key] : {};
    lists[key] = {
      enabled: asBool(source.enabled, true),
      text: asText(source.text, base.lists[key].text, MAX_LIST_BYTES),
    };
  }

  // ---- DNS ----
  const dnsSource = isPlainObject(raw.dns) ? raw.dns : {};
  const cacheSource = isPlainObject(dnsSource.cache) ? dnsSource.cache : {};
  const cache = {
    enabled: asBool(cacheSource.enabled, true),
    minTtl: asNumber(cacheSource.minTtl, 1, 86400, 60),
    maxTtl: asNumber(cacheSource.maxTtl, 1, 86400, 3600),
    maxEntries: asNumber(cacheSource.maxEntries, 10, 10000, 1000),
  };
  if (cache.maxTtl < cache.minTtl) cache.maxTtl = cache.minTtl;

  const dns = {
    defaultUpstream: asString(dnsSource.defaultUpstream, base.dns.defaultUpstream) || base.dns.defaultUpstream,
    customUpstreams: (Array.isArray(dnsSource.customUpstreams) ? dnsSource.customUpstreams : [])
      .filter(isPlainObject)
      .map((item, index) => ({
        id: asString(item.id, '') || `u_${index}`,
        name: asString(item.name, '').slice(0, 60) || '自定义',
        url: asString(item.url, '').slice(0, 2048),
      }))
      .filter((item) => item.url)
      .slice(0, MAX_CUSTOM_UPSTREAMS),
    split: (Array.isArray(dnsSource.split) ? dnsSource.split : [])
      .filter(isPlainObject)
      .map((item) => ({
        pattern: asString(item.pattern, '').slice(0, 200),
        upstream: asString(item.upstream, ''),
      }))
      .filter((item) => item.pattern)
      .slice(0, MAX_SPLIT_RULES),
    timeoutMs: asNumber(dnsSource.timeoutMs, 1000, 30000, base.dns.timeoutMs),
    cache,
  };

  // ---- 代理 ----
  const proxySource = isPlainObject(raw.proxy) ? raw.proxy : {};
  const proxy = {
    enabled: asBool(proxySource.enabled, false),
    mode: PROXY_MODES.has(proxySource.mode) ? proxySource.mode : 'list',
    type: PROXY_TYPES.has(proxySource.type) ? proxySource.type : 'PROXY',
    server: sanitizeProxyServer(proxySource.server),
    port: asNumber(proxySource.port, 1, 65535, 7890),
  };

  // ---- 订阅 ----
  const subscriptions = (Array.isArray(raw.subscriptions) ? raw.subscriptions : [])
    .filter(isPlainObject)
    .map((item, index) => ({
      id: asString(item.id, '') || `s_${index}`,
      name: asString(item.name, '').slice(0, 80) || '未命名',
      url: asString(item.url, '').slice(0, 2048),
      // target 必须是四个列表之一，否则回退为 block
      target: SUB_TARGETS.has(item.target) ? item.target : 'block',
      enabled: asBool(item.enabled, true),
      text: asText(item.text, '', MAX_SUB_BYTES),
      lastUpdate: asNumber(item.lastUpdate, 0, 8.64e15, 0),
    }))
    .filter((item) => item.url)
    .slice(0, MAX_SUBS);

  // ---- 其它 ----
  const logSource = isPlainObject(raw.log) ? raw.log : {};
  const uiSource = isPlainObject(raw.ui) ? raw.ui : {};
  const securitySource = isPlainObject(raw.security) ? raw.security : {};

  return {
    schemaVersion: SCHEMA_VERSION,
    enabled: asBool(raw.enabled, true),
    lists,
    dns,
    proxy,
    builtinRuleset: asBool(raw.builtinRuleset, false),
    log: { enabled: asBool(logSource.enabled, true), max: asNumber(logSource.max, 10, 500, 100) },
    subscriptions,
    security: {
      allowSubRegex: asBool(securitySource.allowSubRegex, false),
      allowSubTrust: asBool(securitySource.allowSubTrust, false),
    },
    ui: { lastTab: UI_TABS.has(uiSource.lastTab) ? uiSource.lastTab : 'general' },
  };
}

/** 读取状态 */
export async function getState() {
  const raw = await chrome.storage.local.get(STATE_KEY);
  return migrate(raw[STATE_KEY]);
}

/** 覆盖写入状态（带存储预算保护） */
export async function saveState(state) {
  const next = migrate(state);
  const size = estimateStateSize(next);

  if (size > STATE_BUDGET_BYTES) {
    // 允许"越写越小"：否则用户无法通过删除内容把状态救回来
    const currentSize = estimateStateSize(await getState());
    if (size >= currentSize) throw new Error(QUOTA_HINT);
  }

  try {
    await chrome.storage.local.set({ [STATE_KEY]: next });
  } catch (err) {
    const message = String(err?.message || err);
    if (/quota/i.test(message)) throw new Error(QUOTA_HINT);
    throw err;
  }
  return next;
}

/** 局部更新状态（深合并） */
export async function patchState(patch) {
  const current = await getState();
  return saveState(deepMerge(current, patch));
}

/** 读取运行期信息 */
export async function getRuntime() {
  const raw = await chrome.storage.local.get(RUNTIME_KEY);
  return raw[RUNTIME_KEY] || {};
}

/** 写入运行期信息 */
export async function patchRuntime(patch) {
  const current = await getRuntime();
  const next = deepMerge(current, patch);
  await chrome.storage.local.set({ [RUNTIME_KEY]: next });
  return next;
}

/** 查询日志（session 级，随浏览器关闭清空） */
export async function getLog() {
  const raw = await chrome.storage.session.get(LOG_KEY);
  return Array.isArray(raw[LOG_KEY]) ? raw[LOG_KEY] : [];
}

/** 追加一条查询日志 */
export async function appendLog(entry, max = 100) {
  const list = await getLog();
  list.unshift(entry);
  const trimmed = list.slice(0, Math.max(10, Number(max) || 100));
  await chrome.storage.session.set({ [LOG_KEY]: trimmed });
  return trimmed;
}

/** 清空日志 */
export async function clearLog() {
  await chrome.storage.session.set({ [LOG_KEY]: [] });
}
