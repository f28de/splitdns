/**
 * SplitDNS - DoH 解析器（RFC 8484 JSON 形式）
 *
 * 说明：浏览器不允许扩展直接接管系统 DNS，因此本扩展以 DoH 客户端的形式
 * 提供"按域名选择上游 / 缓存 / 观测"能力，等价于 mosdns 的 upstream 分组与 cache 插件。
 */

import { normalizeDomain, parseRuleLine, testRule } from './matcher.js';
import { resolveUpstream } from './providers.js';
import { checkEndpoint, checkRedirectTarget, readTextCapped } from './util.js';

export const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'HTTPS', 'ANY'];

/** DoH 响应体上限：正常应答只有几百字节，512KB 已经非常宽松 */
const MAX_DOH_BYTES = 512 * 1024;
/** 单次应答最多保留的记录数，防止恶意上游塞入海量记录 */
const MAX_ANSWERS = 64;

const TYPE_NUM = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65, ANY: 255,
};
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE_NUM).map(([k, v]) => [v, k]));

const RCODE_TEXT = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
};

/** 拼接请求 URL */
export function buildUrl(upstream, name, type = 'A') {
  const tpl = String(upstream.url || '');
  const n = encodeURIComponent(name);
  const t = encodeURIComponent(type);
  if (tpl.includes('{name}') || tpl.includes('{type}')) {
    return tpl.replace(/\{name\}/g, n).replace(/\{type\}/g, t);
  }
  const joiner = tpl.includes('?') ? '&' : '?';
  return `${tpl}${joiner}name=${n}&type=${t}`;
}

/** 从 JSON 响应中提取答案列表（限制条数与单条长度） */
export function parseAnswers(json) {
  const answers = Array.isArray(json?.Answer) ? json.Answer : [];
  return answers.slice(0, MAX_ANSWERS).map((a) => ({
    name: String(a?.name ?? '').replace(/\.$/, '').slice(0, 255),
    type: TYPE_NAME[a?.type] || String(a?.type ?? '').slice(0, 8),
    ttl: Number(a?.TTL) || 0,
    data: String(a?.data ?? '').slice(0, 1024),
  }));
}

/** 最小 TTL（用于缓存时长） */
export function minTtl(answers, fallback = 300) {
  const ttls = answers.map((a) => a.ttl).filter((t) => Number.isFinite(t) && t > 0);
  return ttls.length ? Math.min(...ttls) : fallback;
}

/**
 * 执行一次 DoH 查询
 * @param {string} name 域名
 * @param {object} options { type, upstream, timeout }
 * @returns {Promise<object>}
 */
export async function resolve(name, { type = 'A', upstream, timeout = 5000 } = {}) {
  const host = normalizeDomain(name) || String(name || '').trim().toLowerCase();
  const started = Date.now();
  if (!host) {
    return { ok: false, error: '域名格式不正确', name, type, answers: [], elapsed: 0 };
  }
  if (!upstream || !upstream.url) {
    return { ok: false, error: '未找到可用的 DoH 上游', name: host, type, answers: [], elapsed: 0 };
  }
  if (!TYPE_NUM[type] && type !== 'ANY') {
    return { ok: false, error: `不支持的记录类型：${type}`, name: host, type, answers: [], elapsed: 0 };
  }

  const url = buildUrl(upstream, host, type);

  // 只允许 https（明文 http 仅限本机回环），否则查询的域名会明文暴露给中间人
  const endpoint = checkEndpoint(url);
  if (!endpoint.ok) {
    return {
      ok: false, error: `上游地址不被允许：${endpoint.reason}`, name: host, type, answers: [],
      elapsed: Date.now() - started, upstreamId: upstream.id,
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, Number(timeout) || 5000));

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'follow',
      referrerPolicy: 'no-referrer',
    });
    if (!res.ok) {
      return {
        ok: false, error: `HTTP ${res.status}`, name: host, type, answers: [],
        elapsed: Date.now() - started, upstreamId: upstream.id,
      };
    }
    // 跟随重定向后可能被降级到 http（含回环），这里用初始地址做基线再校验一次
    const redirected = checkRedirectTarget(url, res.url);
    if (!redirected.ok) {
      return {
        ok: false, error: redirected.reason, name: host, type, answers: [],
        elapsed: Date.now() - started, upstreamId: upstream.id,
      };
    }
    const text = await readTextCapped(res, MAX_DOH_BYTES);
    const json = JSON.parse(text);
    const answers = parseAnswers(json);
    const rcode = Number(json?.Status ?? 0);
    return {
      ok: rcode === 0,
      rcode,
      status: RCODE_TEXT[rcode] || `RCODE_${rcode}`,
      error: rcode === 0 ? null : (RCODE_TEXT[rcode] || `RCODE_${rcode}`),
      name: host,
      type,
      answers,
      ttl: minTtl(answers),
      elapsed: Date.now() - started,
      upstreamId: upstream.id,
      upstreamName: upstream.name,
      truncated: Boolean(json?.TC),
      at: started,
    };
  } catch (err) {
    const aborted = err?.name === 'AbortError';
    return {
      ok: false,
      error: aborted ? `请求超时（${timeout}ms）` : (err?.message || '网络错误'),
      name: host,
      type,
      answers: [],
      elapsed: Date.now() - started,
      upstreamId: upstream.id,
      upstreamName: upstream.name,
      at: started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 按分流规则为域名选择上游（等价 mosdns 的 sequence + upstream 选择）
 * @param {string} name
 * @param {object} dnsConfig state.dns
 * @returns {{upstream:object, matched:object|null}}
 */
export function pickUpstream(name, dnsConfig = {}) {
  const host = normalizeDomain(name) || String(name || '').toLowerCase();
  const custom = dnsConfig.customUpstreams || [];
  for (const entry of dnsConfig.split || []) {
    if (!entry || !entry.pattern) continue;
    const rule = parseRuleLine(entry.pattern);
    if (!rule) continue;
    if (!testRule(rule, host)) continue;
    const upstream = resolveUpstream(entry.upstream, custom);
    if (upstream) return { upstream, matched: entry };
  }
  const fallback = resolveUpstream(dnsConfig.defaultUpstream, custom);
  return { upstream: fallback, matched: null };
}
