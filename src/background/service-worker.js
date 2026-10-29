/**
 * SplitDNS - Service Worker（MV3）
 *
 * 职责：
 *  1. 状态读写（chrome.storage.local）
 *  2. 把规则编译为 DNR 动态规则（拦截 / 白名单 / 重定向）
 *  3. 按域名分流到 PAC 代理（可选，需 proxy 权限）
 *  4. 提供 DoH 解析服务与查询缓存
 *  5. 处理 popup / options 页面的消息
 *
 * 注意：MV3 的 Service Worker 随时可能被回收，因此所有状态都必须落在 storage 中，
 * 模块级变量只作为一次性缓存使用。
 */

import {
  getState, patchState, saveState, defaultState, getRuntime, patchRuntime,
  getLog, appendLog, clearLog, migrate, estimateStateSize, STATE_BUDGET_BYTES,
} from './state.js';
import { syncRules, setBuiltinRuleset, getBuiltinRulesetState } from './dnr.js';
import { applyProxy, hasProxyPermission, readProxySetting } from './proxy.js';
import { resolve, pickUpstream } from '../lib/doh.js';
import { resolveUpstream, listUpstreams } from '../lib/providers.js';
import { cacheGet, cachePut, cacheClear, cacheStats } from './cache.js';
import { compileState, matchHost, matchAll, normalizeDomain } from '../lib/matcher.js';
import { checkEndpoint, checkRedirectTarget, readTextCapped } from '../lib/util.js';

/** 订阅规则文件上限 2MB（正常规则表远小于此） */
const MAX_SUB_BYTES = 2 * 1024 * 1024;
/** 导入配置文件上限 4MB */
const MAX_IMPORT_BYTES = 4 * 1024 * 1024;

/* ------------------------------------------------------------------ */
/* 核心流程                                                            */
/* ------------------------------------------------------------------ */

/** 把状态应用到浏览器：DNR 规则 + 内置规则集 + 代理 */
async function applyAll(state) {
  const compiled = compileState(state);
  const active = Boolean(state.enabled);

  // 总开关必须覆盖全部能力，否则用户以为已暂停、实际流量还在走代理/静态规则集。
  // 注意：这里只改"生效状态"，不改 state.proxy.enabled —— 用户配置要保留，重新启用时自动恢复。
  const builtin = await syncBuiltinRuleset(active, Boolean(state.builtinRuleset));

  const dnr = await syncRules(state, compiled);

  let proxy = { active: false, error: null };
  try {
    const effective = active ? state : { ...state, proxy: { ...state.proxy, enabled: false } };
    proxy = await applyProxy(effective, compiled.groups);
    if (!active && proxy.active === false && !proxy.error) proxy.paused = true;
  } catch (err) {
    proxy = { active: false, error: err?.message || String(err) };
  }

  const runtime = await patchRuntime({
    dnr, proxy, counts: compiled.counts, builtinRuleset: builtin, at: Date.now(),
  });
  await updateBadge(state, runtime);
  return {
    runtime,
    counts: compiled.counts,
    invalid: compiled.invalid.slice(0, 50),
    skipped: (compiled.skipped || []).slice(0, 50),
    storage: { usedBytes: estimateStateSize(state), budgetBytes: STATE_BUDGET_BYTES },
  };
}

/** 内置静态规则集只在"总开关开启且用户勾选"时启用 */
async function syncBuiltinRuleset(active, wanted) {
  const target = active && wanted;
  const current = await getBuiltinRulesetState();
  if (current === target) return current;
  await setBuiltinRuleset(target);
  return getBuiltinRulesetState();
}

/** 工具栏角标：仅在出错时提示，平时保持干净 */
async function updateBadge(state, runtime) {
  try {
    if (!state.enabled) {
      await chrome.action.setBadgeText({ text: '' });
      await chrome.action.setTitle({ title: 'SplitDNS 已暂停' });
      return;
    }
    if (runtime?.dnr?.error) {
      await chrome.action.setBadgeBackgroundColor({ color: '#d93025' });
      await chrome.action.setBadgeText({ text: '!' });
      await chrome.action.setTitle({ title: `SplitDNS 规则同步失败：${runtime.dnr.error}` });
      return;
    }
    await chrome.action.setBadgeBackgroundColor({ color: '#2563eb' });
    await chrome.action.setBadgeText({ text: '' });
    await chrome.action.setTitle({ title: 'SplitDNS 运行中' });
  } catch {
    /* 角标失败不影响功能 */
  }
}

/** 带分流的 DoH 解析（含缓存与日志） */
async function resolveWithSplit(state, name, type = 'A') {
  const host = normalizeDomain(name) || String(name || '').trim().toLowerCase();
  if (!host) return { ok: false, error: '域名格式不正确', name: String(name || ''), answers: [] };

  // 总开关关闭时不得再把域名发给上游（隐私承诺的一部分）
  if (state.enabled === false) {
    return { ok: false, paused: true, error: 'SplitDNS 已暂停，启用后才能发起 DoH 查询', name: host, type, answers: [] };
  }

  const dns = state.dns || {};
  const { upstream, matched } = pickUpstream(host, dns);
  if (!upstream) {
    return { ok: false, error: '未找到可用的 DoH 上游，请检查上游设置', name: host, type, answers: [] };
  }

  const cacheCfg = dns.cache || {};
  if (cacheCfg.enabled !== false) {
    const hit = await cacheGet(upstream.id, type, host);
    if (hit) {
      await recordLog(state, { ...hit, name: host, type, upstreamName: upstream.name, matched: matched?.pattern || null });
      return { ...hit, matched: matched?.pattern || null };
    }
  }

  const result = await resolve(host, { type, upstream, timeout: dns.timeoutMs });
  if (result.ok && cacheCfg.enabled !== false) {
    await cachePut(upstream.id, type, host, result, {
      minTtl: cacheCfg.minTtl,
      maxTtl: cacheCfg.maxTtl,
      maxEntries: cacheCfg.maxEntries,
    });
  }
  const payload = { ...result, matched: matched?.pattern || null, cached: false };
  await recordLog(state, payload);
  return payload;
}

async function recordLog(state, payload) {
  if (state.log?.enabled === false) return;
  await appendLog({
    name: payload.name,
    type: payload.type,
    upstream: payload.upstreamName || payload.upstreamId || '—',
    status: payload.ok ? (payload.status || 'NOERROR') : (payload.error || 'ERROR'),
    ok: Boolean(payload.ok),
    ms: payload.elapsed || 0,
    cached: Boolean(payload.cached),
    count: Array.isArray(payload.answers) ? payload.answers.length : 0,
    matched: payload.matched || null,
    at: Date.now(),
  }, state.log?.max);
}

/** 剥离规则正文，供 popup 使用 */
function stripTexts(state) {
  const lists = {};
  for (const [key, list] of Object.entries(state.lists || {})) {
    lists[key] = { enabled: list.enabled, text: '' };
  }
  return {
    ...state,
    lists,
    subscriptions: (state.subscriptions || []).map((sub) => ({ ...sub, text: '' })),
  };
}

/* ------------------------------------------------------------------ */
/* 消息路由                                                            */
/* ------------------------------------------------------------------ */

/**
 * 会写状态的入口串行执行。
 *
 * `syncRules()` 是「getDynamicRules → updateDynamicRules」两步，
 * `state:patch` 是「读 → 改 → 写」，二者都没有原子性。
 * 快速连点或 popup 与 options 同时操作时，两次执行会交错，
 * 最终生效的规则可能与界面显示不一致。这里用一条 Promise 链把写操作排队。
 */
let mutationChain = Promise.resolve();

function serialize(task) {
  const result = mutationChain.then(task, task);
  // 链条自身吞掉异常，避免一次失败卡死后续所有写操作
  mutationChain = result.then(() => {}, () => {});
  return result;
}

/** 需要串行化的消息类型 */
const MUTATING_TYPES = new Set([
  'state:patch', 'state:replace', 'state:reset', 'rules:sync',
  'proxy:apply', 'proxy:clear', 'ruleset:set', 'import', 'ui:remember', 'rules:append',
]);

const handlers = {
  /**
   * 一次性拿到 UI 需要的全部数据。
   * light=true 时剥离规则文本：popup 只显示计数，没必要为了开个弹窗
   * 把几百 KB ~ 几 MB 的规则全量传过去并反序列化。
   */
  async 'state:get'({ light = false } = {}) {
    const state = await getState();
    const runtime = await getRuntime();
    const compiled = compileState(state);
    const cache = await cacheStats();
    const view = light ? stripTexts(state) : state;
    return {
      state: view,
      storage: { usedBytes: estimateStateSize(state), budgetBytes: STATE_BUDGET_BYTES },
      runtime,
      counts: compiled.counts,
      invalid: compiled.invalid.slice(0, 50),
      skipped: (compiled.skipped || []).slice(0, 50),
      cache,
      builtinRuleset: await getBuiltinRulesetState(),
      proxyPermission: await hasProxyPermission(),
      proxySetting: await readProxySetting(),
      upstreams: listUpstreams(state.dns?.customUpstreams),
      version: chrome.runtime.getManifest().version,
    };
  },

  /** 局部更新状态并立即生效 */
  async 'state:patch'({ patch }) {
    const state = await patchState(patch || {});
    const applied = await applyAll(state);
    return { state, ...applied };
  },

  /** 整体替换（导入用） */
  async 'state:replace'({ state }) {
    const next = await saveState(migrate(state));
    const applied = await applyAll(next);
    return { state: next, ...applied };
  },

  async 'state:reset'() {
    const next = await saveState(defaultState());
    const applied = await applyAll(next);
    return { state: next, ...applied };
  },

  /** 手动重新编译规则 */
  async 'rules:sync'() {
    const state = await getState();
    const applied = await applyAll(state);
    return applied;
  },

  /** 规则测试：返回所有命中项与最终判定 */
  async 'rules:test'({ url, host }) {
    const state = await getState();
    const compiled = compileState(state);
    const target = host || url || '';
    const final = matchHost(compiled.groups, target);
    return {
      host: normalizeDomain(target) || target,
      hits: matchAll(compiled.groups, target),
      final,
      counts: compiled.counts,
    };
  },

  /**
   * 向某个列表头部追加一条规则。
   * 由后台完成"读取-判重-追加-保存-生效"，popup 不需要持有全量规则文本。
   */
  async 'rules:append'({ list, line }) {
    const target = ['block', 'direct', 'proxy'].includes(list) ? list : null;
    if (!target) throw new Error('未知的规则列表');
    const text = String(line || '').trim();
    if (!text || text.length > 200) throw new Error('规则格式不正确');

    const state = await getState();
    const current = state.lists[target].text || '';
    const exists = current.split(/\r?\n/).some((row) => row.trim() === text);
    if (exists) {
      return { added: false, reason: 'already-exists', counts: compileState(state).counts };
    }

    const nextText = `${text}\n${current}`.trimEnd() + '\n';
    const next = await saveState({
      ...state,
      lists: { ...state.lists, [target]: { ...state.lists[target], text: nextText } },
    });
    const applied = await applyAll(next);
    return { added: true, counts: applied.counts };
  },

  /** DoH 解析（走分流规则） */
  async 'dns:resolve'({ name, type = 'A' }) {
    const state = await getState();
    if (!state.enabled) throw new Error('SplitDNS 已暂停，请先启用再发起查询');
    return resolveWithSplit(state, name, type);
  },

  /** 指定上游解析（用于设置页的上游连通性测试） */
  async 'dns:test'({ name, type = 'A', upstreamId }) {
    const state = await getState();
    if (!state.enabled) throw new Error('SplitDNS 已暂停，请先启用再发起查询');
    const upstream = resolveUpstream(upstreamId || state.dns.defaultUpstream, state.dns?.customUpstreams);
    if (!upstream) return { ok: false, error: '上游不存在' };
    return resolve(name, { type, upstream, timeout: state.dns?.timeoutMs });
  },

  async 'cache:clear'() {
    await cacheClear();
    return { ok: true, cache: await cacheStats() };
  },

  async 'log:get'() {
    return { log: await getLog() };
  },

  async 'log:clear'() {
    await clearLog();
    return { ok: true };
  },

  /**
   * 显式应用代理。
   * 注意：必须走 applyAll 统一门控——否则总开关关闭时这个入口能把 PAC 重新写回去，
   * "暂停即全部停止"的承诺就被绕过了。
   */
  async 'proxy:apply'() {
    const state = await getState();
    const applied = await applyAll(state);
    return { proxy: applied.runtime.proxy, runtime: applied.runtime, paused: !state.enabled };
  },

  async 'proxy:clear'() {
    const next = await patchState({ proxy: { enabled: false } });
    const applied = await applyAll(next);
    return { proxy: applied.runtime.proxy, state: next };
  },

  async 'proxy:status'() {
    return {
      permission: await hasProxyPermission(),
      setting: await readProxySetting(),
    };
  },

  /**
   * 开关内置静态规则集。
   * 这里只修改"用户期望配置"，实际生效状态一律由 applyAll 决定：
   * 暂停期间即使勾选也不会真正启用。
   */
  async 'ruleset:set'({ enabled }) {
    const next = await patchState({ builtinRuleset: Boolean(enabled) });
    const applied = await applyAll(next);
    return {
      ok: true,
      state: next,
      builtinRuleset: applied.runtime.builtinRuleset,
      wanted: next.builtinRuleset,
      paused: !next.enabled,
    };
  },

  /** 拉取订阅规则（需要对应站点的 host 权限，由 options 页申请） */
  async 'sub:fetch'({ url }) {
    const target = String(url || '').trim();
    const endpoint = checkEndpoint(target);
    if (!endpoint.ok) throw new Error(`订阅地址不被允许：${endpoint.reason}`);
    if (endpoint.insecure) throw new Error('订阅地址不能使用明文 http，请改用 https');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const res = await fetch(target, {
        signal: controller.signal,
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // 重定向可能把 https 降级成 http（含回环地址），以初始地址为基线校验最终地址
      const redirected = checkRedirectTarget(target, res.url);
      if (!redirected.ok) throw new Error(redirected.reason);

      // 先看 Content-Length，再按字节流读取，避免"读完 8MB 才说太大"
      const text = await readTextCapped(res, MAX_SUB_BYTES);
      const compiled = compileState({
        lists: {
          block: { enabled: true, text },
          direct: { enabled: false, text: '' },
          proxy: { enabled: false, text: '' },
          redirect: { enabled: false, text: '' },
        },
        subscriptions: [],
      });
      return { text, lines: text.split(/\r?\n/).length, rules: compiled.counts.block };
    } catch (err) {
      throw new Error(err?.name === 'AbortError' ? '请求超时' : (err?.message || '网络错误'));
    } finally {
      clearTimeout(timer);
    }
  },

  /** 只记住 UI 状态，不触发规则重建 */
  async 'ui:remember'({ tab }) {
    const state = await getState();
    if (!tab || state.ui?.lastTab === tab) return { ok: true, skipped: true };
    await patchState({ ui: { lastTab: tab } });
    return { ok: true };
  },

  async 'export'() {
    const state = await getState();
    return {
      json: JSON.stringify({ app: 'splitdns', schemaVersion: state.schemaVersion, exportedAt: Date.now(), state }, null, 2),
    };
  },

  async 'import'({ json }) {
    if (typeof json === 'string' && json.length > MAX_IMPORT_BYTES) {
      throw new Error(`配置文件过大（上限 ${Math.round(MAX_IMPORT_BYTES / 1024)} KB）`);
    }
    let parsed;
    try {
      parsed = typeof json === 'string' ? JSON.parse(json) : json;
    } catch (err) {
      throw new Error(`配置文件不是合法 JSON：${err?.message || err}`);
    }
    const incoming = parsed?.state || parsed;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      throw new Error('文件内容不是合法的 SplitDNS 配置');
    }
    // migrate 会按白名单重建整个状态（枚举校验、类型收敛、长度截断），
    // 因此恶意配置里的异常字段不会进入运行期。
    const next = await saveState(migrate(incoming));
    const applied = await applyAll(next);
    return { state: next, ...applied };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 只接受本扩展自身页面（popup / options）的消息。
  //
  // 未声明 externally_connectable 时，Chrome 的默认行为是"所有扩展都能连"，
  // 因此同机任意扩展都可以向这里发消息。若不校验来源，别的扩展只需一条
  // state:replace 就能改掉 proxy.server，把浏览器全部流量导向它控制的代理。
  // manifest 里同时声明了 externally_connectable.ids = [] 做第二层限制，
  // 但代码校验才是真正的边界，不依赖 manifest 是否正确。
  if (sender?.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: '非法消息来源' });
    return false;
  }

  const handler = handlers[message?.type];
  if (!handler) {
    sendResponse({ ok: false, error: `未知消息类型：${message?.type}` });
    return false;
  }
  const payload = message.payload || {};
  const invoke = () => handler(payload, sender);
  try {
    Promise.resolve(MUTATING_TYPES.has(message.type) ? serialize(invoke) : invoke())
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
  } catch (err) {
    sendResponse({ ok: false, error: err?.message || String(err) });
    return false;
  }
  return true; // 异步响应
});

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async (details) => {
  const state = await getState();
  if (details.reason === 'install') {
    await saveState(state);
  }
  // 生命周期回调与 onMessage 是两条入口，必须进同一条队列，
  // 否则安装/启动瞬间（此时订阅刚拉完、状态最可能被改）会与并发写操作交错。
  await serialize(() => applyAll(state));
});

chrome.runtime.onStartup.addListener(async () => {
  const state = await getState();
  await serialize(() => applyAll(state));
});

// Service Worker 首次唤醒时也做一次轻量同步，避免规则与状态漂移
(async () => {
  try {
    const state = await getState();
    const runtime = await getRuntime();
    // 超过 6 小时未同步，或从未同步过，则重建一次
    if (!runtime?.dnr?.at || Date.now() - runtime.dnr.at > 6 * 3600 * 1000) {
      await serialize(() => applyAll(state));
    }
  } catch {
    /* 忽略启动期异常 */
  }
})();
