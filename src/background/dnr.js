/**
 * SplitDNS - 规则编译为 declarativeNetRequest 动态规则
 *
 * MV3 中无法使用 blocking webRequest，因此把 mosdns 的"匹配 + 动作"编译为 DNR 规则：
 *   direct / @@ 例外  -> action: allow   （优先级 1000，覆盖拦截）
 *   block             -> action: block   （优先级 500）
 *   redirect          -> action: redirect + URLTransform（优先级 400）
 *   proxy             -> 不进 DNR，交由 PAC 处理（见 pac.js）
 *
 * 所有规则都显式声明 resourceTypes，因为 DNR 在不声明时默认不匹配 main_frame，
 * 会导致"整站拦截"失效。
 */

import { compileState, KIND } from '../lib/matcher.js';

// 只使用长期稳定的资源类型。较新的类型（如 webtransport / webbundle）在旧版浏览器上
// 可能不被识别，一旦出现未知类型会导致整批 updateDynamicRules 失败，故不列入。
const ALL_RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object',
  'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'other',
];

const PRIORITY = { allow: 1000, block: 500, redirect: 400 };

const DNR = () => (typeof chrome !== 'undefined' ? chrome.declarativeNetRequest : null);

function limits() {
  const api = DNR();
  return {
    dynamic: api?.MAX_NUMBER_OF_DYNAMIC_RULES || 5000,
    regex: api?.MAX_NUMBER_OF_REGEX_RULES || 1000,
  };
}

/** 正则元字符转义，用于把 keyword 的值安全嵌进 regexFilter */
function escapeRegex(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 把"主机名正则"包装成"URL 正则"。
 *
 * JS 引擎对主机名求值，DNR 对整条 URL 求值。直接下发用户正则会让 `^ad\d+\.`
 * 永远匹配不上（URL 以 `https://` 开头），规则静默失效。
 *
 * 包装规则：
 *   ^ad\d+\.   ->  ^(?:https?|wss?)://ad\d+\.[^/?#]*        （^ 表示主机开头）
 *   ad\d+$     ->  ^(?:https?|wss?)://[^/?#]*ad\d+(?:[:/?#]|$)（$ 表示主机结尾）
 *   ad\d+\.    ->  ^(?:https?|wss?)://[^/?#]*(?:ad\d+\.)[^/?#]*
 *
 * `[^/?#]*` 保证用户正则只能在主机名区间内匹配，不会串到 path/query。
 * 中间出现的 ^ / $ 已在 inspectRegex 阶段拒绝，因此该映射是无损的。
 */
function wrapHostRegex(pattern) {
  let body = String(pattern);
  let prefix = '[^/?#]*';
  let suffix = '[^/?#]*';

  if (body.startsWith('^')) {
    body = body.slice(1);
    prefix = '';
  }
  if (body.endsWith('$') && !body.endsWith('\\$')) {
    body = body.slice(0, -1);
    suffix = '(?:[:/?#]|$)';
  }
  return `^(?:https?|wss?)://${prefix}(?:${body})${suffix}`;
}

/**
 * 规则 -> DNR 条件数组。
 *
 * keyword 必须用锚定主机名的 regexFilter，不能用裸 urlFilter：
 * `urlFilter: "cdn"` 是无锚点子串匹配，会连 path/query 一起匹配
 * （`https://evil.com/x?cdn=1` 也命中），与 JS 引擎"只匹配主机名"的语义不一致；
 * 放在直连列表时还会生成过宽的 allow，反过来压掉用户自己的 block。
 *
 * full 需要覆盖 http/https/ws/wss 四种 scheme，否则 `full:` 规则在 websocket 上
 * 与 JS 引擎结论不一致（JS 只看主机名，不看 scheme）。
 *
 * 导出以便测试做"双引擎差分比对"。
 */
export function conditionsFor(rule) {
  // 显式声明不区分大小写：DNR 默认就是 false，但写出来才能保证
  // 「规则条件」与「JS 引擎的 i 标志」始终一致，不受浏览器默认值变化影响。
  const withCase = (condition) => ({ ...condition, isUrlFilterCaseSensitive: false });

  switch (rule.kind) {
    case KIND.FULL:
      return [
        withCase({ urlFilter: `|http://${rule.value}^` }),
        withCase({ urlFilter: `|https://${rule.value}^` }),
        withCase({ urlFilter: `|ws://${rule.value}^` }),
        withCase({ urlFilter: `|wss://${rule.value}^` }),
      ];
    case KIND.KEYWORD:
      return [withCase({ regexFilter: `^(?:https?|wss?)://[^/?#]*${escapeRegex(rule.value)}[^/?#]*` })];
    case KIND.REGEXP:
      return [withCase({ regexFilter: wrapHostRegex(rule.value) })];
    default:
      return [withCase({ urlFilter: `||${rule.value}^` })];
  }
}

/** 解析重定向目标为 DNR 的 transform 动作 */
export function redirectAction(target) {
  const raw = String(target || '').trim();
  if (!raw) return null;
  const match = /^(?:([a-z][a-z0-9+.-]*):\/\/)?([^/?#]+)([/?#].*)?$/i.exec(raw);
  if (!match) return null;
  let scheme = match[1] ? match[1].toLowerCase() : null;
  // 端口无法通过 DNR 的 URLTransform 表达（只支持 host / scheme），
  // 静默丢弃会让重定向落到默认端口，与用户写的地址不符 —— 直接拒绝。
  if (/:\d+$/.test(match[2])) return null;
  let host = match[2].toLowerCase();
  host = host.replace(/\.+$/, '');
  if (!host || !/^[a-z0-9.-]+$/.test(host)) return null;
  if (scheme && !['http', 'https'].includes(scheme)) return null;
  const transform = { host };
  if (scheme) transform.scheme = scheme;
  return { type: 'redirect', redirect: { transform } };
}

/**
 * 构建动态规则数组
 * @returns {{rules:Array, skipped:number, regexUsed:number, stats:object}}
 */
export function buildDynamicRules(groups, { maxDynamic, maxRegex } = {}) {
  const lim = limits();
  const capDynamic = maxDynamic || lim.dynamic;
  const capRegex = maxRegex || lim.regex;

  const rules = [];
  const stats = { allow: 0, block: 0, redirect: 0, regexUsed: 0, skipped: 0, skippedRedirect: 0 };
  let nextId = 1;

  /** @returns {boolean} 是否真的写入（配额不足时返回 false，调用方据此决定是否计数） */
  const push = (condition, action, priority) => {
    if (rules.length >= capDynamic) {
      stats.skipped += 1;
      return false;
    }
    if (condition.regexFilter) {
      if (stats.regexUsed >= capRegex) {
        stats.skipped += 1;
        return false;
      }
      stats.regexUsed += 1;
    }
    rules.push({
      id: nextId++,
      priority,
      action,
      condition: { ...condition, resourceTypes: ALL_RESOURCE_TYPES },
    });
    return true;
  };

  // 1) 直连 / 白名单
  for (const rule of groups.direct || []) {
    for (const condition of conditionsFor(rule)) {
      if (push(condition, { type: 'allow' }, PRIORITY.allow)) stats.allow += 1;
    }
  }

  // 2) 拦截（含 @@ 例外）
  for (const rule of groups.block || []) {
    const isException = Boolean(rule.exception);
    for (const condition of conditionsFor(rule)) {
      const written = push(condition, { type: isException ? 'allow' : 'block' }, isException ? PRIORITY.allow : PRIORITY.block);
      if (written) {
        if (isException) stats.allow += 1;
        else stats.block += 1;
      }
    }
  }

  // 3) 重定向
  for (const rule of groups.redirect || []) {
    const action = redirectAction(rule.target);
    if (!action) {
      stats.skippedRedirect += 1;
      continue;
    }
    for (const condition of conditionsFor(rule)) {
      if (push(condition, action, PRIORITY.redirect)) stats.redirect += 1;
    }
  }

  return { rules, skipped: stats.skipped, regexUsed: stats.regexUsed, stats };
}

/** 过滤掉 DNR 一定拒绝的规则，避免整批失败 */
async function sanitize(rules) {
  const api = DNR();
  const out = [];
  let dropped = 0;
  for (const rule of rules) {
    const cond = rule.condition || {};
    if (cond.urlFilter !== undefined) {
      const filter = String(cond.urlFilter);
      if (!filter || filter.length > 2000 || !/^[\x21-\x7e]+$/.test(filter)) {
        dropped += 1;
        continue;
      }
    }
    if (cond.regexFilter !== undefined) {
      const regex = String(cond.regexFilter);
      if (!regex || !/^[\x20-\x7e]+$/.test(regex)) {
        dropped += 1;
        continue;
      }
      // isRegexSupported 在 Chrome 87+ 就有；这里仍做能力检测，
      // 避免在裁剪过的 API 环境（如某些企业策略、未来改名）下整批规则被丢弃。
      if (typeof api.isRegexSupported !== 'function') {
        out.push(rule);
        continue;
      }
      try {
        // eslint-disable-next-line no-await-in-loop
        // 下发的条件显式声明 isUrlFilterCaseSensitive: false，探测也用同样口径
        const support = await api.isRegexSupported({ regex, isCaseSensitive: false });
        if (!support?.isSupported) {
          dropped += 1;
          continue;
        }
      } catch {
        dropped += 1;
        continue;
      }
    }
    out.push(rule);
  }
  return { rules: out, dropped };
}

/**
 * 把状态同步到 DNR。总是先清空本扩展的全部动态规则，再按当前状态重建，
 * 保证不会出现"删了规则但浏览器还在拦"的脏状态。
 */
export async function syncRules(state, precompiled) {
  const api = DNR();
  if (!api) return { error: '当前环境不支持 declarativeNetRequest' };

  const compiled = precompiled || compileState(state);
  const existing = await api.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);

  let built = { rules: [], skipped: 0, regexUsed: 0, stats: {} };
  if (state.enabled) built = buildDynamicRules(compiled.groups);

  const runtime = {
    at: Date.now(),
    enabled: Boolean(state.enabled),
    added: 0,
    skipped: built.skipped || 0,
    regexUsed: built.regexUsed || 0,
    stats: built.stats || {},
    counts: compiled.counts,
    invalid: compiled.invalid.slice(0, 50),
    skippedRules: (compiled.skipped || []).slice(0, 50),
    error: null,
    warning: null,
    keptPrevious: false,
  };

  try {
    await api.updateDynamicRules({ removeRuleIds, addRules: built.rules });
    runtime.added = built.rules.length;
  } catch (err) {
    // 逐条校验后重试一次，尽量把可用规则装进去
    try {
      const { rules, dropped } = await sanitize(built.rules);
      const clean = rules.map((rule, index) => ({ ...rule, id: index + 1 }));
      const currentIds = await api.getDynamicRules().then((rs) => rs.map((r) => r.id));
      await api.updateDynamicRules({ removeRuleIds: currentIds, addRules: clean });
      runtime.added = clean.length;
      runtime.warning = `已丢弃 ${dropped} 条不合法规则：${err?.message || err}`;
    } catch (err2) {
      // 关键：不再清空既有规则。
      // updateDynamicRules 是原子的，上面两次失败都意味着浏览器里的规则没被改动，
      // 此时保留上一份已知可用的规则，避免"同步失败 → 保护全没了"的 fail-open。
      const kept = await api.getDynamicRules().catch(() => []);
      runtime.added = kept.length;
      runtime.keptPrevious = true;
      runtime.error = `${err2?.message || err2}（已保留上一份可用规则 ${kept.length} 条）`;
    }
  }

  // runtime 由调用方（applyAll）统一持久化，这里只返回，避免一次保存写两遍存储
  return runtime;
}

/** 启用/停用内置静态规则集 */
export async function setBuiltinRuleset(enabled) {
  const api = DNR();
  if (!api?.updateEnabledRulesets) return false;
  try {
    await api.updateEnabledRulesets({
      enableRulesetIds: enabled ? ['builtin-ads'] : [],
      disableRulesetIds: enabled ? [] : ['builtin-ads'],
    });
    return true;
  } catch {
    return false;
  }
}

/** 当前内置规则集是否启用 */
export async function getBuiltinRulesetState() {
  const api = DNR();
  if (!api?.getEnabledRulesets) return false;
  const ids = await api.getEnabledRulesets();
  return ids.includes('builtin-ads');
}
