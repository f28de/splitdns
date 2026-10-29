/**
 * SplitDNS - 规则解析 / 匹配引擎
 *
 * 规则语法参考 mosdns 的 domain matcher，并兼容常见的 hosts 与 Adblock 域名语法。
 * 支持的前缀：
 *   domain:example.com     后缀匹配（含自身与所有子域）
 *   full:www.example.com   精确匹配
 *   keyword:example        关键字匹配（对主机名做子串匹配）
 *   regexp:^ad\d+\.        正则匹配（计入 DNR 正则配额）
 * 不带前缀时按 domain（后缀）处理。
 * 兼容语法：
 *   0.0.0.0 example.com    hosts 文件格式
 *   ||example.com^         Adblock 域名锚定
 *   @@||example.com^       Adblock 例外（等价于白名单 / 直连）
 *   domain:old.com => new.com   重定向（仅重写列表使用）
 */

export const KIND = {
  DOMAIN: 'domain',
  FULL: 'full',
  KEYWORD: 'keyword',
  REGEXP: 'regexp',
};

export const KIND_LABEL = {
  domain: '后缀',
  full: '精确',
  keyword: '关键字',
  regexp: '正则',
};

const PREFIXES = [
  ['full:', KIND.FULL],
  ['domain:', KIND.DOMAIN],
  ['suffix:', KIND.DOMAIN],
  ['keyword:', KIND.KEYWORD],
  ['regexp:', KIND.REGEXP],
  ['regex:', KIND.REGEXP],
];

const HOSTS_RE = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(\S+)/;
const DOMAIN_RE = /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$/;
const MAX_REGEX_LEN = 200;
const MAX_HOST_LEN = 253;
/** 单个列表允许的正则规则上限（正则最耗 CPU，且无法完全排除回溯风险） */
export const MAX_REGEX_RULES_PER_GROUP = 100;

/* ------------------------------------------------------------------ */
/* 正则结构解析（静态 ReDoS 检测）                                      */
/* ------------------------------------------------------------------ */

/**
 * 为什么需要自己写解析器：
 * 用"另一组正则去扫括号"无法处理嵌套分组，`^((a)+)+$` 这类模式可以轻松绕过。
 * 因此这里把模式解析成语法树，再在树上判断"量词是否叠加在本身已含量词或选择支的
 * 子表达式之上"——这条规则对任意嵌套深度都成立，不依赖括号配对的文本特征。
 *
 * 局限（已在文档中说明）：这是静态近似，不是形式化证明。JS 正则不可中断、无超时，
 * 且扩展体积不允许内置 RE2，因此对不可信来源（订阅）的正则默认直接禁用。
 */

/** 单次重复上限：{200} 这类大次数在回溯时同样危险 */
const MAX_REPEAT = 100;
/** 有限重复叠加内层量词时的上限，例如 (a?){50} */
const MAX_REPEAT_NESTED = 10;

class RegexUnsafe extends Error {}
/** 语法上合法、但浏览器侧 RE2 不支持的构造 */
class RegexUnsupported extends Error {}

/**
 * 把正则解析成语法树。只做结构解析，不做语义校验（语义交给 new RegExp）。
 * 无法识别的字符按字面量处理，尽量不误伤合法规则。
 */
function parseRegexAst(pattern) {
  let i = 0;
  const len = pattern.length;
  /** 记录所有锚点原子的位置，用于判断 ^ / $ 是否只在首尾 */
  const anchors = [];

  const fail = (reason) => {
    throw new RegexUnsafe(reason);
  };

  function parseAtom() {
    const ch = pattern[i];

    if (ch === '\\') {
      const next = pattern[i + 1];
      if (next === undefined) fail('转义符结尾');
      if (/[1-9]/.test(next)) fail('回溯引用');
      if (next === 'k') fail('命名回溯引用');
      i += 2;
      return { type: 'atom', kind: 'escape' };
    }

    if (ch === '[') {
      i += 1;
      if (pattern[i] === '^') i += 1;
      if (pattern[i] === ']') i += 1;      // 首位 ] 是字面量
      while (i < len && pattern[i] !== ']') {
        if (pattern[i] === '\\') i += 1;
        i += 1;
      }
      if (i >= len) fail('字符组未闭合');
      i += 1;
      return { type: 'atom', kind: 'class' };
    }

    if (ch === '(') {
      if (pattern.startsWith('(?<=', i) || pattern.startsWith('(?<!', i)) {
        throw new RegexUnsupported('后向断言（浏览器侧的 RE2 不支持）');
      }
      i += 1;
      if (pattern[i] === '?') {
        i += 1;
        if (pattern[i] === ':') {
          i += 1;                           // (?:...)
        } else if (pattern[i] === '=' || pattern[i] === '!') {
          // 前瞻在 JS 里合法，但 DNR 用 RE2 执行，不支持前瞻 → 规则会在浏览器侧被丢弃，
          // 而 JS 引擎仍保留，造成"规则测试说命中、实际不生效"。这里直接拒绝。
          throw new RegexUnsupported('前瞻断言（浏览器侧的 RE2 不支持）');
        } else if (pattern[i] === '<') {
          const close = pattern.indexOf('>', i);   // (?<name>...)
          if (close < 0) fail('命名分组未闭合');
          i = close + 1;
        } else {
          // (?i) / (?i:...) 之类内联标志
          while (i < len && pattern[i] !== ':' && pattern[i] !== ')') i += 1;
          if (pattern[i] === ':') i += 1;
        }
      }
      const body = parseAlternation();
      if (pattern[i] !== ')') fail('分组未闭合');
      i += 1;
      return { type: 'group', body };
    }

    if (ch === ')') fail('多余的右括号');

    if (ch === '^' || ch === '$') {
      // 只把"原子位置"的 ^ / $ 记为锚点：字符类 [^a] / [a$] 内部由 parseAtom 的
      // 字符类分支整体跳过，不会走到这里，因此不会被误判为锚点。
      anchors.push({ char: ch, index: i });
      i += 1;
      return { type: 'atom', kind: ch };
    }

    i += 1;
    return { type: 'atom', kind: ch === '.' ? ch : 'literal' };
  }

  function parseQuantified() {
    let node = parseAtom();
    for (;;) {
      const ch = pattern[i];
      let min;
      let max;
      if (ch === '*') {
        min = 0; max = Infinity; i += 1;
      } else if (ch === '+') {
        min = 1; max = Infinity; i += 1;
      } else if (ch === '?') {
        min = 0; max = 1; i += 1;
      } else if (ch === '{') {
        const match = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(i));
        if (!match) return node;            // 不是量词，按字面量处理
        min = Number(match[1]);
        if (match[2] === undefined) max = min;
        else max = match[2] === '' ? Infinity : Number(match[2]);
        i += match[0].length;
      } else {
        return node;
      }
      if (pattern[i] === '?') i += 1;       // 惰性量词
      node = { type: 'quant', min, max, child: node };
    }
  }

  function parseSequence() {
    const items = [];
    while (i < len && pattern[i] !== '|' && pattern[i] !== ')') {
      items.push(parseQuantified());
    }
    return { type: 'seq', items };
  }

  function parseAlternation() {
    const options = [parseSequence()];
    while (pattern[i] === '|') {
      i += 1;
      options.push(parseSequence());
    }
    return options.length === 1 ? options[0] : { type: 'alt', options };
  }

  const ast = parseAlternation();
  if (i < len) fail('无法解析的尾部内容');
  return { ast, anchors };
}

function hasQuantifier(node) {
  if (!node) return false;
  if (node.type === 'quant') return true;
  if (node.type === 'seq') return node.items.some(hasQuantifier);
  if (node.type === 'alt') return node.options.some(hasQuantifier);
  if (node.type === 'group') return hasQuantifier(node.body);
  return false;
}

function hasAlternation(node) {
  if (!node) return false;
  if (node.type === 'alt') return true;
  if (node.type === 'seq') return node.items.some(hasAlternation);
  if (node.type === 'group') return hasAlternation(node.body);
  if (node.type === 'quant') return hasAlternation(node.child);
  return false;
}

/** 递归检查每个量词节点 */
function checkQuantifiers(node) {
  if (!node) return;
  if (node.type === 'seq') {
    for (const item of node.items) checkQuantifiers(item);
    return;
  }
  if (node.type === 'alt') {
    for (const option of node.options) checkQuantifiers(option);
    return;
  }
  if (node.type === 'group') {
    checkQuantifiers(node.body);
    return;
  }
  if (node.type !== 'quant') return;

  const unbounded = node.max === Infinity;
  const innerQuantifier = hasQuantifier(node.child);
  const innerAlternation = hasAlternation(node.child);

  if (unbounded && innerQuantifier) throw new RegexUnsafe('嵌套量词');
  if (unbounded && innerAlternation) throw new RegexUnsafe('分组选择支重复');
  if (!unbounded && node.max > MAX_REPEAT) throw new RegexUnsafe(`重复次数超过 ${MAX_REPEAT}`);
  if (!unbounded && node.max >= MAX_REPEAT_NESTED && innerQuantifier) throw new RegexUnsafe('有限重复叠加量词');

  checkQuantifiers(node.child);
}

/**
 * 锚点约束：正则只对主机名求值，因此 `^` 只能出现在开头、`$` 只能出现在结尾。
 *
 * 这条限制不是洁癖：浏览器侧（DNR）的正则是对整条 URL 执行的，本扩展会把
 * 主机名正则包装成 `^(?:https?|wss?)://<prefix><你的正则><suffix>`。
 * 只有"首 ^ / 尾 $"这一种锚点形式能被无损映射到 URL 上；中间的 `(^|\.)` 之类
 * 在包装后语义会变（`^` 变成"URL 开头"），导致两套引擎结论不一致。
 *
 * 判定基于语法树记录的锚点位置，而不是对字符串做 indexOf：
 * 后者会把字符类里的 `[^a]`、`[a$]` 误判成锚点，导致合法正则被整条丢弃。
 */
function checkAnchors(anchors, length) {
  for (const { char, index } of anchors) {
    if (char === '^' && index !== 0) return '^ 只能出现在正则开头（正则只对主机名求值）';
    if (char === '$' && index !== length - 1) return '$ 只能出现在正则结尾（正则只对主机名求值）';
  }
  return null;
}

/**
 * 统计"无界通配"（`.*` / `.+` / `.{n,}`）的个数。
 * 单个 `.*` 是线性的，但连续多个会让回溯退化成多项式：`^.*.*.*.*=.*$` 在 253 字符主机名上
 * 需要数亿步。匹配主机名用不到 3 个以上无界通配，超过就拒绝。
 */
function countUnboundedWildcards(node) {
  if (!node) return 0;
  if (node.type === 'quant') {
    const isWildcard = node.max === Infinity
      && node.child?.type === 'atom' && node.child.kind === '.';
    return (isWildcard ? 1 : 0) + countUnboundedWildcards(node.child);
  }
  if (node.type === 'seq') return node.items.reduce((sum, item) => sum + countUnboundedWildcards(item), 0);
  if (node.type === 'alt') return node.options.reduce((sum, item) => sum + countUnboundedWildcards(item), 0);
  if (node.type === 'group') return countUnboundedWildcards(node.body);
  return 0;
}

const MAX_UNBOUNDED_WILDCARDS = 2;

/**
 * 正则安全性检查。
 * @returns {{ok:boolean, reason?:string}}
 */
export function inspectRegex(pattern) {
  const p = String(pattern ?? '');
  if (!p) return { ok: false, reason: '空正则' };
  if (p.length > MAX_REGEX_LEN) return { ok: false, reason: `超过 ${MAX_REGEX_LEN} 字符` };
  if (!/^[\x20-\x7e]+$/.test(p)) return { ok: false, reason: '包含非 ASCII 字符' };

  try {
    const { ast, anchors } = parseRegexAst(p);

    const anchorError = checkAnchors(anchors, p.length);
    if (anchorError) return { ok: false, reason: anchorError };

    // 顶层选择支 + 首尾锚点：`^a|b$` 的语义是"以 a 开头 或 以 b 结尾"，
    // 但包装成 URL 正则时 body 会被整体塞进 (?:...)，锚点作用域被扩大到整条选择支，
    // 变成"(a 或 b) 同时贴住主机首尾"——两套引擎结论就不一致了。
    if (ast.type === 'alt' && anchors.length > 0) {
      return { ok: false, reason: '含顶层选择支时不能使用首尾锚点，请改用分组，如 ^(?:a|b)$' };
    }

    checkQuantifiers(ast);

    if (countUnboundedWildcards(ast) > MAX_UNBOUNDED_WILDCARDS) {
      return { ok: false, reason: `无界通配（.* / .+）超过 ${MAX_UNBOUNDED_WILDCARDS} 个，回溯代价过高` };
    }
  } catch (err) {
    if (err instanceof RegexUnsupported) return { ok: false, reason: err.message };
    if (err instanceof RegexUnsafe) return { ok: false, reason: `疑似灾难性回溯（${err.message}）` };
    return { ok: false, reason: '无法解析的正则结构' };
  }

  try {
    // eslint-disable-next-line no-new
    new RegExp(p);
  } catch {
    return { ok: false, reason: '正则语法错误' };
  }
  return { ok: true };
}

/** 兼容旧调用点 */
function isSafeRegex(pattern) {
  return inspectRegex(pattern).ok;
}

/** 主机名规范化：小写、去首尾点、去通配前缀 */
export function normalizeDomain(value) {
  let v = String(value ?? '').trim().toLowerCase();
  v = v.replace(/^[a-z]+:\/\//, '');      // 容错：用户误贴 URL
  v = v.replace(/[/?#].*$/, '');
  v = v.replace(/:\d+$/, '');
  v = v.replace(/^\*?\./, '').replace(/\.+$/, '');
  if (!v) return '';
  if (v.length > MAX_HOST_LEN) return '';
  if (!DOMAIN_RE.test(v)) return '';
  return v;
}

/** 是否注释 / 空行 */
export function isIgnorable(line) {
  const t = String(line ?? '').trim();
  return !t || t.startsWith('#') || t.startsWith('!') || t.startsWith('//');
}

function makeRule(kind, value, raw, extra = {}) {
  return {
    kind,
    value,
    raw: String(raw).trim(),
    exception: Boolean(extra.exception),
    target: extra.target || null,
    source: extra.source || 'manual',
  };
}

/**
 * 解析单行规则
 * @returns {{kind:string,value:string,raw:string,exception:boolean,target:string|null}|null}
 */
export function parseRuleLine(raw) {
  if (typeof raw !== 'string') return null;
  let line = raw.trim();
  if (isIgnorable(line)) return null;

  // 行尾注释（仅识别 " #" 以避免破坏正则）
  const hash = line.indexOf(' #');
  if (hash > 0) line = line.slice(0, hash).trim();
  if (!line) return null;

  // 元素隐藏等 cosmetic 规则（##、#@#、#?#、#$#）不是网络请求规则。
  // 必须在域名规范化之前拦下，否则 "example.com##.banner" 会被解析成 domain:example.com，
  // 导致整站被误拦截。正则规则里允许出现 '#'，因此放行 regexp:/regex: 前缀。
  if (line.includes('#') && !/^regexp?:/i.test(line)) return null;

  // hosts 文件格式
  const hostsMatch = HOSTS_RE.exec(line);
  if (hostsMatch) {
    const domain = normalizeDomain(hostsMatch[1]);
    return domain ? makeRule(KIND.DOMAIN, domain, raw) : null;
  }

  // Adblock 语法
  let exception = false;
  if (line.startsWith('@@')) {
    exception = true;
    line = line.slice(2).trim();
  }
  if (line.startsWith('||')) {
    const body = line.slice(2).replace(/\^+$/, '').replace(/[/:].*$/, '');
    const domain = normalizeDomain(body);
    if (domain && !/[*$|]/.test(domain)) return makeRule(KIND.DOMAIN, domain, raw, { exception });
    return null;
  }
  // 其余通配 / 路径类 Adblock 规则不支持，静默跳过
  if (/^[|*/]/.test(line)) return null;

  // 重定向目标
  let target = null;
  const arrow = line.indexOf('=>');
  if (arrow > 0) {
    target = line.slice(arrow + 2).trim();
    line = line.slice(0, arrow).trim();
  }
  if (!line) return null;

  let kind = KIND.DOMAIN;
  let value = line;
  const lower = line.toLowerCase();
  for (const [prefix, k] of PREFIXES) {
    if (lower.startsWith(prefix)) {
      kind = k;
      value = line.slice(prefix.length).trim();
      break;
    }
  }
  if (!value) return null;

  // `full:` 是精确匹配，写 `*` 说明用户想匹配子域（应该用 `domain:`）。
  // normalizeDomain 会把开头的 `*.` 剥掉，静默变成"精确匹配 example.com"，
  // 与用户意图正好相反 —— 宁可判为无效行。
  if (kind === KIND.FULL && value.includes('*')) return null;

  if (kind === KIND.REGEXP) {
    if (!isSafeRegex(value)) return null;
    return makeRule(kind, value, raw, { exception, target });
  }
  if (kind === KIND.KEYWORD) {
    if (value.length < 2 || /\s/.test(value)) return null;
    return makeRule(kind, value.toLowerCase(), raw, { exception, target });
  }
  const domain = normalizeDomain(value);
  if (!domain) return null;
  return makeRule(kind, domain, raw, { exception, target });
}

/** 把规则还原成文本形式 */
export function ruleToText(rule) {
  const prefix = rule.kind === KIND.DOMAIN ? '' : `${rule.kind}:`;
  const ex = rule.exception ? '@@' : '';
  const tail = rule.target ? ` => ${rule.target}` : '';
  return `${ex}${prefix}${rule.value}${tail}`;
}

/**
 * 编译一段文本为规则数组
 * @returns {{rules:Array, invalid:Array<string>}}
 */
export function compileText(text, source = 'manual') {
  const rules = [];
  const invalid = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (isIgnorable(line)) continue;
    const rule = parseRuleLine(line);
    if (rule) {
      rule.source = source;
      rules.push(rule);
    } else {
      invalid.push(line.trim());
    }
  }
  return { rules, invalid };
}

const LIST_KEYS = ['block', 'direct', 'proxy', 'redirect'];
/** 订阅写入这些列表会"放松"安全（解除拦截 / 改写主机），默认禁止 */
const TRUST_TARGETS = new Set(['direct', 'redirect']);

/**
 * 编译完整状态：合并手动规则与订阅规则
 * @returns {{groups:Object, invalid:Array, counts:Object}}
 */
export function compileState(state) {
  const groups = { block: [], direct: [], proxy: [], redirect: [] };
  const invalid = [];
  const skipped = [];   // 被安全策略主动跳过的规则（区别于"写错的规则"）
  const allowSubRegex = state?.security?.allowSubRegex === true;
  const allowSubTrust = state?.security?.allowSubTrust === true;

  const push = (target, text, source) => {
    const fromSubscription = source.startsWith('sub:');
    const { rules, invalid: bad } = compileText(text, source);

    // 订阅只能"收紧"，不能"放松"：
    // 写入直连列表可以解除用户手写的拦截，写入重定向列表可以把访问改到别的域名，
    // 二者都等于把安全决定权交给远程内容，因此默认整段跳过（需 security.allowSubTrust）。
    if (fromSubscription && TRUST_TARGETS.has(target) && !allowSubTrust && rules.length) {
      skipped.push({
        target,
        source,
        line: `${rules.length} 条规则`,
        reason: '订阅写入直连/重定向列表需在设置中显式允许',
      });
      for (const line of bad) invalid.push({ target, source, line });
      return;
    }

    for (const rule of rules) {
      // 订阅内容不可信：其中的正则默认不参与匹配，避免恶意订阅用灾难性回溯拖死后台
      if (rule.kind === KIND.REGEXP && fromSubscription && !allowSubRegex) {
        skipped.push({ target, source, line: rule.raw, reason: '订阅来源的正则规则默认禁用' });
        continue;
      }
      groups[target].push(rule);
    }
    for (const line of bad) invalid.push({ target, source, line });
  };

  for (const key of LIST_KEYS) {
    const list = state?.lists?.[key];
    if (!list || list.enabled === false) continue;
    push(key, list.text, `manual:${key}`);
  }

  for (const sub of state?.subscriptions || []) {
    if (!sub || sub.enabled === false || !sub.text) continue;
    if (!LIST_KEYS.includes(sub.target)) continue;
    push(sub.target, sub.text, `sub:${sub.name || sub.id}`);
  }

  const counts = {};
  for (const key of LIST_KEYS) {
    groups[key] = dedupe(groups[key]);
    // 正则规则配额：超出部分丢弃，避免匹配耗时随规则数无上限增长
    const regexRules = groups[key].filter((rule) => rule.kind === KIND.REGEXP);
    if (regexRules.length > MAX_REGEX_RULES_PER_GROUP) {
      const dropped = regexRules.slice(MAX_REGEX_RULES_PER_GROUP);
      for (const rule of dropped) {
        skipped.push({
          target: key,
          source: rule.source,
          line: rule.raw,
          reason: `超出单列表 ${MAX_REGEX_RULES_PER_GROUP} 条正则上限`,
        });
      }
      const dropSet = new Set(dropped);
      groups[key] = groups[key].filter((rule) => !dropSet.has(rule));
    }
    counts[key] = groups[key].length;
  }
  return { groups, invalid, counts, skipped };
}

/** 按 kind+value 去重，保留先出现者（手动规则优先于订阅） */
export function dedupe(rules) {
  const seen = new Set();
  const out = [];
  for (const rule of rules) {
    const key = `${rule.exception ? '@@' : ''}${rule.kind}:${rule.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(rule);
  }
  return out;
}

/**
 * 单条规则是否命中主机名。
 * 正则规则编译一次后缓存到规则对象上，避免每次匹配都 new RegExp（性能）；
 * 同时对超长输入直接判否，限制回溯的搜索空间。
 */
export function testRule(rule, host) {
  const h = String(host || '').toLowerCase();
  if (h.length > MAX_HOST_LEN) return false;
  switch (rule.kind) {
    case KIND.FULL:
      return h === rule.value;
    case KIND.KEYWORD:
      return h.includes(rule.value);
    case KIND.REGEXP: {
      try {
        // DNR 的 isUrlFilterCaseSensitive 默认 false（不区分大小写），这里用 i 标志对齐，
        // 否则 `regexp:ADS` 会在浏览器里命中、在规则测试器里显示未命中。
        if (!rule._re) rule._re = new RegExp(rule.value, 'i');
        return rule._re.test(h);
      } catch {
        return false;
      }
    }
    default:
      return h === rule.value || h.endsWith(`.${rule.value}`);
  }
}

/**
 * 判定主机名的最终动作（与运行期优先级保持一致）
 * 优先级：直连 > 拦截列表中的 @@ 例外 > 拦截 > 重定向 > 代理 > 默认
 *
 * 注意：同一列表内例外必须先于普通规则求值，否则 "a.com" 会先于 "@@||safe.a.com^"
 * 命中 safe.a.com，导致白名单失效（DNR 侧靠优先级 1000 保证，这里靠求值顺序保证）。
 * @returns {{action:string, rule:Object}|null}
 */
export function matchHost(groups, host) {
  const h = normalizeDomain(host) || String(host || '').toLowerCase();
  if (!h) return null;

  for (const rule of groups.direct || []) {
    if (testRule(rule, h)) return { action: 'direct', rule };
  }
  for (const rule of groups.block || []) {
    if (rule.exception && testRule(rule, h)) return { action: 'direct', rule };
  }
  for (const rule of groups.block || []) {
    if (!rule.exception && testRule(rule, h)) return { action: 'block', rule };
  }
  for (const rule of groups.redirect || []) {
    if (testRule(rule, h)) return { action: 'redirect', rule };
  }
  for (const rule of groups.proxy || []) {
    if (testRule(rule, h)) return { action: 'proxy', rule };
  }
  return null;
}

/** 返回所有命中的规则（用于规则测试面板），顺序与 matchHost 的求值顺序一致 */
export function matchAll(groups, host) {
  const h = normalizeDomain(host) || String(host || '').toLowerCase();
  const hits = [];
  if (!h) return hits;

  const collect = (key, predicate) => {
    for (const rule of groups[key] || []) {
      if (!predicate(rule) || !testRule(rule, h)) continue;
      hits.push({ action: key === 'block' && rule.exception ? 'direct' : key, rule });
    }
  };

  collect('direct', () => true);
  collect('block', (rule) => rule.exception);
  collect('block', (rule) => !rule.exception);
  collect('redirect', () => true);
  collect('proxy', () => true);
  return hits;
}

/** 统计各列表的规则数量（不合并） */
export function countByKind(rules) {
  const out = { domain: 0, full: 0, keyword: 0, regexp: 0 };
  for (const rule of rules) out[rule.kind] = (out[rule.kind] || 0) + 1;
  return out;
}
