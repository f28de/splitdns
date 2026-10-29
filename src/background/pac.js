/**
 * SplitDNS - PAC 脚本生成
 *
 * mosdns 的"按域名分流到不同上游"在浏览器层的等价物是：按域名决定走代理还是直连。
 * chrome.proxy 的 fixed_servers + bypassList 只能表达"排除"，无法表达"仅代理这些域名"，
 * 所以这里生成 PAC 脚本（ES5，PAC 引擎不保证支持 ES6 语法）。
 */

const MAX_ENTRIES = 8000;

/**
 * 从规则组里挑出 PAC 能表达的类型。
 *
 * @param {Array} rules
 * @param {{includeExceptions?: boolean}} options
 *   includeExceptions：白名单（`@@` 例外）本身带 exception 标记，
 *   收集 DIRECT 表时必须放行，否则"白名单优先"在 PAC 侧完全失效。
 */
export function collectPacEntries(rules, { includeExceptions = false } = {}) {
  const out = { suffix: [], full: [], keyword: [], regexpIgnored: 0 };
  for (const rule of rules || []) {
    if (rule.exception && !includeExceptions) continue;
    if (rule.kind === 'full') {
      if (out.full.length < MAX_ENTRIES) out.full.push(rule.value);
    } else if (rule.kind === 'keyword') {
      if (out.keyword.length < MAX_ENTRIES) out.keyword.push(rule.value);
    } else if (rule.kind === 'regexp') {
      out.regexpIgnored += 1;
    } else if (out.suffix.length < MAX_ENTRIES) {
      out.suffix.push(rule.value);
    }
  }
  return out;
}

function jsonArray(list) {
  return `[${list.map((v) => JSON.stringify(String(v))).join(', ')}]`;
}

/**
 * 生成 PAC 文本
 * @param {object} cfg state.proxy
 * @param {object} groups compileState().groups
 * @returns {{pac:string, stats:object}}
 */
export function buildPac(cfg, groups) {
  const mode = ['global', 'list', 'direct'].includes(cfg?.mode) ? cfg.mode : 'list';
  const type = ['PROXY', 'HTTPS', 'SOCKS5', 'SOCKS4', 'QUIC'].includes(cfg?.type) ? cfg.type : 'PROXY';
  const server = String(cfg?.server || '127.0.0.1').trim();
  const port = Number(cfg?.port) || 7890;
  const proxyString = `${type} ${server}:${port}`;

  const proxyEntries = collectPacEntries(groups?.proxy);
  // 直连表 = 直连列表 + 拦截列表里的 @@ 例外，二者都必须进 DIRECT
  const directRules = [...(groups?.direct || []), ...(groups?.block || []).filter((r) => r.exception)];
  const directEntries = collectPacEntries(directRules, { includeExceptions: true });

  const stats = {
    proxySuffix: proxyEntries.suffix.length,
    proxyFull: proxyEntries.full.length,
    proxyKeyword: proxyEntries.keyword.length,
    directSuffix: directEntries.suffix.length,
    directFull: directEntries.full.length,
    directKeyword: directEntries.keyword.length,
    regexpIgnored: proxyEntries.regexpIgnored,
    proxyString,
    mode,
  };

  const pac = `/* SplitDNS PAC — generated ${new Date().toISOString()} */
var PROXY = ${JSON.stringify(proxyString)};
var MODE = ${JSON.stringify(mode)};
var PROXY_SUFFIX = ${jsonArray(proxyEntries.suffix)};
var PROXY_FULL = ${jsonArray(proxyEntries.full)};
var PROXY_KEYWORD = ${jsonArray(proxyEntries.keyword)};
var DIRECT_SUFFIX = ${jsonArray(directEntries.suffix)};
var DIRECT_FULL = ${jsonArray(directEntries.full)};
var DIRECT_KEYWORD = ${jsonArray(directEntries.keyword)};

function hitSuffix(host, list) {
  for (var i = 0; i < list.length; i++) {
    var d = list[i];
    if (host === d) return true;
    if (host.length > d.length + 1 && host.slice(-(d.length + 1)) === '.' + d) return true;
  }
  return false;
}

function hitKeyword(host, list) {
  for (var i = 0; i < list.length; i++) {
    if (host.indexOf(list[i]) >= 0) return true;
  }
  return false;
}

function isLocalHost(host) {
  if (host === 'localhost' || host === 'localhost.localdomain') return true;
  if (host.indexOf('.') < 0) return true;
  if (host.slice(-6) === '.local' || host.slice(-4) === '.lan') return true;
  if (/^127\\./.test(host) || /^10\\./.test(host) || /^169\\.254\\./.test(host)) return true;
  if (/^192\\.168\\./.test(host)) return true;
  if (/^172\\.(1[6-9]|2[0-9]|3[01])\\./.test(host)) return true;
  return false;
}

function FindProxyForURL(url, host) {
  host = String(host || '').toLowerCase();
  if (isLocalHost(host)) return 'DIRECT';
  if (hitSuffix(host, DIRECT_SUFFIX) || DIRECT_FULL.indexOf(host) >= 0 || hitKeyword(host, DIRECT_KEYWORD)) return 'DIRECT';
  if (MODE === 'direct') return 'DIRECT';
  if (MODE === 'global') return PROXY;
  if (hitSuffix(host, PROXY_SUFFIX) || PROXY_FULL.indexOf(host) >= 0 || hitKeyword(host, PROXY_KEYWORD)) return PROXY;
  return 'DIRECT';
}
`;

  return { pac, stats };
}
