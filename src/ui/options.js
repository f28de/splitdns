/**
 * SplitDNS - 设置页
 *
 * 设计原则：所有改动都立刻落库并立即生效，没有"未保存"状态；
 * 只有规则文本使用草稿 + 显式保存，避免每敲一个字就重建全部 DNR 规则。
 */

import { compileText, parseRuleLine, KIND_LABEL } from '../lib/matcher.js';
import { escapeHtml, formatAgo, formatDateTime, uid, checkEndpoint } from '../lib/util.js';

const $ = (id) => document.getElementById(id);

const LIST_LABEL = { block: '拦截', direct: '直连', proxy: '代理', redirect: '重定向' };
const ACTION_LABEL = { block: '拦截', direct: '直连', proxy: '代理', redirect: '重定向' };
const MAX_IMPORT_BYTES = 4 * 1024 * 1024;

/** 只在自身属性里取值，避免 target='constructor' 之类取到原型上的东西 */
function ownLabel(map, key) {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : '未知';
}

let payload = null;   // state:get 的完整返回
let state = null;     // payload.state
let currentList = 'block';
const draft = { block: '', direct: '', proxy: '', redirect: '' };

/* ------------------------------ 基础 ------------------------------ */

function send(type, payloadData) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload: payloadData }, (res) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) return reject(new Error(lastError.message));
      if (!res) return reject(new Error('后台无响应'));
      if (!res.ok) return reject(new Error(res.error || '未知错误'));
      return resolve(res.data);
    });
  });
}

function toast(text, isError = false) {
  const el = $('toast');
  el.textContent = text;
  el.classList.remove('hidden');
  el.classList.toggle('error', isError);
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.add('hidden'), 2600);
}

/** 应用一次状态更新，并同步内存中的 payload */
function absorb(applied) {
  if (applied.state) {
    state = applied.state;
    payload.state = applied.state;
  }
  if (applied.runtime) payload.runtime = applied.runtime;
  if (applied.counts) payload.counts = applied.counts;
  if (applied.invalid) payload.invalid = applied.invalid;
  if (applied.skipped) payload.skipped = applied.skipped;
  if (applied.storage) payload.storage = applied.storage;
}

async function patch(patchData, message) {
  try {
    const applied = await send('state:patch', { patch: patchData });
    absorb(applied);
    if (applied.runtime?.dnr?.error) {
      toast(`规则同步异常：${applied.runtime.dnr.error}`, true);
    } else if (message) {
      toast(message);
    }
    return applied;
  } catch (err) {
    toast(`保存失败：${err.message}`, true);
    throw err;
  }
}

/* ------------------------------ 导航 ------------------------------ */

function switchTab(tab) {
  document.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });
  document.querySelectorAll('.panel').forEach((el) => {
    el.classList.toggle('hidden', el.dataset.panel !== tab);
  });
  if (state && state.ui?.lastTab !== tab) {
    state.ui = { ...(state.ui || {}), lastTab: tab };
    // 只记忆面板位置，不触发规则重建
    chrome.runtime.sendMessage({ type: 'ui:remember', payload: { tab } });
  }
}

/* ------------------------------ 常规 ------------------------------ */

function renderGeneral() {
  $('enabled').checked = Boolean(state.enabled);
  // 勾选状态表示"用户期望配置"；暂停期间实际生效状态由运行状态面板展示
  $('builtin').checked = Boolean(state.builtinRuleset);
  $('log-enabled').checked = state.log?.enabled !== false;
  $('allow-sub-regex').checked = state.security?.allowSubRegex === true;
  $('allow-sub-trust').checked = state.security?.allowSubTrust === true;

  const cache = state.dns?.cache || {};
  $('cache-enabled').checked = cache.enabled !== false;
  $('cache-min').value = cache.minTtl ?? 60;
  $('cache-max').value = cache.maxTtl ?? 3600;
  $('cache-entries').value = cache.maxEntries ?? 1000;
  $('cache-info').textContent = `当前缓存 ${payload.cache?.entries ?? 0} 条`;
}

function renderRuntime() {
  const rt = payload.runtime || {};
  const dnr = rt.dnr || {};
  const rows = [
    ['规则状态', dnr.error ? `<span class="err">同步失败：${escapeHtml(dnr.error)}</span>`
      : (dnr.enabled === false ? '已暂停' : '已生效')],
    ['DNR 规则数', `${dnr.added ?? 0}${dnr.skipped ? `（${dnr.skipped} 条因配额被跳过）` : ''}`],
    ['正则规则', `${dnr.regexUsed ?? 0} 条`],
    ['编译规则数', `拦截 ${payload.counts?.block ?? 0} · 直连 ${payload.counts?.direct ?? 0} · 代理 ${payload.counts?.proxy ?? 0} · 重定向 ${payload.counts?.redirect ?? 0}`],
    ['代理', rt.proxy?.active ? '已启用' : (rt.proxy?.error ? `<span class="err">${escapeHtml(rt.proxy.error)}</span>` : '未启用')],
    ['上次编译', dnr.at ? formatDateTime(dnr.at) : '—'],
  ];
  const storage = payload.storage;
  if (storage?.usedBytes) {
    const used = (storage.usedBytes / 1024 / 1024).toFixed(2);
    const budget = Math.round(storage.budgetBytes / 1024 / 1024);
    rows.push(['存储占用', `${used} MB / ${budget} MB`]);
  }
  if (dnr.warning) rows.push(['提示', `<span class="muted">${escapeHtml(dnr.warning)}</span>`]);
  if (dnr.keptPrevious) {
    rows.push(['失败处理', '<span class="warn">本次同步失败，已保留上一份可用规则（未清空）</span>']);
  }
  if (payload.invalid?.length) {
    const sample = payload.invalid.slice(0, 3).map((i) => escapeHtml(i.line)).join('、');
    rows.push(['无效行', `<span class="muted">${payload.invalid.length} 条已忽略：${sample}…</span>`]);
  }
  if (payload.skipped?.length) {
    const sample = payload.skipped.slice(0, 2).map((i) => `${escapeHtml(i.line)}（${escapeHtml(i.reason)}）`).join('、');
    rows.push(['安全跳过', `<span class="muted">${payload.skipped.length} 条：${sample}…</span>`]);
  }
  $('runtime-kv').innerHTML = rows
    .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`)
    .join('');
}

/* ------------------------------ 规则 ------------------------------ */

function listStats(text) {
  const { rules, invalid } = compileText(text);
  const byKind = { domain: 0, full: 0, keyword: 0, regexp: 0 };
  for (const rule of rules) byKind[rule.kind] += 1;
  const parts = Object.entries(byKind)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${KIND_LABEL[k]} ${n}`);
  const base = `${rules.length} 条规则${parts.length ? `（${parts.join(' / ')}）` : ''}`;
  return invalid.length ? `${base} · ${invalid.length} 行无法识别` : base;
}

function renderRules() {
  for (const key of Object.keys(LIST_LABEL)) {
    draft[key] = state.lists?.[key]?.text ?? '';
  }
  document.querySelectorAll('#list-tabs .chip').forEach((chip) => {
    chip.classList.toggle('active', chip.dataset.list === currentList);
  });
  $('list-text').value = draft[currentList];
  $('list-stat').textContent = listStats(draft[currentList]);
}

function bindRules() {
  $('list-tabs').addEventListener('click', (event) => {
    const chip = event.target.closest('.chip');
    if (!chip) return;
    draft[currentList] = $('list-text').value;
    currentList = chip.dataset.list;
    renderRules();
  });

  $('list-text').addEventListener('input', () => {
    draft[currentList] = $('list-text').value;
    $('list-stat').textContent = listStats(draft[currentList]);
  });

  $('list-reload').addEventListener('click', () => {
    renderRules();
    toast('已还原为已保存的规则');
  });

  $('list-save').addEventListener('click', async () => {
    draft[currentList] = $('list-text').value;
    const lists = {};
    for (const key of Object.keys(LIST_LABEL)) lists[key] = { text: draft[key] };
    const button = $('list-save');
    button.disabled = true;
    try {
      const applied = await patch({ lists }, '规则已保存并生效');
      if (applied) {
        renderRuntime();
        $('list-stat').textContent = listStats(draft[currentList]);
      }
    } finally {
      button.disabled = false;
    }
  });

  $('test-run').addEventListener('click', runTest);
  $('test-host').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') runTest();
  });
}

async function runTest() {
  const host = $('test-host').value.trim();
  if (!host) return;
  const box = $('test-result');
  box.innerHTML = '<div class="muted">测试中…</div>';
  try {
    const result = await send('rules:test', { host });
    if (!result.hits.length) {
      box.innerHTML = `<div class="muted">${escapeHtml(result.host)} 未命中任何规则，将按浏览器默认方式处理。</div>`;
      return;
    }
    const lines = result.hits.map((hit, index) => {
      const action = ACTION_LABEL[hit.action] || hit.action;
      const src = hit.rule.source?.startsWith('sub:') ? `订阅 ${hit.rule.source.slice(4)}` : '手动';
      return `<div class="hit-line">
        <span class="badge ${hit.action}">${escapeHtml(action)}</span>
        <span class="mono">${escapeHtml(hit.rule.raw || hit.rule.value)}</span>
        <span class="tiny muted">${escapeHtml(src)}${index === 0 ? ' · 最终生效' : ''}</span>
      </div>`;
    });
    box.innerHTML = lines.join('');
  } catch (err) {
    box.innerHTML = `<div class="err">${escapeHtml(err.message)}</div>`;
  }
}

/* ------------------------------ 上游 ------------------------------ */

function upstreamOptions(selected) {
  return (payload.upstreams || [])
    .map((u) => `<option value="${escapeHtml(u.id)}"${u.id === selected ? ' selected' : ''}>${escapeHtml(u.name)}${u.custom ? '（自定义）' : ''}</option>`)
    .join('');
}

function renderUpstream() {
  const dns = state.dns || {};
  $('default-upstream').innerHTML = upstreamOptions(dns.defaultUpstream);
  $('timeout').value = dns.timeoutMs ?? 5000;

  const splitBox = $('split-list');
  const split = dns.split || [];
  splitBox.innerHTML = split.length ? split.map((entry, index) => `
    <div class="item" data-split-index="${index}">
      <span class="grow">
        <span class="mono name">${escapeHtml(entry.pattern)}</span>
        <span class="sub">→ ${escapeHtml(upstreamName(entry.upstream))}</span>
      </span>
      <button data-split-remove="${index}">删除</button>
    </div>`).join('') : '<div class="empty-tip">暂无分流规则，所有域名使用默认上游</div>';

  $('split-upstream').innerHTML = upstreamOptions(dns.defaultUpstream);

  const customBox = $('custom-list');
  const custom = dns.customUpstreams || [];
  customBox.innerHTML = custom.length ? custom.map((up, index) => `
    <div class="item">
      <span class="grow">
        <span class="name">${escapeHtml(up.name || up.id)}</span>
        <span class="sub mono">${escapeHtml(up.url)}</span>
      </span>
      <button data-custom-remove="${index}">删除</button>
    </div>`).join('') : '<div class="empty-tip">暂无自定义上游</div>';

  $('probe-upstream').innerHTML = upstreamOptions(dns.defaultUpstream);
}

function upstreamName(id) {
  const found = (payload.upstreams || []).find((u) => u.id === id);
  return found ? found.name : (id || '—');
}

function bindUpstream() {
  $('default-upstream').addEventListener('change', (event) => {
    patch({ dns: { defaultUpstream: event.target.value } }, '默认上游已更新');
  });

  $('timeout').addEventListener('change', (event) => {
    const value = Math.max(1000, Math.min(30000, Number(event.target.value) || 5000));
    event.target.value = value;
    patch({ dns: { timeoutMs: value } });
  });

  $('split-add').addEventListener('click', async () => {
    const pattern = $('split-pattern').value.trim();
    const upstream = $('split-upstream').value;
    if (!pattern) return toast('请填写匹配规则', true);
    if (!parseRuleLine(pattern)) return toast('规则格式无法识别', true);
    const split = [...(state.dns.split || []), { pattern, upstream }];
    await patch({ dns: { split } }, '分流规则已添加');
    $('split-pattern').value = '';
    renderUpstream();
  });

  $('split-list').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-split-remove]');
    if (!button) return;
    const index = Number(button.dataset.splitRemove);
    const split = (state.dns.split || []).filter((_, i) => i !== index);
    await patch({ dns: { split } }, '已删除');
    renderUpstream();
  });

  $('custom-add').addEventListener('click', async () => {
    const name = $('custom-name').value.trim();
    const url = $('custom-url').value.trim();
    const endpoint = checkEndpoint(url);
    if (!endpoint.ok) return toast(endpoint.reason, true);
    if (endpoint.insecure && !confirm('该地址使用明文 http，查询内容可被中间人看到。确定继续？')) return;
    const origin = safeOrigin(url);
    if (!origin) return toast('上游地址格式不正确，请填写完整链接', true);
    const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
    if (!granted) return toast('未获得该地址的访问权限，无法使用', true);
    const customUpstreams = [...(state.dns.customUpstreams || []), { id: uid('u_'), name: name || '自定义', url }];
    await patch({ dns: { customUpstreams } }, '自定义上游已添加');
    $('custom-name').value = '';
    $('custom-url').value = '';
    await refresh();
  });

  $('custom-list').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-custom-remove]');
    if (!button) return;
    const index = Number(button.dataset.customRemove);
    const removed = (state.dns.customUpstreams || [])[index];
    const customUpstreams = (state.dns.customUpstreams || []).filter((_, i) => i !== index);
    await patch({ dns: { customUpstreams } }, '已删除');
    if (removed) {
      const origin = safeOrigin(removed.url);
      if (origin) chrome.permissions.remove({ origins: [origin] }).catch(() => {});
    }
    await refresh();
  });

  $('probe-run').addEventListener('click', async () => {
    const name = $('probe-name').value.trim();
    if (!name) return;
    const box = $('probe-result');
    box.innerHTML = '<div class="muted">查询中…</div>';
    try {
      const result = await send('dns:test', { name, upstreamId: $('probe-upstream').value });
      if (!result.ok) {
        box.innerHTML = `<div class="err">${escapeHtml(result.error || '解析失败')}${result.elapsed ? `（${result.elapsed}ms）` : ''}</div>`;
        return;
      }
      const lines = result.answers.map((a) => `<div class="hit-line">
        <span class="badge">${escapeHtml(a.type)}</span>
        <span class="mono">${escapeHtml(a.data)}</span>
        <span class="tiny muted">TTL ${a.ttl}s</span>
      </div>`).join('');
      box.innerHTML = `<div class="tiny muted">${escapeHtml(result.upstreamName || '')} · ${result.elapsed}ms · ${escapeHtml(result.status || 'NOERROR')}</div>${lines || '<div class="muted">无记录</div>'}`;
    } catch (err) {
      box.innerHTML = `<div class="err">${escapeHtml(err.message)}</div>`;
    }
  });
}

/**
 * 生成用于 chrome.permissions.request 的匹配模式。
 *
 * 匹配模式语法是 `<scheme>://<host><path>`，**不支持端口**：
 * 用 parsed.host 会拼出 `https://dns.test:5053/*`，Chrome 直接判为非法，
 * 于是所有带端口的 DoH 端点（如 Quad9 的 :5053）都无法添加。
 * hostname 对 IPv6 会返回带方括号的形式（`[::1]`），正好符合匹配模式要求。
 */
function safeOrigin(url) {
  try {
    const parsed = new URL(url);
    if (!parsed.hostname) return null;
    if (!['https:', 'http:'].includes(parsed.protocol)) return null;
    return `${parsed.protocol}//${parsed.hostname}/*`;
  } catch {
    return null;
  }
}

/* ------------------------------ 代理 ------------------------------ */

function renderProxy() {
  const cfg = state.proxy || {};
  $('proxy-enabled').checked = Boolean(cfg.enabled);
  $('proxy-mode').value = cfg.mode || 'list';
  $('proxy-type').value = cfg.type || 'PROXY';
  $('proxy-server').value = cfg.server || '127.0.0.1';
  $('proxy-port').value = cfg.port || 7890;

  const rt = payload.runtime?.proxy;
  const parts = [];
  parts.push(payload.proxyPermission ? '权限：已授予' : '权限：未授予');
  if (payload.proxySetting) parts.push(`当前代理模式：${payload.proxySetting.mode}`);
  if (rt?.active) parts.push(`PAC 已生效（${rt.pacBytes || 0} 字节）`);
  if (rt?.error) parts.push(`错误：${rt.error}`);
  $('proxy-status').innerHTML = `<div class="tiny ${rt?.error ? 'err' : 'muted'}">${escapeHtml(parts.join(' · '))}</div>`;
}

function bindProxy() {
  $('proxy-enabled').addEventListener('change', async (event) => {
    const enabled = event.target.checked;
    if (enabled) {
      // 必须在用户手势中同步发起权限申请
      const granted = await chrome.permissions.request({ permissions: ['proxy'] }).catch(() => false);
      if (!granted) {
        event.target.checked = false;
        toast('未授予代理权限，无法启用分流代理', true);
        return;
      }
    }
    await patch({ proxy: { enabled } }, enabled ? '分流代理已启用' : '分流代理已关闭');
    renderProxy();
  });

  $('proxy-save').addEventListener('click', async () => {
    const server = $('proxy-server').value.trim() || '127.0.0.1';
    // 含引号 / 空格 / 分号会生成非法的 PROXY 串，PAC 静默失败后会回退直连
    if (!/^[a-z0-9._-]+$/i.test(server) && !/^\[[0-9a-f:.]+\]$/i.test(server)) {
      return toast('服务器地址只能是主机名、IPv4 或 [IPv6]', true);
    }
    const cfg = {
      mode: $('proxy-mode').value,
      type: $('proxy-type').value,
      server,
      port: Math.max(1, Math.min(65535, Number($('proxy-port').value) || 7890)),
    };
    await patch({ proxy: cfg }, state?.enabled === false ? '已保存；暂停期间不生效' : '代理配置已应用');
    renderProxy();
  });

  $('proxy-off').addEventListener('click', async () => {
    try {
      await send('proxy:clear');
      await refresh();
      toast('已撤销代理设置');
    } catch (err) {
      toast(`撤销失败：${err.message}`, true);
    }
  });
}

/* ------------------------------ 订阅 ------------------------------ */

function renderSubs() {
  const box = $('sub-list');
  const subs = state.subscriptions || [];
  box.innerHTML = subs.length ? subs.map((sub, index) => {
    const insecure = !/^https:\/\//i.test(sub.url);
    return `
    <div class="item">
      <span class="grow">
        <span class="name">${escapeHtml(sub.name || '未命名')} <span class="badge">${escapeHtml(ownLabel(LIST_LABEL, sub.target))}</span>${insecure ? ' <span class="badge warn">非 https</span>' : ''}</span>
        <span class="sub mono">${escapeHtml(sub.url)}</span>
        <span class="sub">${sub.text ? `${countLines(sub.text)} 行规则` : '尚未拉取'} · 更新于 ${escapeHtml(formatAgo(sub.lastUpdate))}</span>
      </span>
      <label class="switch"><input type="checkbox" data-sub-toggle="${index}"${sub.enabled !== false ? ' checked' : ''}><span></span></label>
      <button data-sub-update="${index}">更新</button>
      <button data-sub-remove="${index}">删除</button>
    </div>`;
  }).join('') : '<div class="empty-tip">暂无订阅</div>';
}

function countLines(text) {
  return String(text || '').split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith('#')).length;
}

function bindSubs() {
  $('sub-add').addEventListener('click', async () => {
    const name = $('sub-name').value.trim();
    const url = $('sub-url').value.trim();
    const target = $('sub-target').value;
    if (!/^https:\/\//i.test(url)) return toast('订阅地址需为 https 链接', true);
    // 先确认能解析出主机名：`https://` 这种只有协议串也能过上面的正则
    const origin = safeOrigin(url);
    if (!origin) return toast('订阅地址格式不正确，请填写完整的 https 链接', true);

    // 同步发起权限申请，保证仍处于用户手势中
    const granted = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
    if (!granted) return toast('未获得该地址的访问权限', true);

    const sub = { id: uid('s_'), name: name || new URL(url).hostname, url, target, enabled: true, text: '', lastUpdate: 0 };
    toast('正在拉取规则…');
    try {
      const result = await send('sub:fetch', { url });
      sub.text = result.text;
      sub.lastUpdate = Date.now();
      const subscriptions = [...(state.subscriptions || []), sub];
      await patch({ subscriptions }, `已添加订阅，共 ${result.rules} 条规则`);
      $('sub-name').value = '';
      $('sub-url').value = '';
      renderSubs();
    } catch (err) {
      toast(`拉取失败：${err.message}`, true);
    }
  });

  $('sub-list').addEventListener('click', async (event) => {
    const updateBtn = event.target.closest('[data-sub-update]');
    if (updateBtn) {
      const index = Number(updateBtn.dataset.subUpdate);
      const sub = state.subscriptions[index];
      if (!sub) return;
      updateBtn.disabled = true;
      updateBtn.textContent = '拉取中';
      try {
        const result = await send('sub:fetch', { url: sub.url });
        const subscriptions = state.subscriptions.map((item, i) => (i === index
          ? { ...item, text: result.text, lastUpdate: Date.now() }
          : item));
        await patch({ subscriptions }, `已更新，共 ${result.rules} 条规则`);
        renderSubs();
      } catch (err) {
        toast(`拉取失败：${err.message}`, true);
        updateBtn.disabled = false;
        updateBtn.textContent = '更新';
      }
      return;
    }

    const removeBtn = event.target.closest('[data-sub-remove]');
    if (removeBtn) {
      const index = Number(removeBtn.dataset.subRemove);
      const subscriptions = state.subscriptions.filter((_, i) => i !== index);
      await patch({ subscriptions }, '订阅已删除');
      renderSubs();
    }
  });

  $('sub-list').addEventListener('change', async (event) => {
    const toggle = event.target.closest('[data-sub-toggle]');
    if (!toggle) return;
    const index = Number(toggle.dataset.subToggle);
    const subscriptions = state.subscriptions.map((item, i) => (i === index
      ? { ...item, enabled: toggle.checked }
      : item));
    await patch({ subscriptions }, toggle.checked ? '订阅已启用' : '订阅已停用');
  });
}

/* ------------------------------ 数据 ------------------------------ */

function bindData() {
  $('export-btn').addEventListener('click', async () => {
    try {
      const result = await send('export');
      const blob = new Blob([result.json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `splitdns-config-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      $('data-info').textContent = `已导出 ${(result.json.length / 1024).toFixed(1)} KB`;
    } catch (err) {
      toast(`导出失败：${err.message}`, true);
    }
  });

  $('import-btn').addEventListener('click', () => $('import-file').click());

  $('import-file').addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      toast(`配置文件过大（上限 ${Math.round(MAX_IMPORT_BYTES / 1024)} KB）`, true);
      event.target.value = '';
      return;
    }
    try {
      const text = await file.text();
      await send('import', { json: text });
      toast('配置已导入');
      await refresh();
    } catch (err) {
      toast(`导入失败：${err.message}`, true);
    } finally {
      event.target.value = '';
    }
  });

  $('reset-btn').addEventListener('click', async () => {
    if (!confirm('将清除全部规则与设置并恢复默认，确定继续？')) return;
    try {
      await send('state:reset');
      toast('已恢复默认设置');
      await refresh();
    } catch (err) {
      toast(`重置失败：${err.message}`, true);
    }
  });
}

/* ------------------------------ 加载 ------------------------------ */

function renderAll() {
  $('side-version').textContent = `v${payload.version}`;
  $('about-version').textContent = `v${payload.version}`;
  renderGeneral();
  renderRuntime();
  renderRules();
  renderUpstream();
  renderProxy();
  renderSubs();
}

async function refresh() {
  payload = await send('state:get');
  state = payload.state;
  renderAll();
}

function bindGeneral() {
  $('enabled').addEventListener('change', async (event) => {
    await patch({ enabled: event.target.checked }, event.target.checked ? '已启用' : '已暂停');
    renderRuntime();
  });

  $('builtin').addEventListener('change', async (event) => {
    try {
      const result = await send('ruleset:set', { enabled: event.target.checked });
      state = result.state;
      payload.state = result.state;
      payload.builtinRuleset = result.builtinRuleset;
      renderGeneral();
      renderRuntime();
      if (result.paused) {
        toast('已保存设置；当前处于暂停状态，规则集不会生效', true);
      } else {
        toast(event.target.checked ? '内置规则集已启用' : '内置规则集已关闭');
      }
    } catch (err) {
      toast(`切换失败：${err.message}`, true);
      event.target.checked = !event.target.checked;
    }
  });

  $('log-enabled').addEventListener('change', (event) => {
    patch({ log: { enabled: event.target.checked } }, '已保存');
  });

  $('allow-sub-regex').addEventListener('change', async (event) => {
    const enabled = event.target.checked;
    if (enabled && !confirm('订阅内容不可信，其中的正则规则存在拖慢浏览器的风险。确定允许？')) {
      event.target.checked = false;
      return;
    }
    await patch({ security: { allowSubRegex: enabled } }, enabled ? '已允许订阅正则' : '已禁用订阅正则');
    renderRuntime();
  });

  $('allow-sub-trust').addEventListener('change', async (event) => {
    const enabled = event.target.checked;
    if (enabled && !confirm('允许订阅写入直连/重定向列表后，订阅可解除你的拦截或改写你访问的域名。确定允许？')) {
      event.target.checked = false;
      return;
    }
    await patch({ security: { allowSubTrust: enabled } }, enabled ? '已允许订阅写入直连/重定向' : '已禁止订阅写入直连/重定向');
    renderRuntime();
  });

  const cacheInputs = ['cache-min', 'cache-max', 'cache-entries'];
  for (const id of cacheInputs) {
    $(id).addEventListener('change', async () => {
      await patch({
        dns: {
          cache: {
            minTtl: Math.max(1, Number($('cache-min').value) || 60),
            maxTtl: Math.max(1, Number($('cache-max').value) || 3600),
            maxEntries: Math.max(10, Number($('cache-entries').value) || 1000),
          },
        },
      }, '缓存设置已保存');
    });
  }

  $('cache-enabled').addEventListener('change', (event) => {
    patch({ dns: { cache: { enabled: event.target.checked } } }, '已保存');
  });

  $('cache-clear').addEventListener('click', async () => {
    try {
      const result = await send('cache:clear');
      payload.cache = result.cache;
      $('cache-info').textContent = '当前缓存 0 条';
      toast('缓存已清空');
    } catch (err) {
      toast(`清空失败：${err.message}`, true);
    }
  });

  $('resync').addEventListener('click', async () => {
    const button = $('resync');
    button.disabled = true;
    try {
      const applied = await send('rules:sync');
      absorb({ runtime: applied.runtime, counts: applied.counts, invalid: applied.invalid });
      renderRuntime();
      toast('规则已重新编译');
    } catch (err) {
      toast(`编译失败：${err.message}`, true);
    } finally {
      button.disabled = false;
    }
  });
}

async function init() {
  $('nav').addEventListener('click', (event) => {
    const item = event.target.closest('.nav-item');
    if (item) switchTab(item.dataset.tab);
  });

  bindGeneral();
  bindRules();
  bindUpstream();
  bindProxy();
  bindSubs();
  bindData();

  try {
    await refresh();
    switchTab(state.ui?.lastTab && document.querySelector(`[data-panel="${state.ui.lastTab}"]`)
      ? state.ui.lastTab
      : 'general');
  } catch (err) {
    toast(`加载失败：${err.message}`, true);
  }
}

init();
