/**
 * SplitDNS - 工具栏弹窗
 */

const $ = (id) => document.getElementById(id);

const VERDICT_TEXT = {
  block: '已拦截',
  direct: '直连',
  proxy: '分流代理',
  redirect: '重定向',
  none: '默认',
};

let snapshot = null;
let currentHost = '';
let currentTabId = null;

function send(type, payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (res) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) return reject(new Error(lastError.message));
      if (!res) return reject(new Error('后台无响应'));
      if (!res.ok) return reject(new Error(res.error || '未知错误'));
      return resolve(res.data);
    });
  });
}

function escapeHtml(input) {
  return String(input ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function toast(text, isError = false) {
  const el = $('toast');
  el.textContent = text;
  el.classList.remove('hidden');
  el.style.color = isError ? 'var(--red)' : 'var(--green)';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.add('hidden'), 2200);
}

/* --------------------------- 渲染 --------------------------- */

function renderHeader(data) {
  $('version').textContent = `v${data.version}`;
  $('master').checked = Boolean(data.state.enabled);

  const counts = data.counts || {};
  const cache = data.cache?.entries ?? 0;
  $('stats').textContent = `拦截 ${counts.block ?? 0} · 直连 ${counts.direct ?? 0} · 代理 ${counts.proxy ?? 0} · 缓存 ${cache}`;
}

function renderVerdict(result) {
  const badge = $('verdict');
  const action = result?.final?.action || 'none';
  badge.className = `badge ${action === 'none' ? '' : action}`;
  badge.textContent = VERDICT_TEXT[action] || action;

  const hitEl = $('hit');
  if (result?.final?.rule) {
    const rule = result.final.rule;
    const src = rule.source?.startsWith('sub:') ? `订阅 ${rule.source.slice(4)}` : '手动';
    hitEl.textContent = `命中 ${rule.kind}:${rule.value}（${src}）`;
  } else if (result?.hits?.length) {
    hitEl.textContent = `命中 ${result.hits.length} 条规则，最终判定 ${VERDICT_TEXT[action] || action}`;
  } else {
    hitEl.textContent = '未命中任何规则';
  }
}

async function refreshVerdict() {
  if (!currentHost) {
    $('verdict').className = 'badge';
    $('verdict').textContent = '不适用';
    $('hit').textContent = '当前页面不是 http(s) 页面';
    $('quick').classList.add('hidden');
    return;
  }
  $('quick').classList.remove('hidden');

  // 总开关关闭时规则不生效，这里如实显示"已暂停"而不是给出会误导人的判定
  if (snapshot?.state?.enabled === false) {
    $('verdict').className = 'badge warn';
    $('verdict').textContent = '已暂停';
    $('hit').textContent = '总开关已关闭：规则、代理与 DoH 查询均不生效';
    return;
  }

  try {
    const result = await send('rules:test', { host: currentHost });
    renderVerdict(result);
  } catch (err) {
    $('hit').textContent = `判定失败：${err.message}`;
  }
}

function renderAnswers(result) {
  const list = $('qres');
  list.innerHTML = '';
  if (!result) {
    $('qmeta').textContent = '';
    return;
  }
  const meta = [];
  if (result.upstreamName) meta.push(`上游 ${result.upstreamName}`);
  if (typeof result.elapsed === 'number') meta.push(`${result.elapsed}ms`);
  if (result.cached) meta.push(`缓存 ${result.cacheAge || 0}s`);
  if (result.status) meta.push(result.status);
  if (result.matched) meta.push(`分流规则 ${result.matched}`);
  $('qmeta').textContent = meta.join(' · ');

  if (!result.ok && !result.answers?.length) {
    const li = document.createElement('li');
    li.className = 'empty err';
    li.textContent = result.error || '解析失败';
    list.appendChild(li);
    return;
  }
  if (!result.answers?.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = '无记录（NOERROR / 空应答）';
    list.appendChild(li);
    return;
  }
  for (const answer of result.answers) {
    const li = document.createElement('li');
    li.innerHTML = `<span class="t">${escapeHtml(answer.type)}</span>`
      + `<span class="d">${escapeHtml(answer.data)}</span>`
      + `<span class="ttl">${answer.ttl}s</span>`;
    list.appendChild(li);
  }
}

/* --------------------------- 交互 --------------------------- */

async function loadCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab) return;
  currentTabId = tab.id;
  try {
    const url = new URL(tab.url || '');
    if (!/^https?:$/.test(url.protocol)) {
      currentHost = '';
    } else {
      currentHost = url.hostname.toLowerCase();
    }
  } catch {
    currentHost = '';
  }
  $('host').textContent = currentHost || '—';
  if (currentHost) $('qname').value = currentHost;
}

async function addRule(action) {
  if (!currentHost) return;
  const lineMap = {
    block: `||${currentHost}^`,
    direct: `domain:${currentHost}`,
    proxy: `domain:${currentHost}`,
  };
  const labelMap = { block: '拦截', direct: '直连', proxy: '代理' };
  const line = lineMap[action];
  if (!line) return;

  try {
    const result = await send('rules:append', { list: action, line });
    if (!result.added) {
      toast(`已在${labelMap[action]}列表中`);
      return;
    }
    snapshot.counts = result.counts;
    $('stats').textContent = `拦截 ${result.counts.block} · 直连 ${result.counts.direct} · 代理 ${result.counts.proxy} · 缓存 ${snapshot.cache?.entries ?? 0}`;
    toast(`已加入${labelMap[action]}列表`);
    await refreshVerdict();
  } catch (err) {
    toast(`保存失败：${err.message}`, true);
  }
}

function bindEvents() {
  $('master').addEventListener('change', async (event) => {
    const enabled = event.target.checked;
    try {
      const applied = await send('state:patch', { enabled });
      snapshot.state = applied.state;
      snapshot.counts = applied.counts;
      $('stats').textContent = `拦截 ${applied.counts.block} · 直连 ${applied.counts.direct} · 代理 ${applied.counts.proxy}`;
      if (applied.runtime?.dnr?.error) toast(`规则同步异常：${applied.runtime.dnr.error}`, true);
      await refreshVerdict();
    } catch (err) {
      toast(`操作失败：${err.message}`, true);
      event.target.checked = !enabled;
    }
  });

  $('quick').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-act]');
    if (!button) return;
    addRule(button.dataset.act);
  });

  $('qform').addEventListener('submit', async (event) => {
    event.preventDefault();
    const name = $('qname').value.trim();
    if (!name) return;
    const button = $('qbtn');
    button.disabled = true;
    $('qmeta').textContent = '解析中…';
    try {
      const result = await send('dns:resolve', { name, type: $('rtype').value });
      renderAnswers(result);
    } catch (err) {
      renderAnswers({ ok: false, error: err.message });
    } finally {
      button.disabled = false;
    }
  });

  $('open-options').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
    window.close();
  });
}

async function init() {
  bindEvents();
  try {
    // light: popup 只显示计数，不必为了开个弹窗把全部规则文本拉过来
    snapshot = await send('state:get', { light: true });
    renderHeader(snapshot);
  } catch (err) {
    $('stats').textContent = `后台未就绪：${err.message}`;
    return;
  }
  await loadCurrentTab();
  await refreshVerdict();
}

init();
