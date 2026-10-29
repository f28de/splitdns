/**
 * SplitDNS - 分流代理应用层
 *
 * proxy 权限放在 optional_permissions 中，只有用户主动开启"分流代理"时才申请，
 * 避免未使用该功能的用户被要求授予高敏感权限（商店审核也更友好）。
 */

import { buildPac } from './pac.js';

const SCOPE = 'regular';

/** 是否已获得 proxy 权限 */
export async function hasProxyPermission() {
  try {
    return await chrome.permissions.contains({ permissions: ['proxy'] });
  } catch {
    return false;
  }
}

/**
 * 申请 proxy 权限（必须在用户手势中调用，例如按钮 click 回调）
 */
export async function requestProxyPermission() {
  try {
    return await chrome.permissions.request({ permissions: ['proxy'] });
  } catch (err) {
    return { error: err?.message || String(err) };
  }
}

/**
 * 应用或撤销代理设置
 * @param {object} state
 * @param {object} groups compileState().groups
 */
export async function applyProxy(state, groups) {
  const cfg = state?.proxy || {};
  const permitted = await hasProxyPermission();

  if (!cfg.enabled) {
    if (permitted) {
      try {
        await chrome.proxy.settings.clear({ scope: SCOPE });
      } catch {
        /* 忽略：可能本来就没有设置 */
      }
    }
    return { active: false, error: null };
  }

  if (!permitted) {
    return { active: false, error: '缺少 proxy 权限，请在设置页重新开启分流代理并授权' };
  }

  const { pac, stats } = buildPac(cfg, groups);
  try {
    await chrome.proxy.settings.set({
      value: { mode: 'pac_script', pacScript: { data: pac, mandatory: false } },
      scope: SCOPE,
    });
    return { active: true, error: null, stats, pacBytes: pac.length, at: Date.now() };
  } catch (err) {
    return { active: false, error: err?.message || String(err) };
  }
}

/** 读取当前生效的代理配置（用于状态展示） */
export async function readProxySetting() {
  try {
    const detail = await chrome.proxy.settings.get({ incognito: false });
    return { mode: detail?.value?.mode || 'system', levelOfControl: detail?.levelOfControl || 'unknown' };
  } catch {
    return { mode: 'unknown', levelOfControl: 'unknown' };
  }
}
