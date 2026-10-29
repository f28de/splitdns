/**
 * SplitDNS - DoH 结果缓存
 *
 * 内存 Map 为主（Service Worker 被回收即失效），同时镜像到 storage.session，
 * 使 Service Worker 重启后仍能命中，行为接近 mosdns 的 cache 插件。
 */

import { clamp } from '../lib/util.js';

const CACHE_KEY = 'splitdns.cache';
const memory = new Map();
/** 载入中的 Promise：并发调用共享同一次载入，避免"标志先置位、快照还没到"的竞态 */
let loadingPromise = null;
let saveTimer = null;

function makeKey(upstreamId, type, name) {
  return `${upstreamId}|${type}|${name}`;
}

async function loadSnapshot() {
  try {
    const raw = await chrome.storage.session.get(CACHE_KEY);
    const snapshot = raw[CACHE_KEY];
    if (snapshot && typeof snapshot === 'object') {
      const now = Date.now();
      for (const [key, entry] of Object.entries(snapshot)) {
        if (entry && entry.expires > now) memory.set(key, entry);
      }
    }
  } catch {
    /* storage.session 不可用时退化为纯内存缓存 */
  }
}

/** 从 storage.session 载入（仅一次，并发安全） */
export async function ensureLoaded() {
  if (!loadingPromise) loadingPromise = loadSnapshot();
  await loadingPromise;
}

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const snapshot = {};
    for (const [key, entry] of memory.entries()) snapshot[key] = entry;
    chrome.storage.session.set({ [CACHE_KEY]: snapshot }).catch(() => {});
  }, 1500);
}

/** 读缓存，命中返回结果对象，未命中返回 null */
export async function cacheGet(upstreamId, type, name) {
  await ensureLoaded();
  const key = makeKey(upstreamId, type, name);
  const entry = memory.get(key);
  if (!entry) return null;
  if (entry.expires <= Date.now()) {
    memory.delete(key);
    scheduleSave();
    return null;
  }
  return { ...entry.result, cached: true, cacheAge: Math.floor((Date.now() - entry.stored) / 1000) };
}

/** 写缓存 */
export async function cachePut(upstreamId, type, name, result, options = {}) {
  await ensureLoaded();
  if (!result?.ok) return;
  const { minTtl = 60, maxTtl = 3600, maxEntries = 1000 } = options;
  const ttl = clamp(result.ttl || 300, Math.max(1, minTtl), Math.max(minTtl, maxTtl));
  const key = makeKey(upstreamId, type, name);
  memory.set(key, {
    stored: Date.now(),
    expires: Date.now() + ttl * 1000,
    ttl,
    result: { ...result, cached: false },
  });
  // 简单淘汰：超限时删掉最早写入的
  if (memory.size > maxEntries) {
    const overflow = memory.size - maxEntries;
    const keys = [...memory.keys()].slice(0, overflow);
    for (const k of keys) memory.delete(k);
  }
  scheduleSave();
}

/** 清空缓存 */
export async function cacheClear() {
  memory.clear();
  try {
    await chrome.storage.session.set({ [CACHE_KEY]: {} });
  } catch {
    /* ignore */
  }
}

/** 缓存统计 */
export async function cacheStats() {
  await ensureLoaded();
  const now = Date.now();
  let alive = 0;
  let expired = 0;
  for (const entry of memory.values()) {
    if (entry.expires > now) alive += 1;
    else expired += 1;
  }
  return { entries: alive, expired };
}
