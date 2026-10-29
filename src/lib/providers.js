/**
 * SplitDNS - 内置 DoH 上游服务商
 * 全部使用 RFC 8484 的 JSON 形式（Accept: application/dns-json），
 * 避免在扩展内实现 DNS 报文编解码，减少代码量与出错面。
 * url 模板中 {name} / {type} 会被替换。
 */

export const PROVIDERS = [
  {
    id: 'alidns',
    name: '阿里 AliDNS',
    region: 'CN',
    url: 'https://dns.alidns.com/resolve?name={name}&type={type}',
    note: '国内解析，支持 ECS',
  },
  {
    id: 'dnspod',
    name: '腾讯 DNSPod',
    region: 'CN',
    url: 'https://doh.pub/dns-query?name={name}&type={type}',
    note: '国内解析，支持 ECS',
  },
  {
    id: '360',
    name: '360 安全 DNS',
    region: 'CN',
    url: 'https://doh.360.cn/resolve?name={name}&type={type}',
    note: '国内解析',
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare 1.1.1.1',
    region: 'GLOBAL',
    url: 'https://cloudflare-dns.com/dns-query?name={name}&type={type}',
    note: '无日志策略，全球节点',
  },
  {
    id: 'google',
    name: 'Google Public DNS',
    region: 'GLOBAL',
    url: 'https://dns.google/resolve?name={name}&type={type}',
    note: '全球节点',
  },
  {
    id: 'quad9',
    name: 'Quad9',
    region: 'GLOBAL',
    url: 'https://dns.quad9.net:5053/dns-query?name={name}&type={type}',
    note: '内置威胁情报拦截',
  },
];

/** 按 id 取内置上游 */
export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id) || null;
}

/**
 * 解析出可用的上游对象（内置或自定义）
 * @param {string} id
 * @param {Array} customUpstreams 形如 [{id,name,url}]
 */
export function resolveUpstream(id, customUpstreams = []) {
  const builtin = getProvider(id);
  if (builtin) return { ...builtin, custom: false };
  const custom = (customUpstreams || []).find((u) => u.id === id);
  if (custom && custom.url) {
    return {
      id: custom.id,
      name: custom.name || custom.id,
      region: 'CUSTOM',
      url: custom.url,
      note: '自定义上游',
      custom: true,
    };
  }
  return null;
}

/** 全部可选上游（内置 + 自定义） */
export function listUpstreams(customUpstreams = []) {
  return [
    ...PROVIDERS.map((p) => ({ ...p, custom: false })),
    ...(customUpstreams || [])
      .filter((u) => u && u.id && u.url)
      .map((u) => ({
        id: u.id,
        name: u.name || u.id,
        region: 'CUSTOM',
        url: u.url,
        note: '自定义上游',
        custom: true,
      })),
  ];
}
