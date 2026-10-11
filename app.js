const $ = (selector) => document.querySelector(selector);
const sourceLink = $('#sourceLink');
const output = $('#yamlOutput');
const convertBtn = $('#convertBtn');
const copyBtn = $('#copyBtn');
const downloadBtn = $('#downloadBtn');
const protocolChip = $('#detectedProtocol');
const inputHint = $('#inputHint');
const details = $('#details');
const detailGrid = $('#detailGrid');
const copyToast = $('#copyToast');
let latestYaml = '';

const examples = {
  vless: 'vless://47459c58-47d3-43cf-afdb-67bc9d4ee03c@1.2.3.4:3443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=nextcloud.ireina.io&fp=chrome&pbk=Q7UWXwC5y0gH9HGebh2k1fAxlllSTtWNj34oox3AD0g&sid=ecd934&spx=%2Fe8&type=tcp#xx',
  hy2: 'hysteria2://a-strong-password@hysteria.example.com:443,20000-30000/?sni=www.apple.com&insecure=0&alpn=h3&obfs=salamander&obfs-password=obfs-secret#Tokyo%20HY2',
  ss2022: 'ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206QUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0@ss.example.com:8388#Tokyo%20SS2022'
};

function decode(value = '') { try { return decodeURIComponent(value.replace(/\+/g, '%20')); } catch { return value; } }
function decodeUserInfo(value = '') { try { return decodeURIComponent(value); } catch { return value; } }
function truthy(value) { return ['1', 'true', 'yes'].includes(String(value).toLowerCase()); }
function listParam(value) { return value ? value.split(',').map(item => item.trim()).filter(Boolean) : undefined; }
function escapeHtml(str) { return str.replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]); }

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
}

function validatePortSet(value) {
  if (!/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(value)) {
    throw new Error('HY2 端口格式无效，请使用 443、20000-30000 或逗号分隔的组合。');
  }
  for (const part of value.split(',')) {
    const [start, end = start] = part.split('-').map(Number);
    if (start < 1 || end > 65535 || start > end) {
      throw new Error('HY2 端口必须在 1–65535 之间，且范围起点不能大于终点。');
    }
  }
  return value;
}

function parseHy2Url(raw) {
  // WHATWG URL rejects port ranges. Validate and save the original authority,
  // then use URL for the remaining URI components with a single placeholder port.
  const [, authority, suffix] = raw.match(/^hysteria2:\/\/([^/?#]*)(.*)$/i);
  const at = authority.lastIndexOf('@');
  const auth = at < 0 ? '' : authority.slice(0, at);
  const address = authority.slice(at + 1);
  const match = address.match(/^(\[[^\]]+\]|[^:]+)(?::(.+))?$/);
  if (!match) throw new Error('HY2 服务器地址无效，IPv6 地址请使用方括号。');
  const [, host, ports = '443'] = match;
  validatePortSet(ports);
  const url = new URL(`hysteria2://${at < 0 ? '' : auth + '@'}${host}:${Number(ports.split(/[,-]/)[0])}${suffix}`);
  if (!url.hostname) throw new Error('HY2 链接缺少服务器地址。');
  url.hy2PortSet = ports;
  url.hy2Auth = decodeUserInfo(auth);
  return url;
}

function parseUrl(raw) {
  const cleaned = raw.trim().split(/\s+/)[0];
  if (!cleaned) throw new Error('请先粘贴一个分享链接。');
  if (/^hysteria2\+realm(?:\+http)?:\/\//i.test(cleaned)) throw new Error('暂不支持 Hysteria2 Realm 分享链接，请使用普通 HY2 链接。');
  if (!/^(vless|hysteria2|hy2|ss):\/\//i.test(cleaned)) throw new Error('仅支持 vless://、hysteria2://、hy2:// 或 ss:// 链接。');
  const normalized = cleaned.replace(/^hy2:\/\//i, 'hysteria2://');
  if (/^hysteria2:\/\//i.test(normalized)) return parseHy2Url(normalized);
  try { return new URL(normalized); } catch { throw new Error('链接格式无法识别，请检查是否完整。'); }
}

function parseSs2022(url) {
  let method;
  let password;

  if (url.password) {
    method = decodeUserInfo(url.username);
    password = decodeUserInfo(url.password);
  } else {
    try {
      const userInfo = decodeBase64Url(decodeUserInfo(url.username));
      const separator = userInfo.indexOf(':');
      if (separator === -1) throw new Error();
      method = userInfo.slice(0, separator);
      password = userInfo.slice(separator + 1);
    } catch {
      throw new Error('SS 链接的认证信息格式无效。');
    }
  }

  if (method !== '2022-blake3-aes-256-gcm') {
    throw new Error(`暂不支持 SS 的 ${method || '未知'} 加密方式。`);
  }
  if (!password) throw new Error('SS 2022 链接缺少密码。');

  return {
    name: decode(url.hash.slice(1)) || `${url.hostname} · SS 2022`,
    type: 'ss',
    server: url.hostname,
    port: Number(url.port || 8388),
    cipher: method,
    password,
    udp: true
  };
}

function parseVless(url) {
  const p = url.searchParams;
  const security = p.get('security') || 'tls';
  if (security !== 'reality' && security !== 'tls') throw new Error(`暂不支持 VLESS 的 security=${security}。`);

  const proxy = {
    name: decode(url.hash.slice(1)) || `${url.hostname} · VLESS`,
    type: 'vless',
    server: url.hostname,
    port: Number(url.port || 443),
    uuid: decode(url.username),
    network: p.get('type') || 'tcp',
    tls: true,
    udp: true,
    flow: p.get('flow') || undefined,
    'client-fingerprint': p.get('fp') || p.get('fingerprint') || undefined,
    servername: p.get('sni') || p.get('serverName') || undefined,
    alpn: listParam(p.get('alpn'))
  };

  if (truthy(p.get('allowInsecure') || p.get('insecure'))) {
    proxy['skip-cert-verify'] = true;
  }

  if (security === 'reality') {
    const publicKey = p.get('pbk') || p.get('publicKey') || p.get('public-key');
    if (!publicKey) throw new Error('Reality 链接缺少 pbk（公钥）参数。');
    const realityOpts = {
      'public-key': publicKey,
      'support-x25519mlkem768': true
    };
    const sid = p.get('sid') || p.get('shortId') || p.get('short-id') || p.get('short_id');
    if (sid) realityOpts['short-id'] = sid;
    proxy['reality-opts'] = realityOpts;
  }

  if (proxy.network === 'ws') {
    proxy['ws-opts'] = {
      path: p.get('path') || '/',
      ...(p.get('host') ? { headers: { Host: p.get('host') } } : {})
    };
  }

  if (proxy.network === 'grpc') {
    proxy['grpc-opts'] = {
      'grpc-service-name': p.get('serviceName') || p.get('service_name') || ''
    };
  }

  return proxy;
}

function parseHy2(url) {
  const p = url.searchParams;
  const officialPorts = url.hy2PortSet;
  const portOptions = [...p.getAll('mport'), ...p.getAll('ports')];
  if (portOptions.includes('')) throw new Error('HY2 的 ports/mport 参数不能为空。');
  if (/[,-]/.test(officialPorts)) portOptions.unshift(officialPorts);
  if (new Set(portOptions).size > 1) throw new Error('HY2 链接中存在冲突的端口跳跃配置。');
  const ports = portOptions.length ? validatePortSet(portOptions[0]) : undefined;
  const hopOptions = [...p.getAll('hop-interval'), ...p.getAll('hopInterval')];
  if (hopOptions.includes('') || new Set(hopOptions).size > 1) throw new Error('HY2 跳跃间隔不能为空或包含冲突值。');
  const hopInterval = hopOptions[0];
  if (hopInterval) {
    const [min, max = min] = hopInterval.split('-').map(Number);
    if (!/^\d+(?:-\d+)?$/.test(hopInterval) || !Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 5 || max < min) {
      throw new Error('HY2 跳跃间隔应为至少 5 秒的整数，或 15-30 形式的范围。');
    }
    if (!ports) throw new Error('HY2 跳跃间隔需要同时指定多端口或 ports/mport。');
  }
  const fingerprint = p.get('pinSHA256')?.replace(/:/g, '').toLowerCase();
  if (fingerprint !== undefined && !/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error('pinSHA256 必须是 64 位十六进制证书指纹。');
  const obfs = p.get('obfs')?.toLowerCase() || undefined;
  const obfsPassword = p.get('obfs-password') || p.get('obfsPassword') || undefined;
  if (obfs && !['salamander', 'gecko'].includes(obfs)) throw new Error(`暂不支持 HY2 的 ${obfs} 混淆方式。`);
  if (obfs && !obfsPassword) throw new Error('HY2 混淆需要 obfs-password 参数。');
  const packetSizes = {};
  for (const key of ['obfs-min-packet-size', 'obfs-max-packet-size']) {
    if (p.has(key)) {
      const value = Number(p.get(key));
      if (obfs !== 'gecko' || !/^\d+$/.test(p.get(key)) || !Number.isSafeInteger(value) || value < 1 || value > 65535) {
        throw new Error(`${key} 仅适用于 gecko，且必须是有效的正整数包大小。`);
      }
      packetSizes[key] = value;
    }
  }
  if (packetSizes['obfs-min-packet-size'] > packetSizes['obfs-max-packet-size']) throw new Error('gecko 最小包大小不能大于最大包大小。');
  const proxy = {
    name: decode(url.hash.slice(1)) || `${url.hostname} · Hysteria2`,
    type: 'hysteria2',
    server: url.hostname.replace(/^\[|\]$/g, ''),
    port: Number(url.port || 443),
    ports,
    'hop-interval': hopInterval || undefined,
    password: url.hy2Auth,
    sni: p.get('sni') || p.get('peer') || undefined,
    alpn: listParam(p.get('alpn')),
    obfs,
    'obfs-password': obfsPassword,
    ...packetSizes,
    fingerprint,
    'ech-opts': p.get('ech') ? { enable: true, config: p.get('ech') } : undefined,
    up: p.get('upmbps') || p.get('up') || undefined,
    down: p.get('downmbps') || p.get('down') || undefined
  };

  if (truthy(p.get('insecure') || p.get('allowInsecure'))) {
    proxy['skip-cert-verify'] = true;
  }

  return proxy;
}

function flowMap(object) {
  // JSON is valid YAML flow syntax and preserves passwords that resemble numbers,
  // booleans or null, as well as whitespace and escaped control characters.
  return JSON.stringify(object);
}

function makeYaml(items) {
  latestYaml = items.map(item => `- ${flowMap(item)}`).join('\n');
  output.innerHTML = `<code>${escapeHtml(latestYaml)}</code>`;
  return latestYaml;
}

async function copyToClipboard(text, successMessage = '已复制到剪贴板') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement('textarea');
    try {
      area.value = text;
      document.body.append(area);
      area.select();
      if (!document.execCommand('copy')) return false;
    } catch {
      return false;
    } finally {
      area.remove();
    }
  }
  copyToast.textContent = successMessage;
  copyToast.classList.add('show');
  setTimeout(() => copyToast.classList.remove('show'), 1600);
  return true;
}

function showDetails(proxies) {
  const fields = [
    ['节点名称', proxy => proxy.name],
    ['协议', proxy => proxy.type],
    ['服务器', proxy => `${proxy.server.includes(':') ? '[' + proxy.server.replace(/^\[|\]$/g, '') + ']' : proxy.server}:${proxy.ports || proxy.port}`],
    ['端口跳跃', proxy => proxy.ports ? `${proxy['hop-interval'] || 30} 秒` : '未启用'],
    ['传输', proxy => proxy.network || (proxy.type === 'ss' ? 'TCP / UDP' : 'QUIC')],
    ['TLS SNI', proxy => proxy.servername || proxy.sni || '未设置'],
    ['Vision / 混淆', proxy => proxy.flow || proxy.obfs || '默认'],
    ['指纹 / ALPN', proxy => proxy.fingerprint || proxy['client-fingerprint'] || proxy.alpn?.join(', ') || '默认'],
    ['跳过证书', proxy => proxy['skip-cert-verify'] ? '是' : '否']
  ];
  detailGrid.innerHTML = `<div class="detail-row detail-head">${fields.map(([label]) => `<span>${label}</span>`).join('')}</div>${proxies.map(proxy => `<div class="detail-row">${fields.map(([, getValue]) => { const value = String(getValue(proxy)); return `<strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong>`; }).join('')}</div>`).join('')}`;
  $('#detailTitle').textContent = `已识别参数 · ${proxies.length} 个节点`;
  details.hidden = false;
}

function fail(message) {
  output.innerHTML = `<code><span class="yaml-bool"># 转换失败</span>\n\n<span class="yaml-string">${escapeHtml(message)}</span></code>`;
  $('#outputFooter').textContent = '请修正链接后重试。';
  copyBtn.disabled = true;
  downloadBtn.disabled = true;
  details.hidden = true;
}

async function convert() {
  try {
    const links = sourceLink.value.match(/(?:vless|hysteria2(?:\+realm(?:\+http)?)?|hy2|ss):\/\/[^\s]+/gi) || [];
    if (!links.length) throw new Error('请粘贴至少一个 vless://、hysteria2://、hy2:// 或 ss:// 链接。');
    const proxies = links.map(link => {
      const url = parseUrl(link);
      if (url.protocol === 'vless:') return parseVless(url);
      if (url.protocol === 'ss:') return parseSs2022(url);
      return parseHy2(url);
    });
    const yaml = makeYaml(proxies);
    showDetails(proxies);
    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    protocolChip.textContent = `${proxies.length} 个节点`;
    protocolChip.classList.add('active');
    inputHint.textContent = `已成功识别并映射 ${proxies.length} 个节点`;
    const copied = await copyToClipboard(yaml, '转换成功，已复制到剪贴板');
    $('#outputFooter').textContent = copied
      ? `已生成 ${proxies.length} 个单行 JSON 代理项，并自动复制到剪贴板。`
      : `已生成 ${proxies.length} 个单行 JSON 代理项；自动复制失败，请点击“复制”。`;
  } catch (err) {
    fail(err.message);
    protocolChip.textContent = '格式有误';
    protocolChip.classList.remove('active');
    inputHint.textContent = '等待有效的分享链接';
  }
}

convertBtn.addEventListener('click', convert);
sourceLink.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') convert();
});
sourceLink.addEventListener('input', () => {
  const links = sourceLink.value.match(/(?:vless|hysteria2(?:\+realm(?:\+http)?)?|hy2|ss):\/\/[^\s]+/gi) || [];
  protocolChip.textContent = links.length ? `${links.length} 个链接` : '等待输入';
  protocolChip.classList.toggle('active', Boolean(links.length));
});
document.querySelectorAll('[data-example]').forEach(btn =>
  btn.addEventListener('click', () => {
    sourceLink.value = examples[btn.dataset.example];
    convert();
  })
);
copyBtn.addEventListener('click', () => copyToClipboard(latestYaml));
downloadBtn.addEventListener('click', () => {
  const blob = new Blob([latestYaml + '\n'], { type: 'text/yaml;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'clash-meta-proxy.yaml';
  a.click();
  URL.revokeObjectURL(a.href);
});
