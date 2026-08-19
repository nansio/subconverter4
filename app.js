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
  hy2: 'hysteria2://a-strong-password@hysteria.example.com:443?sni=www.apple.com&insecure=0&alpn=h3&obfs=salamander&obfs-password=obfs-secret#Tokyo%20HY2'
};

function decode(value = '') { try { return decodeURIComponent(value.replace(/\+/g, '%20')); } catch { return value; } }
function truthy(value) { return ['1', 'true', 'yes'].includes(String(value).toLowerCase()); }
function listParam(value) { return value ? value.split(',').map(item => item.trim()).filter(Boolean) : undefined; }
function escapeHtml(str) { return str.replace(/[&<>]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;' })[c]); }

function shouldQuoteString(key, str) {
  if (key === 'spider-x' || key === 'path' || str.startsWith('/')) {
    return true;
  }
  if (str === '') {
    return true;
  }
  if (/[,{}[\]#"']/.test(str) || /:\s|:$/.test(str)) {
    return true;
  }
  return false;
}

function parseUrl(raw) {
  const cleaned = raw.trim().split(/\s+/)[0];
  if (!cleaned) throw new Error('请先粘贴一个分享链接。');
  if (!/^(vless|hysteria2|hy2):\/\//i.test(cleaned)) throw new Error('仅支持 vless://、hysteria2:// 或 hy2:// 链接。');
  const normalized = cleaned.replace(/^hy2:\/\//i, 'hysteria2://');
  try { return new URL(normalized); } catch { throw new Error('链接格式无法识别，请检查是否完整。'); }
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
    const realityOpts = { 'public-key': publicKey };
    const sid = p.get('sid') || p.get('shortId') || p.get('short-id') || p.get('short_id');
    if (sid) realityOpts['short-id'] = sid;
    const spx = p.get('spx') || p.get('spiderX') || p.get('spider-x') || p.get('spider_x');
    if (spx) realityOpts['spider-x'] = decode(spx);
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
  const proxy = {
    name: decode(url.hash.slice(1)) || `${url.hostname} · Hysteria2`,
    type: 'hysteria2',
    server: url.hostname,
    port: Number(url.port || 443),
    password: decode(url.username),
    sni: p.get('sni') || p.get('peer') || undefined,
    alpn: listParam(p.get('alpn')),
    obfs: p.get('obfs') || undefined,
    'obfs-password': p.get('obfs-password') || p.get('obfsPassword') || undefined,
    up: p.get('upmbps') || p.get('up') || undefined,
    down: p.get('downmbps') || p.get('down') || undefined
  };

  if (truthy(p.get('insecure') || p.get('allowInsecure'))) {
    proxy['skip-cert-verify'] = true;
  }

  if (!proxy.password) throw new Error('Hysteria2 链接缺少密码。');
  return proxy;
}

function flowValue(key, value) {
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (Array.isArray(value)) return `[${value.map(v => flowValue(key, v)).join(', ')}]`;
  if (value && typeof value === 'object') return flowMap(value);
  const str = String(value);
  return shouldQuoteString(key, str) ? JSON.stringify(str) : str;
}

function flowMap(object) {
  const entries = Object.entries(object).filter(
    ([, value]) => value !== undefined && value !== '' && value !== null
  );
  return `{${entries.map(([key, value]) => `${key}: ${flowValue(key, value)}`).join(', ')}}`;
}

function makeYaml(items) {
  latestYaml = items.map(item => `- ${flowMap(item)}`).join('\n');
  output.innerHTML = `<code>${escapeHtml(latestYaml)}</code>`;
}

function showDetails(proxies) {
  const fields = [
    ['节点名称', proxy => proxy.name],
    ['协议', proxy => proxy.type],
    ['服务器', proxy => `${proxy.server}:${proxy.port}`],
    ['传输', proxy => proxy.network || 'QUIC'],
    ['TLS SNI', proxy => proxy.servername || proxy.sni || '未设置'],
    ['Vision / 混淆', proxy => proxy.flow || proxy.obfs || '默认'],
    ['指纹 / ALPN', proxy => proxy['client-fingerprint'] || proxy.alpn?.join(', ') || '默认'],
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

function convert() {
  try {
    const links = sourceLink.value.match(/(?:vless|hysteria2|hy2):\/\/[^\s]+/gi) || [];
    if (!links.length) throw new Error('请粘贴至少一个 vless://、hysteria2:// 或 hy2:// 链接。');
    const proxies = links.map(link => {
      const url = parseUrl(link);
      return url.protocol === 'vless:' ? parseVless(url) : parseHy2(url);
    });
    makeYaml(proxies);
    showDetails(proxies);
    copyBtn.disabled = false;
    downloadBtn.disabled = false;
    protocolChip.textContent = `${proxies.length} 个节点`;
    protocolChip.classList.add('active');
    inputHint.textContent = `已成功识别并映射 ${proxies.length} 个节点`;
    $('#outputFooter').innerHTML = `已生成 ${proxies.length} 个单行 JSON 代理项，可直接合并或下载。`;
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
  const links = sourceLink.value.match(/(?:vless|hysteria2|hy2):\/\/[^\s]+/gi) || [];
  protocolChip.textContent = links.length ? `${links.length} 个链接` : '等待输入';
  protocolChip.classList.toggle('active', Boolean(links.length));
});
document.querySelectorAll('[data-example]').forEach(btn =>
  btn.addEventListener('click', () => {
    sourceLink.value = examples[btn.dataset.example];
    convert();
  })
);
copyBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(latestYaml);
  } catch {
    const area = document.createElement('textarea');
    area.value = latestYaml;
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  copyToast.classList.add('show');
  setTimeout(() => copyToast.classList.remove('show'), 1600);
});
downloadBtn.addEventListener('click', () => {
  const blob = new Blob([latestYaml + '\n'], { type: 'text/yaml;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'clash-meta-proxy.yaml';
  a.click();
  URL.revokeObjectURL(a.href);
});

