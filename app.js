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
  vless: 'vless://2f0581a7-f118-4c22-bc98-45e3cd0f8984@edge.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=ZrYv3J5y6XS6cF__dVqzE4k1Wzi0pL9n0tBOyK_qV9s&sid=6ba85179&type=tcp#HK%20Reality%20Vision',
  hy2: 'hysteria2://a-strong-password@hysteria.example.com:443?sni=www.apple.com&insecure=0&alpn=h3&obfs=salamander&obfs-password=obfs-secret#Tokyo%20HY2'
};

function decode(value = '') { try { return decodeURIComponent(value.replace(/\+/g, '%20')); } catch { return value; } }
function yamlQuote(value) { return JSON.stringify(String(value)); }
function truthy(value) { return ['1', 'true', 'yes'].includes(String(value).toLowerCase()); }
function listParam(value) { return value ? value.split(',').map(item => item.trim()).filter(Boolean) : undefined; }
function escapeHtml(str) { return str.replace(/[&<>]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;' })[c]); }
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
    name: decode(url.hash.slice(1)) || `${url.hostname} · VLESS`, type: 'vless', server: url.hostname,
    port: Number(url.port || 443), uuid: decode(url.username), udp: true, tls: true,
    'skip-cert-verify': truthy(p.get('allowInsecure') || p.get('insecure')),
    servername: p.get('sni') || p.get('serverName'), network: p.get('type') || 'tcp',
    flow: p.get('flow'), 'client-fingerprint': p.get('fp') || p.get('fingerprint'),
    alpn: listParam(p.get('alpn'))
  };
  if (security === 'reality') {
    const publicKey = p.get('pbk') || p.get('publicKey');
    if (!publicKey) throw new Error('Reality 链接缺少 pbk（公钥）参数。');
    proxy['reality-opts'] = { 'public-key': publicKey, ...(p.get('sid') ? { 'short-id': p.get('sid') } : {}) };
  }
  if (proxy.network === 'ws') { proxy['ws-opts'] = { path: p.get('path') || '/', ...(p.get('host') ? { headers: { Host: p.get('host') } } : {}) }; }
  if (proxy.network === 'grpc') { proxy['grpc-opts'] = { 'grpc-service-name': p.get('serviceName') || '' }; }
  return proxy;
}
function parseHy2(url) {
  const p = url.searchParams;
  const proxy = {
    name: decode(url.hash.slice(1)) || `${url.hostname} · Hysteria2`, type: 'hysteria2', server: url.hostname,
    port: Number(url.port || 443), password: decode(url.username),
    sni: p.get('sni') || p.get('peer'), alpn: listParam(p.get('alpn')),
    'skip-cert-verify': truthy(p.get('insecure') || p.get('allowInsecure')),
    obfs: p.get('obfs'), 'obfs-password': p.get('obfs-password') || p.get('obfsPassword'),
    up: p.get('upmbps') || p.get('up'), down: p.get('downmbps') || p.get('down')
  };
  if (!proxy.password) throw new Error('Hysteria2 链接缺少密码。');
  return proxy;
}
function flowValue(value) {
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (Array.isArray(value)) return `[${value.map(flowValue).join(', ')}]`;
  if (value && typeof value === 'object') return flowMap(value);
  return yamlQuote(value);
}
function flowMap(object) { return `{ ${Object.entries(object).filter(([, value]) => value !== undefined && value !== '' && value !== null).map(([key, value]) => `${key}: ${flowValue(value)}`).join(', ')} }`; }
function makeYaml(items) {
  latestYaml = `proxies:\n${items.map(item => `  - ${flowMap(item)}`).join('\n')}`;
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
  $('#outputFooter').textContent = '请修正链接后重试。'; copyBtn.disabled = true; downloadBtn.disabled = true; details.hidden = true;
}
function convert() {
  try {
    const links = sourceLink.value.match(/(?:vless|hysteria2|hy2):\/\/[^\s]+/gi) || [];
    if (!links.length) throw new Error('请粘贴至少一个 vless://、hysteria2:// 或 hy2:// 链接。');
    const proxies = links.map(link => { const url = parseUrl(link); return url.protocol === 'vless:' ? parseVless(url) : parseHy2(url); });
    makeYaml(proxies); showDetails(proxies); copyBtn.disabled = false; downloadBtn.disabled = false;
    protocolChip.textContent = `${proxies.length} 个节点`; protocolChip.classList.add('active');
    inputHint.textContent = `已成功识别并映射 ${proxies.length} 个节点`; $('#outputFooter').innerHTML = `已生成 ${proxies.length} 个单行 JSON 代理项，可直接合并或下载。`;
  } catch (err) { fail(err.message); protocolChip.textContent = '格式有误'; protocolChip.classList.remove('active'); inputHint.textContent = '等待有效的分享链接'; }
}
convertBtn.addEventListener('click', convert);
sourceLink.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') convert(); });
sourceLink.addEventListener('input', () => { const links = sourceLink.value.match(/(?:vless|hysteria2|hy2):\/\/[^\s]+/gi) || []; protocolChip.textContent = links.length ? `${links.length} 个链接` : '等待输入'; protocolChip.classList.toggle('active', Boolean(links.length)); });
document.querySelectorAll('[data-example]').forEach(btn => btn.addEventListener('click', () => { sourceLink.value = examples[btn.dataset.example]; convert(); }));
copyBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(latestYaml); } catch { const area = document.createElement('textarea'); area.value = latestYaml; document.body.append(area); area.select(); document.execCommand('copy'); area.remove(); } copyToast.classList.add('show'); setTimeout(() => copyToast.classList.remove('show'), 1600); });
downloadBtn.addEventListener('click', () => { const blob = new Blob([latestYaml + '\n'], { type:'text/yaml;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'clash-meta-proxy.yaml'; a.click(); URL.revokeObjectURL(a.href); });
