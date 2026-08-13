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
function yamlValue(value) {
  if (typeof value === 'boolean') return `<span class="yaml-bool">${value}</span>`;
  if (typeof value === 'number') return `<span class="yaml-number">${value}</span>`;
  return `<span class="yaml-string">${escapeHtml(yamlQuote(value))}</span>`;
}
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
    flow: p.get('flow'), 'client-fingerprint': p.get('fp') || p.get('fingerprint')
  };
  if (security === 'reality') {
    const publicKey = p.get('pbk') || p.get('publicKey');
    if (!publicKey) throw new Error('Reality 链接缺少 pbk（公钥）参数。');
    proxy['reality-opts'] = `{ public-key: ${yamlQuote(publicKey)}${p.get('sid') ? `, short-id: ${yamlQuote(p.get('sid'))}` : ''} }`;
  }
  if (proxy.network === 'ws') { proxy['ws-opts'] = `{ path: ${yamlQuote(p.get('path') || '/')}${p.get('host') ? `, headers: { Host: ${yamlQuote(p.get('host'))} }` : ''} }`; }
  if (proxy.network === 'grpc') { proxy['grpc-opts'] = `{ grpc-service-name: ${yamlQuote(p.get('serviceName') || '')} }`; }
  return proxy;
}
function parseHy2(url) {
  const p = url.searchParams;
  const proxy = {
    name: decode(url.hash.slice(1)) || `${url.hostname} · Hysteria2`, type: 'hysteria2', server: url.hostname,
    port: Number(url.port || 443), password: decode(url.username),
    sni: p.get('sni') || p.get('peer'), alpn: p.get('alpn'),
    'skip-cert-verify': truthy(p.get('insecure') || p.get('allowInsecure')),
    obfs: p.get('obfs'), 'obfs-password': p.get('obfs-password') || p.get('obfsPassword'),
    up: p.get('upmbps') || p.get('up'), down: p.get('downmbps') || p.get('down')
  };
  if (!proxy.password) throw new Error('Hysteria2 链接缺少密码。');
  return proxy;
}
function makeYaml(items) {
  const plain = items.map(item => Object.fromEntries(Object.entries(item).map(([k,v]) => [k, v?.raw || v])));
  const lines = ['proxies:'];
  for (const item of plain) for (const [key,value] of Object.entries(item)) {
    if (value === undefined || value === '' || value === null) continue;
    const raw = ['reality-opts','ws-opts','grpc-opts'].includes(key);
    lines.push(`${key === 'name' ? '  - ' : '    '}${key}: ${raw ? escapeHtml(value) : yamlValue(value)}`);
  }
  output.innerHTML = `<code>${lines.join('\n')}</code>`;
  latestYaml = plainYamlWithRaw(plain);
}
function plainYamlWithRaw(items) { return 'proxies:\n' + items.map(item => Object.entries(item).filter(([,v]) => v !== undefined && v !== '' && v !== null).map(([key,value],i) => `${i ? '    ' : '  - '}${key}: ${['reality-opts','ws-opts','grpc-opts'].includes(key) ? value : (typeof value === 'boolean' || typeof value === 'number' ? value : JSON.stringify(String(value)))}`).join('\n')).join('\n'); }
function showDetails(proxy) {
  const keys = [['协议', proxy.type], ['服务器', `${proxy.server}:${proxy.port}`], ['传输', proxy.network || 'QUIC'], ['TLS SNI', proxy.servername || proxy.sni || '未设置'], ['指纹 / ALPN', proxy['client-fingerprint'] || proxy.alpn || '默认'], ['跳过证书', proxy['skip-cert-verify'] ? '是' : '否']];
  detailGrid.innerHTML = keys.map(([label,value]) => `<div class="detail"><label>${label}</label><strong title="${escapeHtml(String(value))}">${escapeHtml(String(value))}</strong></div>`).join('');
  details.hidden = false;
}
function fail(message) {
  output.innerHTML = `<code><span class="yaml-bool"># 转换失败</span>\n\n<span class="yaml-string">${escapeHtml(message)}</span></code>`;
  $('#outputFooter').textContent = '请修正链接后重试。'; copyBtn.disabled = true; downloadBtn.disabled = true; details.hidden = true;
}
function convert() {
  try {
    const url = parseUrl(sourceLink.value);
    const proxy = url.protocol === 'vless:' ? parseVless(url) : parseHy2(url);
    makeYaml([proxy]); showDetails(proxy); copyBtn.disabled = false; downloadBtn.disabled = false;
    protocolChip.textContent = proxy.type === 'vless' ? 'VLESS · REALITY' : 'HYSTERIA2'; protocolChip.classList.add('active');
    inputHint.textContent = '已成功识别并映射参数'; $('#outputFooter').innerHTML = '生成的是完整的 <code>proxies:</code> 片段，可直接合并或下载。';
  } catch (err) { fail(err.message); protocolChip.textContent = '格式有误'; protocolChip.classList.remove('active'); inputHint.textContent = '等待有效的分享链接'; }
}
convertBtn.addEventListener('click', convert);
sourceLink.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') convert(); });
sourceLink.addEventListener('input', () => { const value = sourceLink.value.trim().toLowerCase(); protocolChip.textContent = value.startsWith('vless://') ? 'VLESS' : value.startsWith('hy2://') || value.startsWith('hysteria2://') ? 'HYSTERIA2' : '等待输入'; protocolChip.classList.toggle('active', Boolean(value)); });
document.querySelectorAll('[data-example]').forEach(btn => btn.addEventListener('click', () => { sourceLink.value = examples[btn.dataset.example]; convert(); }));
copyBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(latestYaml); } catch { const area = document.createElement('textarea'); area.value = latestYaml; document.body.append(area); area.select(); document.execCommand('copy'); area.remove(); } copyToast.classList.add('show'); setTimeout(() => copyToast.classList.remove('show'), 1600); });
downloadBtn.addEventListener('click', () => { const blob = new Blob([latestYaml + '\n'], { type:'text/yaml;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'clash-meta-proxy.yaml'; a.click(); URL.revokeObjectURL(a.href); });
