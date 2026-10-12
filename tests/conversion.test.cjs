const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const element = () => ({addEventListener(){}, classList:{add(){},remove(){},toggle(){}}});
const context = vm.createContext({URL, atob, document:{querySelector:element,querySelectorAll:()=>[]}});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../app.js'),'utf8'),context);
function hy(uri) { return JSON.parse(vm.runInContext(`JSON.stringify(parseHy2(parseUrl(${JSON.stringify(uri)})))`,context)); }
const prefix='hy2://test@example.com';
test('official mixed ports and IPv6 port hopping',()=>{
 const p=hy(prefix+':443,20000-30000/#hop'); assert.equal(p.ports,'443,20000-30000'); assert.equal(p.port,443);
 const ipv6=hy('hy2://test@[2001:db8::1]:20000-30000/'); assert.equal(ipv6.server,'2001:db8::1'); assert.equal(ipv6.ports,'20000-30000');
});
test('mport and ports extensions retain fixed and random hop intervals',()=>{
 const p=hy(prefix+':443?mport=20000-30000&hop-interval=15-30'); assert.equal(p.ports,'20000-30000'); assert.equal(p['hop-interval'],'15-30');
 assert.equal(hy(prefix+'?ports=443,8443&hopInterval=10')['hop-interval'],'10');
});
test('preserves full userpass, colons and literal/encoded plus',()=>{
 assert.equal(hy('hy2://user:pa+ss@example.com').password,'user:pa+ss');
 assert.equal(hy('hy2://a%2Bb%3Ac@example.com').password,'a+b:c');
 assert.equal(hy('hy2://user:@example.com').password,'user:');
});
test('normalizes certificate pin and retains ECH',()=>{
 const p=hy(prefix+'?pinSHA256='+Array(32).fill('AB').join(':')+'&insecure=1&ech=AAj%2BDQAEAAAAAA%3D%3D');
 assert.equal(p.fingerprint,'ab'.repeat(32)); assert.equal(p['skip-cert-verify'],true);
 assert.deepEqual(p['ech-opts'],{enable:true,config:'AAj+DQAEAAAAAA=='});
});
test('gecko extensions are numeric and obfs credentials are preserved',()=>{
 const p=hy(prefix+'?obfs=gecko&obfs-password=a%2Bb&obfs-min-packet-size=512&obfs-max-packet-size=1200');
 assert.equal(p['obfs-password'],'a+b'); assert.equal(p['obfs-min-packet-size'],512); assert.equal(p['obfs-max-packet-size'],1200);
});
test('rejects invalid ports and conflicting port definitions',()=>{
 for(const suffix of [':0',':65536',':100-99',':443,,8443',':443-65536','?mport=abc',':443,8443?mport=9000-9001']) assert.throws(()=>hy(prefix+suffix));
});
test('rejects invalid hop intervals, pins and obfuscation',()=>{
 for(const query of ['ports=443,8443&hop-interval=4','ports=443,8443&hop-interval=30-15','ports=443,8443&hop-interval=15s','pinSHA256=bad','obfs=unknown','obfs=gecko','obfs=gecko&obfs-password=x&obfs-min-packet-size=1200&obfs-max-packet-size=512']) assert.throws(()=>hy(prefix+'?'+query));
});
test('optional auth and default port follow the official URI',()=>{
 assert.equal(hy('hysteria2://example.com/').port,443); assert.equal(hy('hysteria2://example.com/').password,'');
});
test('output leaves keys and values unquoted, including nested objects and arrays',()=>{
 const rendered=vm.runInContext(`flowMap({name: 'Tokyo HY2', port: 443, password: '00123', tls: true, alpn: ['h3', 'h2'], 'reality-opts': {'public-key': 'abc', 'support-x25519mlkem768': true}, missing: undefined})`,context);
 assert.equal(rendered,'{name: Tokyo HY2, port: 443, password: 00123, tls: true, alpn: [h3, h2], reality-opts: {public-key: abc, support-x25519mlkem768: true}}');
});
test('multiple output items use the same unquoted format',()=>{
 assert.equal(vm.runInContext(`makeYaml([{name: 'one', password: 'a+b:c'}, {name: 'two', udp: true}])`,context), '- {name: one, password: a+b:c}\n- {name: two, udp: true}');
});
test('VLESS Reality and SS2022 conversions remain supported',()=>{
 const result=vm.runInContext(`JSON.stringify([parseVless(parseUrl(examples.vless)),parseSs2022(parseUrl(examples.ss2022))])`,context);
 const [v,s]=JSON.parse(result);assert.equal(v['reality-opts']['support-x25519mlkem768'],true);assert.equal(s.cipher,'2022-blake3-aes-256-gcm');
});
test('unsupported Realm links produce an explicit error',()=>assert.throws(()=>vm.runInContext(`parseUrl('hysteria2+realm://token@example.com/room?auth=test')`,context),/Realm/));
test('rejects empty or conflicting repeated hopping options',()=>{
 for(const query of ['mport=','ports=','ports=443,8443&hop-interval=','ports=443,8443&hop-interval=10&hopInterval=20','ports=443,8443&ports=9000']) assert.throws(()=>hy(prefix+'?'+query));
 assert.equal(hy(prefix+'?ports=443,8443&ports=443,8443').ports,'443,8443');
});
