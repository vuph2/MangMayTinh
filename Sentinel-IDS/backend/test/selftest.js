'use strict';
/**
 * Self-test end-to-end: dung SSH server GIA LAP (chi trong bai test, khong nam trong ung dung)
 * de kiem chung backend: Auth/Admin, VM health+metrics, Gateway tunnel (IP user bi an), ngat khi co su co,
 * doi port, policy port, Active Response (iptables), Rule deploy, Sensor log, Telegram error handling.
 * Chay:  npm test
 */
const net = require('net');
const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { Server, utils } = require('ssh2');

const API = 'http://127.0.0.1:3399/api';
const SSH_PORT = 2299, WEB_PORT = 8399;
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✔', m); } else { fail++; console.log('  ✘ FAIL:', m); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- Dich (website) gia lap: ghi lai IP nguon nhin thay ----
const seenRemote = [];
const web = http.createServer((req, res) => { seenRemote.push(req.socket.remoteAddress); res.end('hello-from-target'); }).listen(WEB_PORT, '127.0.0.1');

// ---- VM (SSH) gia lap ----
const cmds = [];
const hostKey = utils.generateKeyPairSync('ed25519').private;
const sshd = new Server({ hostKeys: [hostKey] }, client => {
  client.on('authentication', ctx => (ctx.method === 'password' && ctx.username === 'vm' && ctx.password === 'pw') ? ctx.accept() : ctx.reject());
  client.on('error', () => {});
  client.on('ready', () => {
    client.on('session', accept => {
      const s = accept();
      s.on('pty', acc => acc && acc());
      s.on('shell', acc => { const sh = acc(); sh.write('welcome-shell\n'); sh.on('data', d => sh.write('echo:' + d)); });
      s.on('exec', (acc, rej, info) => {
        const st = acc(); const c = info.command; cmds.push(c);
        if (c.includes('tail -F')) { st.write('10/22/2026-08:59:01.123456  [**] [1:2010935:3] ET SCAN Possible Nmap User-Agent Observed [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.56.101:44444 -> 192.168.56.102:80\n'); return; }
        let stdin = ''; st.on('data', d => { stdin += d; });
        st.on('end', () => {
          if (c.includes('/proc/stat')) st.write('cpu  100 0 100 800 0 0 0 0\ncpu  200 0 200 1600 0 0 0 0\n2000 500\n0.10 0.20 0.30\n1234\n');
          else if (c.includes('DEPLOY_OK')) st.write('DEPLOY_OK\n');
          else if (c.startsWith('cat >')) cmds.push('STDIN:' + stdin.trim());
          st.exit(0); st.end();
        });
      });
    });
    client.on('tcpip', (acc, rej, info) => { const sock = net.connect(info.destPort, info.destIP); sock.on('error', () => rej()); sock.on('connect', () => { const ch = acc(); ch.pipe(sock).pipe(ch); ch.on('close', () => sock.destroy()); sock.on('error', () => ch.close()); }); });
  });
}).listen(SSH_PORT, '127.0.0.1');

const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
const be = spawn('node', [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: '3399', DATA_DIR: DATA, ADMIN_PASSWORD: 'Admin12345', FRONTEND_PORT: '5199' }, stdio: ['ignore', 'pipe', 'pipe'] });
be.stderr.on('data', d => process.stderr.write(d));

async function call(method, p, body, token) {
  const r = await fetch(API + p, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = {}; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}
const get = (p, t) => call('GET', p, null, t), post = (p, b, t) => call('POST', p, b, t);

(async () => {
  for (let i = 0; i < 40; i++) { try { await fetch(API + '/health'); break; } catch { await sleep(150); } }
  console.log('\n[1] Auth & phan quyen');
  let r = await post('/auth/login', { username: 'admin', password: 'sai' }); ok(r.status === 401, 'Sai mat khau -> 401');
  r = await get('/alerts'); ok(r.status === 401, 'Khong token -> 401');
  r = await post('/auth/login', { username: 'admin', password: 'Admin12345' }); ok(r.status === 200 && r.body.token, 'Admin dang nhap');
  const A = r.body.token;
  r = await post('/users', { username: 'alice', password: 'alice12345', role: 'user', mustChangePassword: false }, A); ok(r.status === 200, 'Admin tao user');
  r = await post('/users', { username: 'alice', password: 'alice12345' }, A); ok(r.status === 409, 'Trung username -> 409');
  r = await post('/users', { username: 'bob', password: '123' }, A); ok(r.status === 400, 'Mat khau yeu bi tu choi');
  r = await post('/auth/login', { username: 'alice', password: 'alice12345' }); const U = r.body.token; ok(!!U, 'User dang nhap');
  r = await get('/users', U); ok(r.status === 403, 'User khong xem duoc danh sach user (403)');
  r = await post('/vms', { name: 'x', ip: '1.1.1.1' }, U); ok(r.status === 403, 'User khong tao duoc VM');
  r = await get('/vms', U); ok(r.status === 200, 'User xem VM'); 

  console.log('\n[2] VM + health + metrics that');
  r = await post('/vms', { name: 'gw-vm', ip: '127.0.0.1', sshPort: SSH_PORT, sshUser: 'vm', sshPass: 'pw', roles: ['gateway', 'sensor', 'victim'], logPath: '/var/log/suricata/fast.log' }, A);
  ok(r.status === 200 && !('sshPassEnc' in r.body) && !JSON.stringify(r.body).includes('"pw"'), 'Tao VM, khong lo mat khau');
  const vmId = r.body.id;
  await sleep(400); const stored = fs.readFileSync(path.join(DATA, 'vms.json'), 'utf8'); ok(!stored.includes('"pw"') && stored.includes('enc1:'), 'Mat khau VM luu dang ma hoa');
  r = await post(`/vms/${vmId}/test`, {}, A); ok(r.body.ok === true, 'Test SSH toi VM');
  await sleep(2800);
  r = await get('/vms', U); const vm = r.body.find(v => v.id === vmId);
  ok(vm && vm.on === 1, 'Health: VM online'); ok(vm && vm.cpu === 20, `CPU do that qua /proc/stat = ${vm && vm.cpu}% (ky vong 20)`); ok(vm && vm.mem === 25, `RAM do that = ${vm && vm.mem}% (ky vong 25)`);
  r = await get('/vms', U); ok(!('sshUser' in r.body[0]), 'User thuong khong thay cau hinh SSH cua VM');

  console.log('\n[3] Sensor: doc log Suricata that');
  await sleep(5500);
  r = await get('/alerts', U); ok(r.body.data.length >= 1 && r.body.data[0].sid === 2010935 && r.body.data[0].ip === '192.168.56.101', 'Canh bao Suricata duoc parse tu log qua SSH');
  ok(r.body.data[0].source === 'suricata', 'Nguon = suricata (khong phai du lieu gia)');

  console.log('\n[4] Gateway: User -> VM -> Dich (an IP user)');
  r = await get('/ports/policy', U); ok(r.status === 200, 'Lay chinh sach cong');
  r = await post('/gateway/tunnels', { toolId: 'dvwa', vmId, targetHost: '127.0.0.1', targetPort: WEB_PORT, localPort: 9999 }, U); ok(r.status === 403, 'Cong ngoai dai cap -> 403');
  r = await post('/gateway/tunnels', { toolId: 'dvwa', vmId, targetHost: '127.0.0.1', targetPort: WEB_PORT, localPort: 8085 }, U);
  ok(r.status === 200 && r.body.running && r.body.kind === 'allocated', 'Tao tunnel tren cong local cap san 8085');
  const tid = r.body.id;
  let page = await (await fetch('http://127.0.0.1:8085/')).text(); ok(page === 'hello-from-target', 'Di duoc User -> VM -> Dich, nhan noi dung that');
  ok(seenRemote.length > 0, 'Dich thay ket noi den tu phia VM (khong co IP cua user)');
  r = await post('/gateway/probe', { vmId, host: '127.0.0.1', port: WEB_PORT }, U); ok(r.body.open === true, 'Probe cong dich qua VM: mo');
  r = await post('/gateway/probe', { vmId, host: '127.0.0.1', port: 1 }, U); ok(r.body.open === false, 'Probe cong dong: dong');
  r = await call('PATCH', '/gateway/tunnels/' + tid, { localPort: 20001 }, U); ok(r.status === 200 && r.body.localPort === 20001 && r.body.kind === 'private' && r.body.running, 'DOI PORT sang cong private 20001, tunnel tu chay lai');
  page = await (await fetch('http://127.0.0.1:20001/')).text(); ok(page === 'hello-from-target', 'Cong moi hoat dong');
  try { await fetch('http://127.0.0.1:8085/'); ok(false, 'Cong cu phai dong'); } catch { ok(true, 'Cong cu da dong'); }
  r = await post('/gateway/tunnels', { toolId: 'tcp', vmId, targetHost: '127.0.0.1', targetPort: WEB_PORT, localPort: 20001 }, U); ok(r.status === 409, 'Trung cong -> 409');
  r = await post('/gateway/tunnels', { toolId: 'tcp', vmId, targetHost: '127.0.0.1', targetPort: WEB_PORT, localPort: 3399 }, U); ok(r.status === 400, 'Cong he thong bi cam');
  r = await get('/gateway/tunnels', A); ok(r.body.length === 1, 'Admin thay tunnel cua user');

  console.log('\n[5] Su co -> ngat tai VM + thong bao');
  r = await post('/alerts', { ip: '192.168.56.101', dst_ip: '127.0.0.1', dst_port: 80, type: 'SQL injection', sev: 'High', sid: 1, signature: 'test incident' });
  ok(r.status === 401, 'Ingest khong key -> 401');
  const key = (await get('/settings/ingest-key', A)).body.ingestKey;
  r = await fetch(API + '/alerts', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Ingest-Key': key }, body: JSON.stringify({ ip: '192.168.56.101', dst_ip: '127.0.0.1', dst_port: 80, type: 'SQL injection', sev: 'High', sid: 1, signature: 'test incident' }) });
  ok(r.status === 200, 'Ingest voi X-Ingest-Key');
  await sleep(300);
  r = await get('/gateway/tunnels', U); ok(r.body[0].running === false && /incident/.test(r.body[0].lastStopReason), 'Tunnel bi NGAT tu dong do canh bao High: ' + r.body[0].lastStopReason);
  try { await fetch('http://127.0.0.1:20001/'); ok(false, 'Cong phai dong'); } catch { ok(true, 'Ket noi toi dich bi cat ngay'); }
  r = await post('/gateway/tunnels/' + tid + '/start', {}, U); ok(r.status === 200 && r.body.running, 'User bat lai tunnel');
  r = await post('/gateway/cut-all', {}, U); ok(r.body.cut === 1, 'Nut ngat tat ca');

  console.log('\n[5b] Web SSH Terminal qua VM');
  r = await post('/terminal', { vmId, targetHost: '127.0.0.1', targetPort: SSH_PORT, username: 'vm', password: 'sai' }, U); ok(r.status === 401, 'Terminal: sai mat khau may dich -> 401');
  r = await post('/terminal', { vmId, targetHost: '127.0.0.1', targetPort: SSH_PORT, username: 'vm', password: 'pw' }, U); ok(r.status === 200 && r.body.id, 'Terminal: mo shell tren dich qua VM (SSH long SSH)');
  const termId = r.body.id;
  r = await post(`/terminal/${termId}/ticket`, {}, U); const tk = r.body.ticket;
  const sse = await fetch(`${API}/terminal/${termId}/stream?ticket=${tk}`);
  const reader = sse.body.getReader(); let got = '';
  const pump = (async () => { const dec = new TextDecoder(); for (;;) { const { value, done } = await reader.read(); if (done) break; got += dec.decode(value); } })().catch(() => {});
  await sleep(400); await post(`/terminal/${termId}/input`, { data: 'hello\n' }, U); await sleep(500);
  ok(got.includes('welcome-shell') && got.includes('echo:hello'), 'Terminal: nhan dau ra va echo lenh qua SSE');
  r = await post(`/terminal/${termId}/input`, { data: 'x' }, A); ok(r.status === 200, 'Admin co the xem/dieu khien terminal'); 
  r = await call('DELETE', `/terminal/${termId}`, null, U); ok(r.status === 200, 'Dong terminal'); reader.cancel().catch(() => {});

  console.log('\n[6] Active Response / Rules');
  r = await post('/blocklist', { ip: '10.9.9.9', reason: 'test' }, U); ok(r.status === 403, 'User khong chan IP duoc');
  r = await post('/blocklist', { ip: '10.9.9.9; rm -rf /' }, A); ok(r.status === 400, 'Chong injection trong IP');
  r = await post('/blocklist', { ip: '127.0.0.1' }, A); ok(r.status === 400, 'Khong cho chan IP cua he thong');
  r = await post('/blocklist', { ip: '10.9.9.9', reason: 'test' }, A);
  ok(r.status === 200 && r.body.status === 'applied', 'Chan IP: iptables chay that qua SSH (status=applied)');
  ok(cmds.some(c => c.includes('iptables -I INPUT -s 10.9.9.9 -j DROP')), 'Lenh iptables DROP da toi VM');
  r = await call('DELETE', '/blocklist/10.9.9.9', null, A); ok(cmds.some(c => c.includes('iptables -D INPUT -s 10.9.9.9')), 'Bo chan: iptables -D da toi VM');
  r = await post('/rules', { raw: 'alert tcp any any -> $HOME_NET 22 (msg:"SSH test"; sid:1000101; rev:1;)' }, A); ok(r.status === 200, 'Them luat hop le');
  r = await post('/rules', { raw: 'xoa het' }, A); ok(r.status === 400, 'Luat sai cu phap bi tu choi');
  r = await post('/rules/deploy', { vmId }, A); ok(r.body.ok === true, 'Deploy luat xuong sensor');
  ok(cmds.some(c => c.startsWith('STDIN:') && c.includes('sid:1000101')), 'Noi dung local.rules duoc ghi that');

  console.log('\n[7] Dich vu ngoai (khong gia lap)');
  r = await post('/settings/telegram-test', { token: '123:abc', chatId: '1' }, A); ok(r.status === 502, 'Telegram that: token sai -> bao loi tu API (khong tra "gia lap thanh cong")');
  r = await get('/wazuh/status', U); ok(r.body.configured === false, 'Wazuh chua cau hinh -> bao that, khong co du lieu mau');
  r = await get('/audit', A); ok(r.body.some(a => a.action === 'tunnel.cut') && r.body.some(a => a.action === 'user.create'), 'Audit log ghi day du');
  r = await get('/audit', U); ok(r.status === 403, 'User khong xem audit');
  r = await post('/auth/logout', {}, U); r = await get('/vms', U); ok(r.status === 401, 'Logout thu hoi token');

  console.log(`\nKet qua: ${pass} dat, ${fail} that bai`);
  be.kill('SIGINT'); sshd.close(); web.close();
  setTimeout(() => process.exit(fail ? 1 : 0), 400);
})().catch(e => { console.error(e); be.kill(); process.exit(1); });
