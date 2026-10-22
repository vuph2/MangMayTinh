'use strict';
/** Lop tien ich SSH dung chung: ket noi (TOFU host key), exec, sudo, forwardOut. */
const { Client } = require('ssh2');
const net = require('net');
const vms = require('./vms');

const shq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";

/** Tao ket noi SSH rieng toi 1 VM. Xac minh host key kieu TOFU (lan dau tin tuong, sau do phai trung khop). */
function connect(vm, { timeout = 6000, sock } = {}) {
  return new Promise((resolve, reject) => {
    const c = vms.creds(vm);
    if (!c.username || (!c.password && !c.privateKey)) return reject(new Error('VM chua cau hinh tai khoan SSH'));
    const conn = new Client();
    let hostKeyBad = false, done = false;
    const fail = e => { if (done) return; done = true; try { conn.end(); } catch {} reject(e); };
    conn.once('ready', () => { if (done) return; done = true; resolve(conn); });
    conn.on('error', e => fail(hostKeyBad ? new Error('Host key cua VM da thay doi (nghi ngo MITM). Admin can "Reset host key" neu VM duoc cai lai.') : e));
    conn.once('timeout', () => fail(new Error('SSH timeout')));
    conn.connect({
      ...c, sock, readyTimeout: timeout, keepaliveInterval: 15000, keepaliveCountMax: 3,
      hostHash: 'sha256',
      hostVerifier: hash => {
        if (!vm.hostKey) { vm.hostKey = hash; vms.save(); return true; }
        if (vm.hostKey !== hash) { hostKeyBad = true; return false; }
        return true;
      }
    });
  });
}

// ---- Ket noi dieu khien dung chung cho exec (metrics, iptables, rules...) ----
const control = new Map(); // vmId -> Promise<Client>
function getControl(vm) {
  let p = control.get(vm.id);
  if (p) return p;
  p = connect(vm).then(conn => {
    const drop = () => { if (control.get(vm.id) === p) control.delete(vm.id); };
    conn.on('close', drop); conn.on('error', drop); conn.on('end', drop);
    return conn;
  });
  control.set(vm.id, p);
  p.catch(() => { if (control.get(vm.id) === p) control.delete(vm.id); });
  return p;
}
function dropControl(vmId) {
  const p = control.get(vmId);
  control.delete(vmId);
  if (p) p.then(c => c.end()).catch(() => {});
}

/** Chay lenh tren VM. opts: { sudo, timeout, stdin } */
async function exec(vm, cmd, opts = {}) {
  const { sudo = false, timeout = 20000, stdin } = opts;
  const conn = await getControl(vm);
  let command = cmd, input = stdin;
  if (sudo) {
    if (vm.sudoMode === 'nopasswd') command = `sudo -n bash -c ${shq(cmd)}`;
    else { command = `sudo -S -p '' bash -c ${shq(cmd)}`; input = vms.sudoPassword(vm) + '\n'; }
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Lenh SSH qua thoi gian')), timeout);
    conn.exec(command, (err, stream) => {
      if (err) { clearTimeout(timer); dropControl(vm.id); return reject(err); }
      let out = '', errOut = '';
      stream.on('data', d => { out += d; });
      stream.stderr.on('data', d => { errOut += d; });
      stream.on('close', code => { clearTimeout(timer); resolve({ code, stdout: out, stderr: errOut }); });
      if (input !== undefined) stream.end(input); else stream.end();
    });
  });
}

/** Mo kenh TCP tu VM toi host:port (day la "dau ra" - dich chi thay IP cua VM) */
function forwardOut(conn, host, port) {
  return new Promise((resolve, reject) => {
    conn.forwardOut('127.0.0.1', 0, host, port, (err, stream) => err ? reject(err) : resolve(stream));
  });
}

function tcpCheck(host, port, timeout = 1200) {
  return new Promise(resolve => {
    const s = new net.Socket(); let t0 = Date.now(), done = false;
    const end = ok => { if (done) return; done = true; s.destroy(); resolve(ok ? Date.now() - t0 : -1); };
    s.setTimeout(timeout); s.once('connect', () => end(true)); s.once('timeout', () => end(false)); s.once('error', () => end(false));
    s.connect(port, host);
  });
}

module.exports = { connect, exec, getControl, dropControl, forwardOut, tcpCheck, shq };
