'use strict';
/**
 * Web SSH Terminal qua VM trung gian:  Trinh duyet -> Backend -> [SSH #1 toi VM gateway] -> forwardOut -> [SSH #2 toi may dich]
 * Nguoi dung luon phai nhap tai khoan CUA MINH tren may dich (backend khong dua mat khau VM cua admin cho user).
 * Du lieu ra: SSE; du lieu vao: POST. Khong can WebSocket.
 */
const { Client } = require('ssh2');
const vms = require('./vms');
const ssh = require('./ssh');
const events = require('./events');
const audit = require('./audit');
const { HttpError } = require('../http');
const { randomToken } = require('../security/crypto');

const sessions = new Map(); // id -> { id, userId, label, gw, target, stream, buf, subs:Set, lastActivity }
const MAX_BUF = 64 * 1024;
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]+\]?$/;

async function open(user, body) {
  const vm = vms.byId(body.vmId);
  if (!vm || !vm.enabled || !(vm.roles || []).includes('gateway')) throw new HttpError(400, 'VM gateway khong hop le');
  let host = String(body.targetHost || '').trim() || vm.ip;
  if (host === 'localhost') host = '127.0.0.1';
  const port = parseInt(body.targetPort, 10) || 22;
  if (!HOST_RE.test(host) || !(port >= 1 && port <= 65535)) throw new HttpError(400, 'Dich khong hop le');
  if (user.role !== 'admin' && !user.portPolicy.allowCustomTarget && !(host === vm.ip || host === '127.0.0.1' || vms.isKnownHost(host)))
    throw new HttpError(403, 'Tai khoan cua ban chi duoc SSH toi cac VM trong he thong');
  const username = String(body.username || '').trim();
  const password = typeof body.password === 'string' ? body.password : '';
  if (!username || !password) throw new HttpError(400, 'Nhap tai khoan va mat khau cua may dich');
  if ([...sessions.values()].filter(s => s.userId === user.id).length >= 5) throw new HttpError(409, 'Toi da 5 terminal cung luc');

  let gw;
  try { gw = await ssh.connect(vm); } catch (e) { throw new HttpError(502, 'Khong ket noi duoc VM trung gian: ' + e.message); }
  let sock;
  try { sock = await ssh.forwardOut(gw, host, port); } catch (e) { gw.end(); throw new HttpError(502, `VM khong toi duoc ${host}:${port}: ${e.message}`); }

  const target = new Client();
  const s = { id: randomToken(12), userId: user.id, label: `${username}@${host}:${port} via ${vm.name}`, gw, target, stream: null, buf: '', subs: new Set(), lastActivity: Date.now() };
  try {
    await new Promise((resolve, reject) => {
      target.once('ready', resolve); target.once('error', reject);
      target.connect({ sock, username, password, readyTimeout: 8000 });
    });
    s.stream = await new Promise((resolve, reject) => target.shell({ term: 'dumb', cols: +body.cols || 120, rows: +body.rows || 30 }, (e, st) => e ? reject(e) : resolve(st)));
  } catch (e) { try { target.end(); } catch {} try { gw.end(); } catch {} throw new HttpError(401, 'Dang nhap may dich that bai: ' + e.message); }

  s.stream.on('data', d => push(s, d.toString('utf8')));
  s.stream.stderr && s.stream.stderr.on('data', d => push(s, d.toString('utf8')));
  s.stream.on('close', () => close(s.id, 'Phien SSH da dong'));
  gw.on('close', () => close(s.id, 'Mat ket noi toi VM trung gian'));
  gw.on('error', () => {});
  target.on('error', () => {});
  sessions.set(s.id, s);
  audit.log(user, 'terminal.open', s.label);
  return { id: s.id, label: s.label };
}

function push(s, text) {
  s.buf += text; if (s.buf.length > MAX_BUF) s.buf = s.buf.slice(-MAX_BUF);
  s.lastActivity = Date.now();
  for (const res of s.subs) { try { res.write(`data: ${JSON.stringify(text)}\n\n`); } catch {} }
}

function get(user, id) {
  const s = sessions.get(id);
  if (!s || (s.userId !== user.id && user.role !== 'admin')) throw new HttpError(404, 'Khong tim thay terminal');
  return s;
}

function subscribe(user, id, res) {
  const s = get(user, id);
  res.write(`data: ${JSON.stringify(s.buf)}\n\n`);
  s.subs.add(res); res.on('close', () => s.subs.delete(res));
}
function input(user, id, data) { const s = get(user, id); s.lastActivity = Date.now(); s.stream.write(String(data).slice(0, 8192)); }
function resize(user, id, cols, rows) { const s = get(user, id); try { s.stream.setWindow(+rows || 30, +cols || 120, 0, 0); } catch {} }

function close(id, reason = 'closed') {
  const s = sessions.get(id); if (!s) return;
  sessions.delete(id);
  for (const res of s.subs) { try { res.write(`event: closed\ndata: ${JSON.stringify(reason)}\n\n`); res.end(); } catch {} }
  try { s.stream && s.stream.end(); } catch {}
  try { s.target.end(); } catch {}
  try { s.gw.end(); } catch {}
}

const list = user => [...sessions.values()].filter(s => user.role === 'admin' || s.userId === user.id).map(s => ({ id: s.id, label: s.label, userId: s.userId }));
setInterval(() => { for (const s of [...sessions.values()]) if (Date.now() - s.lastActivity > 30 * 60000) close(s.id, 'Het thoi gian cho (30 phut)'); }, 60000).unref();
function closeAll() { for (const id of [...sessions.keys()]) close(id, 'Server dang tat'); }

module.exports = { open, subscribe, input, resize, close: (user, id) => { get(user, id); close(id, 'Da dong boi nguoi dung'); }, list, closeAll };
