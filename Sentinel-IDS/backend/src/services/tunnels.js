'use strict';
/**
 * GATEWAY / PORT TUNNELS
 *   User  ->  [cong local tren backend]  ->  SSH toi VM (gateway)  ->  forwardOut  ->  Dich (website/dich vu)
 * Dich chi nhin thay IP cua VM. IP cua user khong bao gio duoc gui di. Moi tunnel co 1 ket noi SSH RIENG,
 * nen "ngat" = dong ket noi do ngay tai VM, moi socket/kenh bi huy tuc thi, sau do thong bao cho user.
 */
const net = require('net');
const store = require('../db/store');
const cfg = require('../config');
const vms = require('./vms');
const ssh = require('./ssh');
const tools = require('./tools');
const policy = require('./portpolicy');
const settings = require('./settings');
const events = require('./events');
const audit = require('./audit');
const telegram = require('./telegram');
const users = require('./users');
const { HttpError } = require('../http');

const col = store.open('tunnels', []);
const runtime = new Map(); // id -> { server, conn, sockets:Set, startedAt, expiresAt, lastActivity, bytesIn, bytesOut, conns, error }
const uid = () => 't-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);

const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]+\]?$/;

function resolveTarget(user, tool, body, vm) {
  let host, port, scheme = tool.scheme, path = tool.path || '';
  if (tool.kind === 'url') {
    let u;
    try { u = new URL(String(body.url || '')); } catch { throw new HttpError(400, 'URL khong hop le'); }
    if (!['http:', 'https:'].includes(u.protocol)) throw new HttpError(400, 'Chi ho tro http/https');
    host = u.hostname.replace(/^\[|\]$/g, ''); scheme = u.protocol.slice(0, -1);
    port = u.port ? +u.port : (scheme === 'https' ? 443 : 80);
    path = (u.pathname || '/') + (u.search || '');
  } else {
    host = String(body.targetHost || '').trim() || vm.ip;
    port = parseInt(body.targetPort, 10) || tool.port;
    if (host === 'localhost') host = '127.0.0.1';
  }
  if (!HOST_RE.test(host) || host.length > 253) throw new HttpError(400, 'Host dich khong hop le');
  if (!(port >= 1 && port <= 65535)) throw new HttpError(400, 'Cong dich khong hop le');
  // Nguoi dung thuong: neu khong duoc phep tu nhap dich -> chi duoc toi chinh VM hoac VM da dang ky
  if (user.role !== 'admin' && !user.portPolicy.allowCustomTarget && tool.kind !== 'url') {
    const ok = host === vm.ip || host === '127.0.0.1' || vms.isKnownHost(host);
    if (!ok) throw new HttpError(403, 'Tai khoan cua ban chi duoc mo dich la cac VM trong he thong');
  }
  if (user.role !== 'admin' && !user.portPolicy.allowCustomTarget && tool.kind === 'url') throw new HttpError(403, 'Tai khoan cua ban khong duoc mo website/link tuy y');
  return { host, port, scheme, path };
}

function view(t) {
  const r = runtime.get(t.id);
  const vm = vms.byId(t.vmId);
  return {
    id: t.id, ownerId: t.ownerId, ownerName: t.ownerName, name: t.name, toolId: t.toolId, vmId: t.vmId, vmName: vm ? vm.name : '(da xoa)', vmIp: vm ? vm.ip : '',
    targetHost: t.targetHost, targetPort: t.targetPort, scheme: t.scheme, path: t.path, localPort: t.localPort, kind: t.kind, ephemeral: !!t.ephemeral,
    createdAt: t.createdAt, running: !!r, startedAt: r ? r.startedAt : 0, expiresAt: r ? r.expiresAt : 0, connections: r ? r.conns : 0,
    bytesIn: r ? r.bytesIn : 0, bytesOut: r ? r.bytesOut : 0, lastError: t.lastError || '', lastStopReason: t.lastStopReason || ''
  };
}
const pushState = t => events.emit('tunnel_state', view(t), { userId: t.ownerId, alsoAdmins: true });

const listFor = user => col.data.filter(t => user.role === 'admin' || t.ownerId === user.id).map(view);
function getOwned(user, id) {
  const t = col.data.find(x => x.id === id);
  if (!t || (user.role !== 'admin' && t.ownerId !== user.id)) throw new HttpError(404, 'Khong tim thay tunnel');
  return t;
}

async function create(user, body) {
  const tool = tools.byId(body.toolId);
  if (!tool || !tool.enabled) throw new HttpError(400, 'Cong cu khong ton tai');
  if (tool.kind === 'ssh') throw new HttpError(400, 'SSH Terminal mo qua /api/terminal');
  const vm = vms.byId(body.vmId);
  if (!vm || !vm.enabled || !(vm.roles || []).includes('gateway')) throw new HttpError(400, 'VM khong phai may trung gian (gateway) hop le');
  const target = resolveTarget(user, tool, body, vm);

  const mine = col.data.filter(t => t.ownerId === user.id);
  const limit = user.role === 'admin' ? 100 : Math.min(user.portPolicy.maxTunnels, settings.get().gateway.maxTunnelsPerUser);
  if (mine.length >= limit) throw new HttpError(409, `Da dat gioi han ${limit} tunnel. Hay xoa bot truoc khi tao moi.`);

  const used = new Set(col.data.map(t => t.localPort));
  let localPort = parseInt(body.localPort, 10);
  let kind;
  if (!localPort) { localPort = await policy.pickFree(user, used); kind = 'allocated'; }
  else {
    kind = policy.classify(user, localPort);
    if (used.has(localPort)) throw new HttpError(409, `Cong ${localPort} da gan cho tunnel khac`);
  }
  const t = {
    id: uid(), ownerId: user.id, ownerName: user.username,
    name: String(body.name || `${tool.name} via ${vm.name}`).slice(0, 64), toolId: tool.id, vmId: vm.id,
    targetHost: target.host, targetPort: target.port, scheme: target.scheme, path: target.path,
    localPort, kind, ephemeral: !!body.ephemeral, createdAt: Date.now()
  };
  col.data.push(t); col.save();
  audit.log(user, 'tunnel.create', `${t.name} :${localPort} -> ${vm.name} -> ${t.targetHost}:${t.targetPort}`);
  if (body.start !== false) await start(user, t.id);
  return view(t);
}

async function start(user, id) {
  const t = getOwned(user, id);
  if (runtime.has(t.id)) return view(t);
  const vm = vms.byId(t.vmId);
  if (!vm || !vm.enabled) throw new HttpError(400, 'VM khong kha dung');
  if (!(await policy.canBind(t.localPort))) throw new HttpError(409, `Cong local ${t.localPort} dang bi tien trinh khac su dung`);

  let conn;
  try { conn = await ssh.connect(vm); }
  catch (e) { t.lastError = 'Khong ket noi duoc VM: ' + e.message; col.save(); throw new HttpError(502, t.lastError); }

  const st = settings.get().gateway;
  const rt = { server: null, conn, sockets: new Set(), startedAt: Date.now(), lastActivity: Date.now(), bytesIn: 0, bytesOut: 0, conns: 0,
    expiresAt: st.maxLifetimeMin ? Date.now() + st.maxLifetimeMin * 60000 : 0 };
  const server = net.createServer(sock => {
    rt.sockets.add(sock); rt.conns++;
    sock.on('error', () => {});
    sock.on('close', () => { rt.sockets.delete(sock); rt.conns = rt.sockets.size; });
    ssh.forwardOut(conn, t.targetHost, t.targetPort).then(stream => {
      if (sock.destroyed) return stream.destroy();
      stream.on('error', () => sock.destroy());
      stream.on('close', () => sock.destroy());
      sock.on('close', () => stream.destroy());
      sock.on('data', d => { rt.bytesOut += d.length; rt.lastActivity = Date.now(); });
      stream.on('data', d => { rt.bytesIn += d.length; rt.lastActivity = Date.now(); });
      sock.pipe(stream); stream.pipe(sock);
    }).catch(() => sock.destroy());
  });
  rt.server = server;
  server.on('error', e => stop(t.id, 'listen-error: ' + e.message, { silent: false }));
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(t.localPort, cfg.TUNNEL_BIND_HOST, () => { server.removeListener('error', reject); resolve(); }); })
    .catch(e => { try { conn.end(); } catch {} throw new HttpError(409, 'Khong mo duoc cong: ' + e.message); });

  // Neu SSH toi VM roi -> cat tunnel ngay
  const lost = () => { if (runtime.get(t.id) === rt) stop(t.id, 'vm-connection-lost', { cutBy: 'vm' }); };
  conn.on('close', lost); conn.on('end', lost); conn.on('error', lost);

  runtime.set(t.id, rt);
  t.lastError = ''; t.lastStopReason = ''; col.save();
  audit.log(user, 'tunnel.start', `${t.name} :${t.localPort}`);
  pushState(t);
  return view(t);
}

/**
 * Ngat tunnel TAI VM. reason: 'user' | 'expired' | 'idle' | 'incident: ...' | 'vm-down' ...
 * Neu ly do la su co (khong phai user tu ngat) -> thong bao cho user (SSE + Telegram ca nhan).
 */
function stop(id, reason = 'user', opts = {}) {
  const t = col.data.find(x => x.id === id);
  const rt = runtime.get(id);
  if (!t) return false;
  if (rt) {
    runtime.delete(id);
    try { rt.server.close(); } catch {}
    for (const s of rt.sockets) { try { s.destroy(); } catch {} }
    try { rt.conn.end(); } catch {}
    try { rt.conn.destroy(); } catch {}
  }
  t.lastStopReason = reason; col.save();
  const forced = reason !== 'user';
  if (rt && forced) {
    const msg = `Tunnel "${t.name}" (cong ${t.localPort}) da bi NGAT tai VM. Ly do: ${reason}. IP cua ban khong bi lo toi dich.`;
    events.emit('gateway_cut', { id: t.id, name: t.name, localPort: t.localPort, reason, ts: Date.now(), message: msg }, { userId: t.ownerId, alsoAdmins: true });
    audit.log(null, 'tunnel.cut', `${t.name} [${t.ownerName}] ${reason}`);
    const owner = users.byId(t.ownerId);
    if (owner && owner.telegramChatId) telegram.notify('🔌 ' + msg, owner.telegramChatId);
  }
  if (rt && t.ephemeral) { col.data.splice(col.data.indexOf(t), 1); col.save(); events.emit('tunnel_removed', { id: t.id }, { userId: t.ownerId, alsoAdmins: true }); }
  else pushState(t);
  return !!rt;
}

function stopAllForVm(vmId, reason) { for (const t of col.data) if (t.vmId === vmId && runtime.has(t.id)) stop(t.id, reason); }

/** Cat tunnel lien quan toi mot su co (alert) */
function cutForIncident(alert, reason) {
  const hit = [];
  for (const t of col.data) {
    if (!runtime.has(t.id)) continue;
    const vm = vms.byId(t.vmId);
    const ips = [alert.ip, alert.dst_ip];
    if ((vm && ips.includes(vm.ip)) || ips.includes(t.targetHost)) { stop(t.id, reason); hit.push(t.id); }
  }
  return hit;
}

async function update(user, id, body) {
  const t = getOwned(user, id);
  const wasRunning = runtime.has(t.id);
  const tool = tools.byId(t.toolId);
  const vm = vms.byId(body.vmId || t.vmId);
  if (body.name !== undefined) t.name = String(body.name).slice(0, 64);
  if (body.localPort !== undefined && parseInt(body.localPort, 10) !== t.localPort) {   // DOI PORT
    const p = parseInt(body.localPort, 10);
    const kind = policy.classify(user.id === t.ownerId ? user : users.byId(t.ownerId), p);
    if (col.data.some(x => x.id !== t.id && x.localPort === p)) throw new HttpError(409, `Cong ${p} da gan cho tunnel khac`);
    if (!(await policy.canBind(p)) && !(wasRunning && p === t.localPort)) throw new HttpError(409, `Cong ${p} dang bi su dung tren may chu`);
    if (wasRunning) stop(t.id, 'user');
    t.localPort = p; t.kind = kind;
  }
  if (body.targetHost !== undefined || body.targetPort !== undefined || body.vmId !== undefined || body.url !== undefined) {
    if (!vm || !(vm.roles || []).includes('gateway')) throw new HttpError(400, 'VM gateway khong hop le');
    const r = resolveTarget(user, tool, { url: body.url, targetHost: body.targetHost !== undefined ? body.targetHost : t.targetHost, targetPort: body.targetPort !== undefined ? body.targetPort : t.targetPort }, vm);
    if (wasRunning) stop(t.id, 'user');
    Object.assign(t, { targetHost: r.host, targetPort: r.port, scheme: r.scheme, path: r.path, vmId: vm.id });
  }
  col.save();
  audit.log(user, 'tunnel.update', `${t.name} :${t.localPort}`);
  if (wasRunning) await start(user, t.id);
  return view(t);
}

function remove(user, id) {
  const t = getOwned(user, id);
  stop(t.id, 'user');
  const i = col.data.indexOf(t); if (i >= 0) col.data.splice(i, 1);
  col.save(); audit.log(user, 'tunnel.delete', t.name);
  events.emit('tunnel_removed', { id: t.id }, { userId: t.ownerId, alsoAdmins: true });
}

/** Kiem tra 1 dich co mo khong, di tu VM (de user thu cong private truoc khi tao tunnel) */
async function probe(user, body) {
  const vm = vms.byId(body.vmId);
  if (!vm || !(vm.roles || []).includes('gateway')) throw new HttpError(400, 'VM gateway khong hop le');
  const host = String(body.host || vm.ip).trim(), port = parseInt(body.port, 10);
  if (!HOST_RE.test(host) || !(port >= 1 && port <= 65535)) throw new HttpError(400, 'Host/cong khong hop le');
  if (user.role !== 'admin' && !user.portPolicy.allowCustomTarget && !(host === vm.ip || host === '127.0.0.1' || vms.isKnownHost(host))) throw new HttpError(403, 'Khong duoc phep kiem tra host nay');
  const t0 = Date.now();
  try {
    const conn = await ssh.getControl(vm);
    const stream = await Promise.race([ssh.forwardOut(conn, host === 'localhost' ? '127.0.0.1' : host, port), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 4000))]);
    stream.destroy();
    return { open: true, latencyMs: Date.now() - t0 };
  } catch (e) { return { open: false, error: e.message, latencyMs: Date.now() - t0 }; }
}

// Vong lap het han / idle
setInterval(() => {
  const g = settings.get().gateway, now = Date.now();
  for (const [id, rt] of runtime) {
    if (rt.expiresAt && now > rt.expiresAt) stop(id, 'expired (het thoi gian cho phep)');
    else if (g.idleMin && now - rt.lastActivity > g.idleMin * 60000) stop(id, 'idle (khong hoat dong)');
  }
}, 15000).unref();

function stopAll(reason = 'server-shutdown') { for (const id of [...runtime.keys()]) stop(id, reason); }

module.exports = { listFor, create, start, stop, update, remove, probe, stopAllForVm, cutForIncident, stopAll, view, getOwned, running: () => runtime.size, all: () => col.data };
