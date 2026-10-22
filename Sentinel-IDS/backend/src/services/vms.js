'use strict';
const net = require('net');
const store = require('../db/store');
const { encrypt, decrypt } = require('../security/crypto');
const { HttpError } = require('../http');

const col = store.open('vms', []);
const runtime = new Map(); // id -> { on, status, cpu, mem, memUsedMb, memTotalMb, load, uptime, lastSeen, latencyMs }
const uid = () => 'vm-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);

const ROLES = ['gateway', 'sensor', 'victim', 'attacker', 'siem'];

function validateHost(h) {
  if (typeof h !== 'string' || !h || h.length > 253 || !/^[A-Za-z0-9.\-:]+$/.test(h)) throw new HttpError(400, 'Dia chi IP/host khong hop le');
}
const port = (v, d) => { const n = parseInt(v, 10); return n >= 1 && n <= 65535 ? n : d; };

function normalize(body, cur = {}) {
  const v = { ...cur };
  if (body.name !== undefined) { if (!String(body.name).trim()) throw new HttpError(400, 'Thieu ten VM'); v.name = String(body.name).trim().slice(0, 48); }
  if (body.ip !== undefined) { validateHost(body.ip); v.ip = body.ip.trim(); }
  if (body.sshPort !== undefined) v.sshPort = port(body.sshPort, 22);
  if (body.sshUser !== undefined) v.sshUser = String(body.sshUser).trim().slice(0, 64);
  if (typeof body.sshPass === 'string' && body.sshPass !== '') v.sshPassEnc = encrypt(body.sshPass);
  if (typeof body.sshKey === 'string' && body.sshKey.trim() !== '') v.sshKeyEnc = encrypt(body.sshKey);
  if (typeof body.sudoPass === 'string' && body.sudoPass !== '') v.sudoPassEnc = encrypt(body.sudoPass);
  if (body.sudoMode !== undefined) v.sudoMode = ['password', 'nopasswd'].includes(body.sudoMode) ? body.sudoMode : 'password';
  if (Array.isArray(body.roles)) v.roles = body.roles.filter(r => ROLES.includes(r));
  if (body.os !== undefined) v.os = String(body.os).slice(0, 64);
  if (body.notes !== undefined) v.notes = String(body.notes).slice(0, 300);
  if (body.healthPort !== undefined) v.healthPort = body.healthPort ? port(body.healthPort, 0) : 0;
  if (body.logPath !== undefined) v.logPath = String(body.logPath).trim().slice(0, 200) || '/var/log/suricata/fast.log';
  if (body.enabled !== undefined) v.enabled = !!body.enabled;
  if (body.resetHostKey) v.hostKey = '';
  return v;
}

function create(body) {
  const v = normalize(body, { id: uid(), sshPort: 22, roles: [], enabled: true, sudoMode: 'password', logPath: '/var/log/suricata/fast.log', healthPort: 0, hostKey: '', createdAt: Date.now() });
  if (!v.name || !v.ip) throw new HttpError(400, 'Can name va ip');
  if (col.data.some(x => x.ip === v.ip && x.sshPort === v.sshPort)) throw new HttpError(409, 'VM (ip:port) da ton tai');
  col.data.push(v); col.save();
  return v;
}
function update(id, body) {
  const cur = byId(id);
  if (!cur) throw new HttpError(404, 'Khong tim thay VM');
  Object.assign(cur, normalize(body, cur)); col.save();
  return cur;
}
function remove(id) {
  const cur = byId(id);
  if (!cur) throw new HttpError(404, 'Khong tim thay VM');
  col.data.splice(col.data.indexOf(cur), 1); runtime.delete(id); col.save();
  return cur;
}

const byId = id => col.data.find(v => v.id === id);
const all = () => col.data;
const withRole = r => col.data.filter(v => v.enabled && (v.roles || []).includes(r));
const rt = id => runtime.get(id) || { on: 0, status: 'unknown', cpu: null, mem: null };
const setRt = (id, patch) => { runtime.set(id, { ...rt(id), ...patch }); return runtime.get(id); };

/** Giai ma thong tin dang nhap (chi dung noi bo, KHONG bao gio tra ve client) */
function creds(vm) {
  return {
    host: vm.ip, port: vm.sshPort || 22, username: vm.sshUser,
    password: decrypt(vm.sshPassEnc) || undefined,
    privateKey: decrypt(vm.sshKeyEnc) || undefined
  };
}
const sudoPassword = vm => decrypt(vm.sudoPassEnc) || decrypt(vm.sshPassEnc) || '';

/** Ban an toan cho client. Admin thay them cau hinh (khong bao gio co mat khau). */
function toPublic(vm, admin = false) {
  const r = rt(vm.id);
  const base = {
    id: vm.id, name: vm.name, ip: vm.ip, roles: vm.roles || [], os: vm.os || '', notes: vm.notes || '',
    enabled: vm.enabled, on: r.on, status: r.status, cpu: r.cpu, mem: r.mem,
    memUsedMb: r.memUsedMb, memTotalMb: r.memTotalMb, load: r.load, uptime: r.uptime, lastSeen: r.lastSeen, latencyMs: r.latencyMs,
    gateway: (vm.roles || []).includes('gateway')
  };
  if (admin) Object.assign(base, {
    sshPort: vm.sshPort, sshUser: vm.sshUser, healthPort: vm.healthPort, logPath: vm.logPath, sudoMode: vm.sudoMode,
    hasSshPass: !!vm.sshPassEnc, hasSshKey: !!vm.sshKeyEnc, hasSudoPass: !!vm.sudoPassEnc, hostKey: vm.hostKey || '', createdAt: vm.createdAt
  });
  return base;
}

const isKnownHost = h => col.data.some(v => v.ip === h);

module.exports = { create, update, remove, byId, all, withRole, rt, setRt, creds, sudoPassword, toPublic, isKnownHost, ROLES, save: () => col.save() };
