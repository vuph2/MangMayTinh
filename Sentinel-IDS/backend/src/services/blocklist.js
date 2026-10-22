'use strict';
/** Active Response THAT: SSH vao may duoc bao ve (role "victim") chay iptables DROP. */
const os = require('os');
const net = require('net');
const store = require('../db/store');
const vms = require('./vms');
const ssh = require('./ssh');
const events = require('./events');
const audit = require('./audit');
const { HttpError } = require('../http');

const col = store.open('blocklist', {});

function ownAddresses() {
  const set = new Set(['127.0.0.1', '::1', '0.0.0.0']);
  for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) set.add(i.address);
  for (const v of vms.all()) if ((v.roles || []).includes('gateway')) set.add(v.ip);
  return set;
}

const enforcers = () => vms.all().filter(v => v.enabled && (v.roles || []).includes('victim'));

async function applyOn(vm, ip, add) {
  const cmd = add
    ? `iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || iptables -I INPUT -s ${ip} -j DROP`
    : `while iptables -C INPUT -s ${ip} -j DROP 2>/dev/null; do iptables -D INPUT -s ${ip} -j DROP; done; true`;
  try {
    const r = await ssh.exec(vm, cmd, { sudo: true, timeout: 15000 });
    return { vmId: vm.id, vm: vm.name, ok: r.code === 0, error: r.code === 0 ? '' : (r.stderr || '').trim().slice(0, 200) };
  } catch (e) { return { vmId: vm.id, vm: vm.name, ok: false, error: e.message }; }
}

async function block(ip, { reason, duration = 3600, source = 'manual', ruleSid = null } = {}, user = null) {
  if (!net.isIP(ip)) throw new HttpError(400, 'IP khong hop le');
  if (ownAddresses().has(ip)) throw new HttpError(400, 'Khong the chan IP cua chinh he thong/may trung gian (se tu cat ket noi).');
  const targets = enforcers();
  const results = await Promise.all(targets.map(v => applyOn(v, ip, true)));
  const okN = results.filter(r => r.ok).length;
  const entry = {
    ip, reason: String(reason || 'Chan thu cong tu Sentinel IDS').slice(0, 200), blockedAt: Date.now(),
    duration: Math.max(0, parseInt(duration, 10) || 0), source, ruleSid, results,
    status: !targets.length ? 'no-enforcer' : okN === targets.length ? 'applied' : okN ? 'partial' : 'failed'
  };
  col.data[ip] = entry; col.save();
  events.emit('ip_blocked', entry);
  audit.log(user, 'blocklist.add', `${ip} (${entry.status}) ${entry.reason}`);
  return entry;
}

async function unblock(ip, user = null) {
  const entry = col.data[ip];
  if (!entry) throw new HttpError(404, 'IP khong co trong danh sach chan');
  const results = await Promise.all(enforcers().map(v => applyOn(v, ip, false)));
  delete col.data[ip]; col.save();
  events.emit('ip_unblocked', { ip });
  audit.log(user, 'blocklist.remove', ip);
  return { ip, results };
}

async function reapply(ip, user) {
  const e = col.data[ip]; if (!e) throw new HttpError(404, 'IP khong co trong danh sach chan');
  return block(ip, { reason: e.reason, duration: e.duration, source: e.source, ruleSid: e.ruleSid }, user);
}

const list = () => Object.values(col.data).sort((a, b) => b.blockedAt - a.blockedAt);
const isBlocked = ip => !!col.data[ip];

setInterval(() => {
  for (const e of Object.values(col.data)) if (e.duration && Date.now() > e.blockedAt + e.duration * 1000) unblock(e.ip).catch(() => {});
}, 30000).unref();

module.exports = { block, unblock, reapply, list, isBlocked, enforcers };
