'use strict';
/** Quan ly luat Suricata + trien khai luat THAT xuong may sensor qua SSH (local.rules, suricata -T, restart). */
const store = require('../db/store');
const vms = require('./vms');
const ssh = require('./ssh');
const events = require('./events');
const audit = require('./audit');
const { HttpError } = require('../http');

const col = store.open('rules', []);
const RULE_RE = /^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+(tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smb|dcerpc|smtp)\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s+\(.*\)\s*$/;

function validate(raw) {
  const errors = [];
  const s = String(raw || '').trim();
  if (!s) errors.push('Luat rong');
  else {
    if (/[\r\n]/.test(s)) errors.push('Luat phai nam tren 1 dong');
    if (!RULE_RE.test(s)) errors.push('Sai cu phap co ban: <action> <proto> <src> <sport> -> <dst> <dport> (options)');
    if (!/\bsid\s*:\s*\d+\s*;/.test(s)) errors.push('Thieu sid:<so>;');
    if (!/\bmsg\s*:\s*"[^"]*"\s*;/.test(s)) errors.push('Thieu msg:"...";');
    if ((s.match(/\(/g) || []).length !== (s.match(/\)/g) || []).length) errors.push('Dau ngoac khong can bang');
  }
  return { valid: !errors.length, errors };
}
const sidOf = raw => { const m = /\bsid\s*:\s*(\d+)\s*;/.exec(raw); return m ? +m[1] : 0; };

function buildRaw(b) {
  const name = String(b.name || 'Custom rule').replace(/["\\;]/g, '');
  return `${b.action || 'alert'} ${b.proto || 'tcp'} ${b.src || 'any any'} -> ${b.dst || '$HOME_NET any'} (msg:"${name}"; sid:${b.sid}; rev:1;)`;
}

function nextSid() { const m = Math.max(1000000, ...col.data.map(r => r.sid)); return m + 1; }

function create(b, user) {
  const sid = parseInt(b.sid, 10) || nextSid();
  const raw = String(b.raw || '').trim() || buildRaw({ ...b, sid });
  const v = validate(raw); if (!v.valid) throw new HttpError(400, v.errors.join('; '));
  const realSid = sidOf(raw);
  if (col.data.some(r => r.sid === realSid)) throw new HttpError(409, `SID ${realSid} da ton tai`);
  const r = { id: col.data.length ? Math.max(...col.data.map(x => x.id)) + 1 : 1, sid: realSid, rev: 1, name: String(b.name || (/msg:"([^"]*)"/.exec(raw) || [])[1] || 'Rule').slice(0, 100), raw, enabled: b.enabled !== false, desc: String(b.desc || '').slice(0, 300), deployedAt: 0 };
  col.data.push(r); col.save(); events.emit('rules_updated', col.data); audit.log(user, 'rule.create', `sid ${r.sid}`);
  return r;
}
function update(id, b, user) {
  const r = col.data.find(x => x.id === id); if (!r) throw new HttpError(404, 'Khong tim thay luat');
  if (b.raw !== undefined) {
    const v = validate(b.raw); if (!v.valid) throw new HttpError(400, v.errors.join('; '));
    const s = sidOf(b.raw); if (col.data.some(x => x.id !== id && x.sid === s)) throw new HttpError(409, `SID ${s} da ton tai`);
    r.raw = String(b.raw).trim(); r.sid = s; r.rev++;
  }
  if (b.name !== undefined) r.name = String(b.name).slice(0, 100);
  if (b.desc !== undefined) r.desc = String(b.desc).slice(0, 300);
  if (b.enabled !== undefined) r.enabled = !!b.enabled;
  col.save(); events.emit('rules_updated', col.data); audit.log(user, 'rule.update', `sid ${r.sid}`);
  return r;
}
function remove(id, user) {
  const i = col.data.findIndex(x => x.id === id); if (i < 0) throw new HttpError(404, 'Khong tim thay luat');
  const [r] = col.data.splice(i, 1); col.save(); events.emit('rules_updated', col.data); audit.log(user, 'rule.delete', `sid ${r.sid}`);
}

/** Ghi luat xuong /etc/suricata/rules/local.rules, kiem tra suricata -T, restart; loi thi khoi phuc ban cu. */
async function deploy(vmId, user) {
  const vm = vms.byId(vmId);
  if (!vm || !(vm.roles || []).includes('sensor')) throw new HttpError(400, 'VM khong phai sensor (Suricata)');
  const text = col.data.filter(r => r.enabled).map(r => r.raw).join('\n') + '\n';
  await ssh.exec(vm, 'cat > /tmp/sentinel.local.rules', { stdin: text, timeout: 15000 });
  const script = [
    'cp -f /etc/suricata/rules/local.rules /tmp/local.rules.bak 2>/dev/null || true',
    'cp /tmp/sentinel.local.rules /etc/suricata/rules/local.rules',
    'if suricata -T -c /etc/suricata/suricata.yaml -v >/tmp/suricata-test.log 2>&1; then',
    '  systemctl restart suricata && echo DEPLOY_OK || echo DEPLOY_RESTART_FAIL',
    'else',
    '  cp -f /tmp/local.rules.bak /etc/suricata/rules/local.rules 2>/dev/null',
    '  echo DEPLOY_SYNTAX_FAIL; tail -n 15 /tmp/suricata-test.log',
    'fi'
  ].join('\n');
  const r = await ssh.exec(vm, script, { sudo: true, timeout: 120000 });
  const ok = r.stdout.includes('DEPLOY_OK');
  if (ok) { const t = Date.now(); col.data.filter(x => x.enabled).forEach(x => { x.deployedAt = t; }); col.save(); }
  audit.log(user, 'rule.deploy', `${vm.name}: ${ok ? 'OK' : 'FAIL'}`);
  return { ok, vm: vm.name, count: col.data.filter(x => x.enabled).length, output: (r.stdout + r.stderr).trim().slice(-1500) };
}

module.exports = { list: () => col.data, validate, create, update, remove, deploy };
