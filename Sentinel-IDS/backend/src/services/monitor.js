'use strict';
/** Kiem tra song/chet that (TCP + ping) va do CPU/RAM that qua SSH (/proc/stat, free). */
const { execFile } = require('child_process');
const net = require('net');
const vms = require('./vms');
const ssh = require('./ssh');
const settings = require('./settings');
const events = require('./events');
const audit = require('./audit');
const tunnels = require('./tunnels');

function ping(ip) {
  return new Promise(resolve => {
    if (!net.isIP(ip) && !/^[A-Za-z0-9.\-]+$/.test(ip)) return resolve(false);
    const args = process.platform === 'win32' ? ['-n', '1', '-w', '800', ip] : ['-c', '1', '-W', '1', ip];
    execFile('ping', args, { timeout: 3000 }, (err, out) => resolve(!err && /ttl=/i.test(out)));
  });
}

const METRIC_CMD = `a=$(head -1 /proc/stat); sleep 1; b=$(head -1 /proc/stat); echo "$a"; echo "$b"; free -m | awk '/^Mem:/{print $2" "$3}'; cut -d' ' -f1-3 /proc/loadavg; cut -d. -f1 /proc/uptime`;

function parseMetrics(out) {
  const L = out.trim().split('\n');
  if (L.length < 5) return null;
  const f = s => s.trim().split(/\s+/).slice(1, 9).map(Number);
  const a = f(L[0]), b = f(L[1]);
  const tot = x => x.reduce((p, c) => p + c, 0), idle = x => x[3] + (x[4] || 0);
  const dt = tot(b) - tot(a), di = idle(b) - idle(a);
  const cpu = dt > 0 ? Math.round((1 - di / dt) * 100) : 0;
  const [mt, mu] = L[2].trim().split(/\s+/).map(Number);
  return { cpu: Math.max(0, Math.min(100, cpu)), memTotalMb: mt, memUsedMb: mu, mem: mt ? Math.round(mu / mt * 100) : 0, load: L[3].trim(), uptime: parseInt(L[4], 10) || 0 };
}

const busy = new Set();
async function probeVm(vm) {
  if (busy.has(vm.id)) return; busy.add(vm.id);
  try {
    const before = vms.rt(vm.id);
    const t0 = Date.now();
    let lat = await ssh.tcpCheck(vm.ip, vm.healthPort || vm.sshPort || 22);
    let up = lat >= 0;
    if (!up) { up = await ping(vm.ip); lat = up ? Date.now() - t0 : -1; }
    const patch = { on: up ? 1 : 0, status: up ? 'active' : 'disconnected', latencyMs: lat };
    if (up) patch.lastSeen = Date.now();
    if (up && vm.sshUser) {
      try {
        const r = await ssh.exec(vm, METRIC_CMD, { timeout: 8000 });
        const m = r.code === 0 ? parseMetrics(r.stdout) : null;
        if (m) Object.assign(patch, m, { metricsError: '' });
      } catch (e) { patch.metricsError = e.message; patch.cpu = null; patch.mem = null; }
    } else { patch.cpu = null; patch.mem = null; }
    vms.setRt(vm.id, patch);
    if (before.on && !up) {
      ssh.dropControl(vm.id);
      tunnels.stopAllForVm(vm.id, 'vm-down (may trung gian mat ket noi)');
      audit.log(null, 'vm.down', vm.name);
      events.emit('vm_down', { id: vm.id, name: vm.name, ts: Date.now() });
    }
    if (!before.on && up && before.status !== 'unknown') audit.log(null, 'vm.up', vm.name);
  } finally { busy.delete(vm.id); }
}

let timer = null;
function loop() {
  const all = vms.all().filter(v => v.enabled);
  Promise.all(all.map(probeVm)).finally(() => {
    events.emit('agents_updated', vms.all().map(v => vms.toPublic(v)));
    timer = setTimeout(loop, settings.get().healthIntervalSec * 1000);
  });
}
const start = () => { if (!timer) { timer = setTimeout(loop, 500); } };
const checkNow = vm => probeVm(vm);

module.exports = { start, checkNow, parseMetrics };
