'use strict';
/** Doc log Suricata (fast.log) THAT theo thoi gian thuc qua SSH tu moi VM co vai tro "sensor". */
const vms = require('./vms');
const ssh = require('./ssh');
const alerts = require('./alerts');
const { shq } = ssh;

const streams = new Map(); // vmId -> { conn, stopping }
const state = new Map();   // vmId -> { status, error, lines, lastLine }

const RE = /^(\d\d)\/(\d\d)\/(\d{4})-(\d\d):(\d\d):(\d\d)\S*\s+\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.*?)\s*\[\*\*\](?:\s*\[Classification:\s*(.*?)\])?\s*\[Priority:\s*(\d+)\]\s*\{(.*?)\}\s*([0-9a-fA-F.:]+?):?(\d*)\s*->\s*([0-9a-fA-F.:]+?):?(\d*)\s*$/;

function classify(sig, cls) {
  const s = sig.toLowerCase();
  if (s.includes('nmap') || s.includes('scan')) return ['Port scan', 'nmap'];
  if (s.includes('ssh') || s.includes('hydra') || s.includes('brute')) return ['SSH brute force', 'Hydra'];
  if (s.includes('sql')) return ['SQL injection', 'sqlmap'];
  if (s.includes('flood') || s.includes('dos')) return ['SYN flood', 'hping3'];
  if (s.includes('passwd') || s.includes('/etc/')) return ['Sensitive File Access', 'curl'];
  return [cls || 'Intrusion Attempt', 'Suricata'];
}

function parseLine(line, vm) {
  const m = RE.exec(line.trim());
  if (!m) return null;
  const prio = +m[12];
  const [type, tool] = classify(m[10], m[11]);
  const ts = Math.min(new Date(+m[3], +m[1] - 1, +m[2], +m[4], +m[5], +m[6]).getTime(), Date.now());
  return {
    ts, ip: m[14], src_port: +m[15] || 0, dst_ip: m[16], dst_port: +m[17] || 0, proto: m[13],
    type, tool, sev: prio === 1 ? 'High' : prio === 2 ? 'Medium' : 'Low', sid: +m[8], signature: m[10].trim(),
    payload: line.trim(), source: 'suricata', agent: vm.name, dedupKey: vm.id + '|' + line.trim()
  };
}

async function startStream(vm, useSudo = false) {
  const st = state.get(vm.id) || { lines: 0 };
  state.set(vm.id, { ...st, status: 'connecting', error: '' });
  let conn;
  try { conn = await ssh.connect(vm); } catch (e) { state.set(vm.id, { ...st, status: 'error', error: e.message }); return; }
  const rec = { conn, stopping: false };
  streams.set(vm.id, rec);
  const done = () => { if (streams.get(vm.id) === rec) { streams.delete(vm.id); const s = state.get(vm.id) || {}; if (s.status !== 'error') state.set(vm.id, { ...s, status: 'disconnected' }); } };
  conn.on('close', done); conn.on('error', done);
  const tail = `tail -F -n 30 ${shq(vm.logPath || '/var/log/suricata/fast.log')}`;
  const cmd = useSudo ? (vm.sudoMode === 'nopasswd' ? `sudo -n ${tail}` : `sudo -S -p '' ${tail}`) : tail;
  conn.exec(cmd, (err, stream) => {
    if (err) { state.set(vm.id, { ...st, status: 'error', error: err.message }); conn.end(); return; }
    if (useSudo && vm.sudoMode !== 'nopasswd') stream.write(vms.sudoPassword(vm) + '\n');
    state.set(vm.id, { ...(state.get(vm.id) || {}), status: 'streaming', error: '' });
    let buf = '';
    stream.on('data', d => {
      buf += d.toString(); const lines = buf.split('\n'); buf = lines.pop();
      for (const line of lines) {
        if (!line.includes('[**]')) continue;
        const a = parseLine(line, vm); if (!a) continue;
        const s = state.get(vm.id) || {}; s.lines = (s.lines || 0) + 1; s.lastLine = Date.now(); state.set(vm.id, s);
        alerts.add(a);
      }
    });
    let errBuf = '';
    stream.stderr.on('data', d => {
      errBuf += d.toString();
      if (!useSudo && /permission denied/i.test(errBuf)) { rec.stopping = true; conn.end(); setTimeout(() => startStream(vm, true), 500); }
      else if (/no such file/i.test(errBuf)) state.set(vm.id, { ...(state.get(vm.id) || {}), status: 'error', error: 'Khong thay file log: ' + vm.logPath });
    });
    stream.on('close', () => conn.end());
  });
}

/** Dong bo: mo luong cho sensor dang online, dong luong cua VM bi tat/xoa */
function sync() {
  const want = new Set();
  for (const vm of vms.withRole('sensor')) {
    want.add(vm.id);
    if (!streams.has(vm.id) && vms.rt(vm.id).on && vm.sshUser && !(state.get(vm.id) || {}).connecting) {
      streams.set(vm.id, { conn: null, stopping: false }); // giu cho trong luc ket noi
      startStream(vm).catch(() => {}).finally(() => { const r = streams.get(vm.id); if (r && !r.conn) streams.delete(vm.id); });
    }
  }
  for (const [id, rec] of streams) if (!want.has(id)) { try { rec.conn && rec.conn.end(); } catch {} streams.delete(id); state.delete(id); }
}

const start = () => setInterval(sync, 5000).unref();
const status = () => Object.fromEntries([...state.entries()]);

module.exports = { start, sync, status, parseLine };
