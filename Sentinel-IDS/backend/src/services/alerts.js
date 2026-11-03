'use strict';
/** Kho canh bao + xu ly su co (thong bao Telegram, tu dong chan IP, tu dong ngat tunnel). */
const store = require('../db/store');
const cfg = require('../config');
const settings = require('./settings');
const events = require('./events');
const telegram = require('./telegram');
const audit = require('./audit');
const whitelist = require('./whitelist');

const col = store.open('alerts', []);
const seen = new Set(col.data.slice(0, 500).map(a => a.dedupKey).filter(Boolean));
const hits = new Map(); // ip -> [timestamps] cho auto-block
let hooks = { block: null, cut: null };
const setHooks = h => { hooks = { ...hooks, ...h }; };

const SEVS = ['High', 'Medium', 'Low'];
let counter = 0;

// ---- MITRE ATT&CK mapping ----
const MITRE_MAP = [
  { re: /nmap|port.?scan|scan/i,           tactic: 'Reconnaissance',        technique: 'T1046', name: 'Network Service Scanning' },
  { re: /ssh.?brute|hydra|brute.?force/i,  tactic: 'Credential Access',     technique: 'T1110', name: 'Brute Force' },
  { re: /sql.?inject|sqli/i,               tactic: 'Initial Access',        technique: 'T1190', name: 'Exploit Public-Facing Application' },
  { re: /flood|dos|syn.?flood|ddos/i,      tactic: 'Impact',                technique: 'T1498', name: 'Network Denial of Service' },
  { re: /\/etc\/passwd|sensitive.*file|lfi|file.?inclus/i, tactic: 'Discovery', technique: 'T1083', name: 'File and Directory Discovery' },
  { re: /xss|cross.?site/i,                tactic: 'Initial Access',        technique: 'T1059.007', name: 'JavaScript' },
  { re: /reverse.?shell|backdoor|bind.?shell/i, tactic: 'Execution',       technique: 'T1059', name: 'Command and Scripting Interpreter' },
  { re: /privilege.?escal|sudo|suid/i,     tactic: 'Privilege Escalation',  technique: 'T1548', name: 'Abuse Elevation Control Mechanism' },
  { re: /lateral|pass.?the.?hash|pth/i,    tactic: 'Lateral Movement',      technique: 'T1550', name: 'Use Alternate Authentication Material' },
];

function resolveMitre(alert) {
  // Wazuh co san cac truong rule.mitre
  if (alert.mitre) return alert.mitre;
  const text = (alert.signature || '') + ' ' + (alert.type || '');
  for (const m of MITRE_MAP) {
    if (m.re.test(text)) return { tactic: m.tactic, technique: m.technique, techniqueName: m.name };
  }
  return null;
}

function normalize(d) {
  const ts = Number(d.ts) || Date.now();
  const mitre = resolveMitre(d);
  return {
    id: d.id || `ALT-${ts.toString(36)}-${(++counter).toString(36)}`,
    ts, ip: String(d.ip || '').slice(0, 64), src_port: +d.src_port || 0,
    dst_ip: String(d.dst_ip || '').slice(0, 64), dst_port: +d.dst_port || 0,
    proto: String(d.proto || 'TCP').slice(0, 12), type: String(d.type || 'Intrusion Attempt').slice(0, 80),
    tool: String(d.tool || 'Suricata').slice(0, 40), sev: SEVS.includes(d.sev) ? d.sev : 'Medium',
    sid: +d.sid || 0, signature: String(d.signature || d.type || '').slice(0, 300),
    payload: String(d.payload || '').slice(0, 2000), status: 'active',
    source: String(d.source || 'ingest').slice(0, 20), agent: String(d.agent || '').slice(0, 64),
    dedupKey: d.dedupKey || null,
    mitre: mitre || undefined
  };
}

/** Them canh bao. Tra ve null neu trung hoac nam trong whitelist. */
function add(raw) {
  const a = normalize(raw);
  // Kiem tra danh sach trang
  if (whitelist.isWhitelisted(a)) return null;
  if (a.dedupKey) { if (seen.has(a.dedupKey)) return null; seen.add(a.dedupKey); if (seen.size > 3000) seen.clear(); }
  col.data.unshift(a);
  if (col.data.length > cfg.MAX_ALERTS) col.data.length = cfg.MAX_ALERTS;
  col.save();
  events.emit('new_alert', a);
  handleIncident(a);
  return a;
}

function handleIncident(a) {
  const s = settings.get();
  // 1. Telegram that
  if (s.telegram.enabled && settings.sevAtLeast(a.sev, s.telegram.minSeverity)) {
    telegram.notify(`🚨 [${a.sev.toUpperCase()}] ${a.type}\n${a.signature}\n${a.ip}${a.src_port ? ':' + a.src_port : ''} → ${a.dst_ip}:${a.dst_port} (${a.proto})\nNguon: ${a.source}${a.agent ? ' / ' + a.agent : ''}${a.mitre ? '\nMITRE: ' + a.mitre.tactic + ' / ' + a.mitre.technique : ''}`);
  }
  // 2. Tu dong ngat tunnel gateway lien quan (cat tai VM)
  if (s.incident.autoCut && hooks.cut && settings.sevAtLeast(a.sev, s.incident.minSeverity)) {
    const cut = hooks.cut(a, `incident: ${a.type} (${a.ip} -> ${a.dst_ip})`);
    if (cut && cut.length) audit.log(null, 'incident.autocut', `${cut.length} tunnel bi ngat do canh bao ${a.id}`);
  }
  // 3. Tu dong chan IP khi lap lai nhieu lan
  const ab = s.autoBlock;
  if (ab.enabled && hooks.block && a.ip) {
    const arr = (hits.get(a.ip) || []).filter(t => Date.now() - t < ab.windowSec * 1000);
    arr.push(Date.now()); hits.set(a.ip, arr);
    if (arr.length >= ab.threshold && settings.sevAtLeast(a.sev, 'Medium')) {
      hits.delete(a.ip);
      hooks.block(a.ip, { reason: `Auto-block: ${arr.length} canh bao/${ab.windowSec}s (${a.type})`, duration: ab.durationSec, source: 'auto', ruleSid: a.sid }).catch(() => {});
    }
  }
}

function query({ ip, type, sev, status, limit = 200, since } = {}) {
  let r = col.data;
  if (ip) r = r.filter(a => a.ip.includes(ip) || a.dst_ip.includes(ip));
  if (type) r = r.filter(a => a.type === type);
  if (sev) r = r.filter(a => a.sev === sev);
  if (status) r = r.filter(a => a.status === status);
  if (since) r = r.filter(a => a.ts >= since);
  return { total: col.data.length, matched: r.length, data: r.slice(0, Math.min(parseInt(limit, 10) || 200, 1000)) };
}
const byId = id => col.data.find(a => a.id === id);
function setStatus(id, status) {
  const a = byId(id); if (!a) return null;
  if (!['active', 'resolved', 'false_positive'].includes(status)) return undefined;
  a.status = status; col.save(); events.emit('alert_updated', a); return a;
}
function clear() { col.data.length = 0; seen.clear(); col.save(); events.emit('cleared', {}); }

function stats() {
  const now = Date.now(), BUCKET = 300000, N = 36;
  const timeline = Array.from({ length: N }, (_, i) => ({ t: now - (N - 1 - i) * BUCKET, count: 0 }));
  const byType = {}, byIp = {}, bySev = { High: 0, Medium: 0, Low: 0 }, byStatus = { active: 0, resolved: 0, false_positive: 0 };
  const bySig = {}, byMitreTactic = {};
  let last1h = 0;
  for (const a of col.data) {
    byType[a.type] = (byType[a.type] || 0) + 1;
    byIp[a.ip] = (byIp[a.ip] || 0) + 1;
    bySev[a.sev]++; byStatus[a.status] = (byStatus[a.status] || 0) + 1;
    if (a.signature) bySig[a.signature] = (bySig[a.signature] || 0) + 1;
    if (a.mitre && a.mitre.tactic) byMitreTactic[a.mitre.tactic] = (byMitreTactic[a.mitre.tactic] || 0) + 1;
    const age = now - a.ts;
    if (age < 3600000) last1h++;
    if (age >= 0 && age < N * BUCKET) timeline[N - 1 - Math.floor(age / BUCKET)].count++;
  }
  return { total: col.data.length, last1h, byType, byIp, bySev, byStatus, bySig, byMitreTactic, timeline };
}

/** Gom su co theo IP nguon: tat ca canh bao cua mot IP, sap xep theo thoi gian. */
function incidents(ip, limit = 200) {
  const data = col.data.filter(a => a.ip === ip).slice(0, Math.min(parseInt(limit, 10) || 200, 500));
  const firstSeen = data.length ? Math.min(...data.map(a => a.ts)) : null;
  const lastSeen = data.length ? Math.max(...data.map(a => a.ts)) : null;
  const types = [...new Set(data.map(a => a.type))];
  const maxSev = data.some(a => a.sev === 'High') ? 'High' : data.some(a => a.sev === 'Medium') ? 'Medium' : 'Low';
  return { ip, total: data.length, firstSeen, lastSeen, maxSev, types, timeline: data };
}

/** Top N IP tan cong: sap xep theo so canh bao giam dan. */
function topIps(n = 10) {
  const st = stats();
  return Object.entries(st.byIp).sort((a, b) => b[1] - a[1]).slice(0, n).map(([ip, count]) => ({ ip, count }));
}

/** Top N chu ky (signature). */
function topSignatures(n = 10) {
  const st = stats();
  return Object.entries(st.bySig).sort((a, b) => b[1] - a[1]).slice(0, n).map(([sig, count]) => ({ sig, count }));
}

module.exports = { add, query, byId, setStatus, clear, stats, setHooks, all: () => col.data, incidents, topIps, topSignatures };
