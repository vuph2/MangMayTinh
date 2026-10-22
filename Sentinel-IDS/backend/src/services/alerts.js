'use strict';
/** Kho canh bao + xu ly su co (thong bao Telegram, tu dong chan IP, tu dong ngat tunnel). */
const store = require('../db/store');
const cfg = require('../config');
const settings = require('./settings');
const events = require('./events');
const telegram = require('./telegram');
const audit = require('./audit');

const col = store.open('alerts', []);
const seen = new Set(col.data.slice(0, 500).map(a => a.dedupKey).filter(Boolean));
const hits = new Map(); // ip -> [timestamps] cho auto-block
let hooks = { block: null, cut: null };
const setHooks = h => { hooks = { ...hooks, ...h }; };

const SEVS = ['High', 'Medium', 'Low'];
let counter = 0;

function normalize(d) {
  const ts = Number(d.ts) || Date.now();
  return {
    id: d.id || `ALT-${ts.toString(36)}-${(++counter).toString(36)}`,
    ts, ip: String(d.ip || '').slice(0, 64), src_port: +d.src_port || 0,
    dst_ip: String(d.dst_ip || '').slice(0, 64), dst_port: +d.dst_port || 0,
    proto: String(d.proto || 'TCP').slice(0, 12), type: String(d.type || 'Intrusion Attempt').slice(0, 80),
    tool: String(d.tool || 'Suricata').slice(0, 40), sev: SEVS.includes(d.sev) ? d.sev : 'Medium',
    sid: +d.sid || 0, signature: String(d.signature || d.type || '').slice(0, 300),
    payload: String(d.payload || '').slice(0, 2000), status: 'active',
    source: String(d.source || 'ingest').slice(0, 20), agent: String(d.agent || '').slice(0, 64),
    dedupKey: d.dedupKey || null
  };
}

/** Them canh bao. Tra ve null neu trung. */
function add(raw) {
  const a = normalize(raw);
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
    telegram.notify(`🚨 [${a.sev.toUpperCase()}] ${a.type}\n${a.signature}\n${a.ip}${a.src_port ? ':' + a.src_port : ''} → ${a.dst_ip}:${a.dst_port} (${a.proto})\nNguon: ${a.source}${a.agent ? ' / ' + a.agent : ''}`);
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
  let last1h = 0;
  for (const a of col.data) {
    byType[a.type] = (byType[a.type] || 0) + 1;
    byIp[a.ip] = (byIp[a.ip] || 0) + 1;
    bySev[a.sev]++; byStatus[a.status] = (byStatus[a.status] || 0) + 1;
    const age = now - a.ts;
    if (age < 3600000) last1h++;
    if (age >= 0 && age < N * BUCKET) timeline[N - 1 - Math.floor(age / BUCKET)].count++;
  }
  return { total: col.data.length, last1h, byType, byIp, bySev, byStatus, timeline };
}

module.exports = { add, query, byId, setStatus, clear, stats, setHooks, all: () => col.data };
