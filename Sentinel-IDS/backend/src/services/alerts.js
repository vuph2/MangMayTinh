'use strict';
/**
 * alerts.js — Kho CANH BAO + xu ly SU CO.
 *
 * Luong chinh (cho nguoi moi):
 *   1) Canh bao di vao qua add() (tu sensor Suricata, Wazuh, hoac API ingest).
 *   2) add() lam sach du lieu (normalize), bo canh bao trong whitelist / trung lap,
 *      CHONG TRAN (gop canh bao giong nhau xay ra lien tuc), roi luu + day realtime (SSE).
 *   3) handleIncident() phan ung: bao Telegram/Email, tu ngat tunnel, tu chan IP.
 *   4) stats()/incidents()/topIps()/topSignatures() phuc vu trang Bao cao & Thong ke.
 */
const store = require('../db/store');
const cfg = require('../config');
const settings = require('./settings');
const events = require('./events');
const telegram = require('./telegram');
const email = require('./email');          // MOI: gui canh bao qua email
const audit = require('./audit');
const whitelist = require('./whitelist');

const col = store.open('alerts', []);
// Nho "dedupKey" cua ~500 canh bao gan nhat de loai canh bao TRUNG Y HET (vd Wazuh gui lai 1 su kien)
const seen = new Set(col.data.slice(0, 500).map(a => a.dedupKey).filter(Boolean));
const hits = new Map();                    // ip -> [moc thoi gian]  (phuc vu tu dong chan IP)
const floodState = new Map();              // key(ip|type) -> { times:[], repId, lastEmit }  (phuc vu chong tran)
let hooks = { block: null, cut: null };    // ham do server.js "cam" vao (chan IP / ngat tunnel)
const setHooks = h => { hooks = { ...hooks, ...h }; };

const SEVS = ['High', 'Medium', 'Low'];
let counter = 0;

// ---- Anh xa MITRE ATT&CK: tu chu ky canh bao doan ra chien thuat/ky thuat tan cong ----
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

// Neu canh bao da co san truong mitre (vd tu Wazuh) thi giu; neu khong thi doan tu chu ky.
function resolveMitre(alert) {
  if (alert.mitre) return alert.mitre;
  const text = (alert.signature || '') + ' ' + (alert.type || '');
  for (const m of MITRE_MAP)
    if (m.re.test(text)) return { tactic: m.tactic, technique: m.technique, techniqueName: m.name };
  return null;
}

// normalize(): bien du lieu tho (co the thieu/sai kieu) thanh 1 canh bao chuan, an toan.
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

// Gui su kien SSE nhung co "ga" thoi gian: khong day qua day khi dang bi tran.
function emitThrottled(key, event, data) {
  const st = floodState.get(key); const now = Date.now();
  if (st && now - (st.lastEmit || 0) < 1000) return;      // moi khoa toi da 1 su kien / giay
  if (st) st.lastEmit = now;
  events.emit(event, data);
}

/**
 * add(raw): them 1 canh bao. Tra ve:
 *   - null  neu bi bo (whitelist hoac trung lap)
 *   - canh bao (co the la canh bao DAI DIEN da gop) neu duoc nhan.
 */
function add(raw) {
  const a = normalize(raw);

  // (1) Bo qua neu IP/SID nam trong danh sach trang
  if (whitelist.isWhitelisted(a)) return null;

  // (2) Bo qua neu trung Y HET canh bao gan day (theo dedupKey)
  if (a.dedupKey) {
    if (seen.has(a.dedupKey)) return null;
    seen.add(a.dedupKey); if (seen.size > 3000) seen.clear();
  }

  // (3) CHONG TRAN: neu cung IP + cung loai lap lai > nguong trong cua so thoi gian,
  //     ta GOP vao 1 canh bao dai dien (tang bo dem) thay vi lam ngap danh sach.
  const fc = settings.get().floodControl;
  if (fc.enabled && a.ip) {
    const key = a.ip + '|' + a.type;
    const now = a.ts;
    let st = floodState.get(key) || { times: [], repId: null, lastEmit: 0 };
    st.times = st.times.filter(t => now - t < fc.windowSec * 1000);   // chi giu moc trong cua so
    st.times.push(now);
    floodState.set(key, st);
    if (st.times.length > fc.threshold) {
      const rep = st.repId ? byId(st.repId) : null;
      if (rep) {                                    // da co dai dien -> chi tang bo dem, KHONG them dong moi
        rep.count = (rep.count || 1) + 1;
        rep.lastTs = now;
        col.save();
        emitThrottled(key, 'alert_updated', rep);
        return rep;
      }
      a.count = st.times.length;                    // canh bao dau tien vuot nguong -> thanh dai dien
      a.aggregated = true;
      st.repId = a.id;
    } else {
      st.repId = null;                              // chua tran -> dot sau se tao dai dien moi
    }
  }

  // (4) Luu vao dau danh sach (moi nhat len truoc), cat bot neu qua dai
  col.data.unshift(a);
  if (col.data.length > cfg.MAX_ALERTS) col.data.length = cfg.MAX_ALERTS;
  col.save();
  events.emit('new_alert', a);                      // day realtime xuong web
  handleIncident(a);                                // phan ung su co
  return a;
}

// handleIncident(): cac phan ung TU DONG khi co canh bao moi.
function handleIncident(a) {
  const s = settings.get();
  // Noi dung thong bao dung chung cho Telegram va Email
  const title = `[${a.sev.toUpperCase()}] ${a.type}`;
  const detail =
    `${a.signature}\n` +
    `${a.ip}${a.src_port ? ':' + a.src_port : ''} -> ${a.dst_ip}:${a.dst_port} (${a.proto})\n` +
    `Nguon: ${a.source}${a.agent ? ' / ' + a.agent : ''}` +
    (a.mitre ? `\nMITRE: ${a.mitre.tactic} / ${a.mitre.technique}` : '');

  // 1) Thong bao Telegram (neu bat va du muc do)
  if (s.telegram.enabled && settings.sevAtLeast(a.sev, s.telegram.minSeverity))
    telegram.notify('🚨 ' + title + '\n' + detail);

  // 2) Thong bao Email (neu bat va du muc do)
  if (s.email.enabled && settings.sevAtLeast(a.sev, s.email.minSeverity))
    email.notify('[Sentinel IDS] ' + title, detail);

  // 3) Tu dong ngat tunnel gateway lien quan (cat ngay tai VM)
  if (s.incident.autoCut && hooks.cut && settings.sevAtLeast(a.sev, s.incident.minSeverity)) {
    const cut = hooks.cut(a, `incident: ${a.type} (${a.ip} -> ${a.dst_ip})`);
    if (cut && cut.length) audit.log(null, 'incident.autocut', `${cut.length} tunnel bi ngat do canh bao ${a.id}`);
  }

  // 4) Tu dong chan IP khi 1 IP gay ra qua nhieu canh bao trong cua so thoi gian
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

// query(): loc danh sach canh bao theo IP / loai / muc do / trang thai / tu thoi diem.
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

// Doi trang thai xu ly cua 1 canh bao: active / resolved / false_positive
function setStatus(id, status) {
  const a = byId(id); if (!a) return null;
  if (!['active', 'resolved', 'false_positive'].includes(status)) return undefined;
  a.status = status; col.save(); events.emit('alert_updated', a); return a;
}

function clear() { col.data.length = 0; seen.clear(); floodState.clear(); col.save(); events.emit('cleared', {}); }

/**
 * stats(opts): tong hop so lieu cho trang Bao cao.
 *   - Khong truyen gi: che do mac dinh (duong thoi gian 36 moc x 5 phut = 3 gio gan nhat).
 *   - Truyen { from, to }: BAO CAO THEO KHOANG THOI GIAN — chi tinh canh bao trong [from, to]
 *     va chia duong thoi gian thanh ~48 moc deu nhau trong khoang do.
 */
function stats(opts = {}) {
  const hasRange = opts.from != null && opts.to != null;
  const from = hasRange ? Number(opts.from) : null;
  const to = hasRange ? Number(opts.to) : null;

  // Chon so moc (N) va do rong moi moc (BUCKET) cho duong thoi gian
  let N, BUCKET, base;
  if (hasRange) { N = 48; BUCKET = Math.max(1, Math.ceil((to - from) / N)); base = from; }
  else { N = 36; BUCKET = 300000; base = Date.now() - (N - 1) * BUCKET; }

  const timeline = Array.from({ length: N }, (_, i) => ({ t: base + i * BUCKET, count: 0 }));
  const byType = {}, byIp = {}, bySev = { High: 0, Medium: 0, Low: 0 }, byStatus = { active: 0, resolved: 0, false_positive: 0 };
  const bySig = {}, byMitreTactic = {}, byHour = Array.from({ length: 24 }, () => 0);  // byHour: thong ke theo gio trong ngay
  let last1h = 0, total = 0;
  const now = Date.now();

  for (const a of col.data) {
    if (hasRange && (a.ts < from || a.ts > to)) continue;             // bo canh bao ngoai khoang
    total++;
    byType[a.type] = (byType[a.type] || 0) + 1;
    byIp[a.ip] = (byIp[a.ip] || 0) + 1;
    bySev[a.sev] = (bySev[a.sev] || 0) + 1;
    byStatus[a.status] = (byStatus[a.status] || 0) + 1;
    if (a.signature) bySig[a.signature] = (bySig[a.signature] || 0) + 1;
    if (a.mitre && a.mitre.tactic) byMitreTactic[a.mitre.tactic] = (byMitreTactic[a.mitre.tactic] || 0) + 1;
    byHour[new Date(a.ts).getHours()]++;
    if (now - a.ts < 3600000) last1h++;
    const idx = Math.floor((a.ts - base) / BUCKET);                  // canh bao roi vao moc nao cua duong thoi gian
    if (idx >= 0 && idx < N) timeline[idx].count++;
  }
  return { total, last1h, byType, byIp, bySev, byStatus, bySig, byMitreTactic, byHour, timeline, from, to };
}

/** Gom su co theo IP nguon: tat ca canh bao cua mot IP, sap xep theo thoi gian (dong thoi gian). */
function incidents(ip, limit = 200) {
  const data = col.data.filter(a => a.ip === ip).slice(0, Math.min(parseInt(limit, 10) || 200, 500));
  const firstSeen = data.length ? Math.min(...data.map(a => a.ts)) : null;
  const lastSeen = data.length ? Math.max(...data.map(a => a.ts)) : null;
  const types = [...new Set(data.map(a => a.type))];
  const maxSev = data.some(a => a.sev === 'High') ? 'High' : data.some(a => a.sev === 'Medium') ? 'Medium' : 'Low';
  return { ip, total: data.length, firstSeen, lastSeen, maxSev, types, timeline: data };
}

// Top N IP tan cong (nhieu canh bao nhat). Co the gioi han theo khoang thoi gian.
function topIps(n = 10, range) {
  return Object.entries(stats(range || {}).byIp).sort((a, b) => b[1] - a[1]).slice(0, n).map(([ip, count]) => ({ ip, count }));
}

// Top N chu ky (signature) xuat hien nhieu nhat.
function topSignatures(n = 10, range) {
  return Object.entries(stats(range || {}).bySig).sort((a, b) => b[1] - a[1]).slice(0, n).map(([sig, count]) => ({ sig, count }));
}

module.exports = { add, query, byId, setStatus, clear, stats, setHooks, all: () => col.data, incidents, topIps, topSignatures };
