'use strict';
/**
 * settings.js — Noi luu TOAN BO cau hinh he thong (1 file settings.json).
 *
 * Giai thich cho nguoi moi:
 *  - "settings" la mot object JSON duy nhat, duoc luu xuong file qua lop store.
 *  - Nhung gi la bi mat (token Telegram, mat khau Wazuh, mat khau email SMTP) duoc
 *    MA HOA truoc khi luu (ham encrypt), va khi gui ra Frontend thi bi che di (ham masked).
 *  - Khi them khoa cau hinh moi o ban nang cap, ham migrate() tu dien gia tri mac dinh,
 *    nho vay file settings.json cu van chay duoc ma khong loi.
 */
const store = require('../db/store');
const { randomToken, encrypt, decrypt } = require('../security/crypto');

// Gia tri mac dinh cho toan bo cau hinh. Moi lan khoi dong neu thieu khoa nao se lay o day.
const defaults = () => ({
  ingestKey: randomToken(24),                 // khoa de API ngoai gui canh bao vao (X-Ingest-Key)
  telegram: { enabled: false, tokenEnc: '', chatId: '', minSeverity: 'High' },
  // MOI: cau hinh gui Email (SMTP). secure=true dung cong 465 (TLS ngay), false dung 587 (STARTTLS)
  email: { enabled: false, host: '', port: 587, secure: false, user: '', passEnc: '', from: '', to: '', minSeverity: 'High' },
  wazuh: { enabled: false, host: '', apiPort: 55000, apiUser: 'wazuh', apiPassEnc: '', indexerPort: 9200, indexerUser: 'admin', indexerPassEnc: '', verifyTLS: false, pollSec: 15 },
  autoBlock: { enabled: false, threshold: 5, windowSec: 60, durationSec: 3600 },
  // MOI: chong tran canh bao — gop cac canh bao giong nhau (cung IP + loai) trong 1 cua so thoi gian
  floodControl: { enabled: true, windowSec: 30, threshold: 5 },
  incident: { autoCut: true, minSeverity: 'High', notifyTelegram: true },
  gateway: { maxLifetimeMin: 60, idleMin: 0, maxTunnelsPerUser: 5 },
  security: { allowRegistration: true },
  healthIntervalSec: 5
});

// Mo (hoac tao) file settings.json
const col = store.open('settings', defaults());

// migrate(): bo sung cac khoa con THIEU khi nang cap phien ban (giu nguyen gia tri cu).
(function migrate() {
  const d = defaults();
  for (const k of Object.keys(d)) {
    if (col.data[k] === undefined) col.data[k] = d[k];                 // khoa moi hoan toan -> dien mac dinh
    else if (typeof d[k] === 'object' && !Array.isArray(d[k]))
      col.data[k] = { ...d[k], ...col.data[k] };                      // object -> tron mac dinh voi gia tri cu
  }
  col.save(true);
})();

const get = () => col.data;                       // lay toan bo cau hinh (dang object that, co ca ...Enc)

// So sanh muc do nghiem trong: canh bao >= nguong moi gui thong bao
const SEV = { Low: 1, Medium: 2, High: 3 };
const sevAtLeast = (sev, min) => (SEV[sev] || 0) >= (SEV[min] || 3);

/** masked(): tra ve ban SAO da che bi mat (token/password) de gui an toan ra Frontend. */
function masked() {
  const s = JSON.parse(JSON.stringify(col.data));                     // sao chep sau de khong dung vao ban that
  s.telegram.hasToken = !!s.telegram.tokenEnc; delete s.telegram.tokenEnc;
  s.email.hasPass = !!s.email.passEnc; delete s.email.passEnc;        // chi bao "da co mat khau hay chua"
  s.wazuh.hasApiPass = !!s.wazuh.apiPassEnc; delete s.wazuh.apiPassEnc;
  s.wazuh.hasIndexerPass = !!s.wazuh.indexerPassEnc; delete s.wazuh.indexerPassEnc;
  return s;
}

// Lam sach so nguyen trong khoang [min, max], neu khong hop le thi tra mac dinh
const num = (v, min, max, dflt) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : dflt; };

/** update(body): cap nhat tung nhom cau hinh. Chi nhan dung kieu/khoa cho phep (chong rac). */
function update(body) {
  const s = col.data;
  if (body.telegram) {
    const t = body.telegram;
    if (t.enabled !== undefined) s.telegram.enabled = !!t.enabled;
    if (typeof t.chatId === 'string') s.telegram.chatId = t.chatId.trim().slice(0, 64);
    if (['Low', 'Medium', 'High'].includes(t.minSeverity)) s.telegram.minSeverity = t.minSeverity;
    if (typeof t.token === 'string' && t.token) s.telegram.tokenEnc = encrypt(t.token.trim()); // chi ghi de khi co token moi
  }
  if (body.email) {                                                   // MOI: cau hinh email SMTP
    const e = body.email;
    if (e.enabled !== undefined) s.email.enabled = !!e.enabled;
    if (typeof e.host === 'string') s.email.host = e.host.trim().slice(0, 253);
    if (e.port !== undefined) s.email.port = num(e.port, 1, 65535, 587);
    if (e.secure !== undefined) s.email.secure = !!e.secure;
    if (typeof e.user === 'string') s.email.user = e.user.trim().slice(0, 190);
    if (typeof e.from === 'string') s.email.from = e.from.trim().slice(0, 190);
    if (typeof e.to === 'string') s.email.to = e.to.trim().slice(0, 400);   // co the nhieu dia chi, cach nhau dau phay
    if (['Low', 'Medium', 'High'].includes(e.minSeverity)) s.email.minSeverity = e.minSeverity;
    if (typeof e.pass === 'string' && e.pass) s.email.passEnc = encrypt(e.pass);  // chi ma hoa/ghi khi co mat khau moi
  }
  if (body.wazuh) {
    const w = body.wazuh;
    if (w.enabled !== undefined) s.wazuh.enabled = !!w.enabled;
    if (typeof w.host === 'string') s.wazuh.host = w.host.trim().slice(0, 253);
    if (w.apiPort !== undefined) s.wazuh.apiPort = num(w.apiPort, 1, 65535, 55000);
    if (w.indexerPort !== undefined) s.wazuh.indexerPort = num(w.indexerPort, 1, 65535, 9200);
    if (typeof w.apiUser === 'string') s.wazuh.apiUser = w.apiUser.trim();
    if (typeof w.indexerUser === 'string') s.wazuh.indexerUser = w.indexerUser.trim();
    if (typeof w.apiPass === 'string' && w.apiPass) s.wazuh.apiPassEnc = encrypt(w.apiPass);
    if (typeof w.indexerPass === 'string' && w.indexerPass) s.wazuh.indexerPassEnc = encrypt(w.indexerPass);
    if (w.verifyTLS !== undefined) s.wazuh.verifyTLS = !!w.verifyTLS;
    if (w.pollSec !== undefined) s.wazuh.pollSec = num(w.pollSec, 5, 3600, 15);
  }
  if (body.autoBlock) {
    const a = body.autoBlock;
    if (a.enabled !== undefined) s.autoBlock.enabled = !!a.enabled;
    if (a.threshold !== undefined) s.autoBlock.threshold = num(a.threshold, 1, 1000, 5);
    if (a.windowSec !== undefined) s.autoBlock.windowSec = num(a.windowSec, 5, 86400, 60);
    if (a.durationSec !== undefined) s.autoBlock.durationSec = num(a.durationSec, 0, 31536000, 3600);
  }
  if (body.floodControl) {                                            // MOI: nguong chong tran canh bao
    const f = body.floodControl;
    if (f.enabled !== undefined) s.floodControl.enabled = !!f.enabled;
    if (f.windowSec !== undefined) s.floodControl.windowSec = num(f.windowSec, 1, 3600, 30);
    if (f.threshold !== undefined) s.floodControl.threshold = num(f.threshold, 2, 10000, 5);
  }
  if (body.incident) {
    const i = body.incident;
    if (i.autoCut !== undefined) s.incident.autoCut = !!i.autoCut;
    if (['Low', 'Medium', 'High'].includes(i.minSeverity)) s.incident.minSeverity = i.minSeverity;
    if (i.notifyTelegram !== undefined) s.incident.notifyTelegram = !!i.notifyTelegram;
  }
  if (body.gateway) {
    const g = body.gateway;
    if (g.maxLifetimeMin !== undefined) s.gateway.maxLifetimeMin = num(g.maxLifetimeMin, 0, 10080, 60);
    if (g.idleMin !== undefined) s.gateway.idleMin = num(g.idleMin, 0, 1440, 0);
    if (g.maxTunnelsPerUser !== undefined) s.gateway.maxTunnelsPerUser = num(g.maxTunnelsPerUser, 1, 100, 5);
  }
  if (body.security && body.security.allowRegistration !== undefined) s.security.allowRegistration = !!body.security.allowRegistration;
  if (body.healthIntervalSec !== undefined) s.healthIntervalSec = num(body.healthIntervalSec, 2, 300, 5);
  col.save();
  return masked();
}

// Tao lai khoa ingest moi (khi nghi bi lo)
function regenerateIngestKey() { col.data.ingestKey = randomToken(24); col.save(); return col.data.ingestKey; }

module.exports = { get, masked, update, sevAtLeast, regenerateIngestKey, decrypt };
