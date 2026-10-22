'use strict';
const store = require('../db/store');
const { randomToken, encrypt, decrypt } = require('../security/crypto');

const defaults = () => ({
  ingestKey: randomToken(24),
  telegram: { enabled: false, tokenEnc: '', chatId: '', minSeverity: 'High' },
  wazuh: { enabled: false, host: '', apiPort: 55000, apiUser: 'wazuh', apiPassEnc: '', indexerPort: 9200, indexerUser: 'admin', indexerPassEnc: '', verifyTLS: false, pollSec: 15 },
  autoBlock: { enabled: false, threshold: 5, windowSec: 60, durationSec: 3600 },
  incident: { autoCut: true, minSeverity: 'High', notifyTelegram: true },
  gateway: { maxLifetimeMin: 60, idleMin: 0, maxTunnelsPerUser: 5 },
  healthIntervalSec: 5
});

const col = store.open('settings', defaults());
// Bo sung khoa moi khi nang cap phien ban
(function migrate() {
  const d = defaults();
  for (const k of Object.keys(d)) {
    if (col.data[k] === undefined) col.data[k] = d[k];
    else if (typeof d[k] === 'object') col.data[k] = { ...d[k], ...col.data[k] };
  }
  col.save(true);
})();

const get = () => col.data;
const SEV = { Low: 1, Medium: 2, High: 3 };
const sevAtLeast = (sev, min) => (SEV[sev] || 0) >= (SEV[min] || 3);

/** Tra ve ban an bi mat de gui cho Frontend (token/password chi hien co / chua co). */
function masked() {
  const s = JSON.parse(JSON.stringify(col.data));
  s.telegram.hasToken = !!s.telegram.tokenEnc; delete s.telegram.tokenEnc;
  s.wazuh.hasApiPass = !!s.wazuh.apiPassEnc; delete s.wazuh.apiPassEnc;
  s.wazuh.hasIndexerPass = !!s.wazuh.indexerPassEnc; delete s.wazuh.indexerPassEnc;
  return s;
}

const num = (v, min, max, dflt) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : dflt; };

function update(body) {
  const s = col.data;
  if (body.telegram) {
    const t = body.telegram;
    if (t.enabled !== undefined) s.telegram.enabled = !!t.enabled;
    if (typeof t.chatId === 'string') s.telegram.chatId = t.chatId.trim().slice(0, 64);
    if (['Low', 'Medium', 'High'].includes(t.minSeverity)) s.telegram.minSeverity = t.minSeverity;
    if (typeof t.token === 'string' && t.token) s.telegram.tokenEnc = encrypt(t.token.trim());
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
  if (body.healthIntervalSec !== undefined) s.healthIntervalSec = num(body.healthIntervalSec, 2, 300, 5);
  col.save();
  return masked();
}

function regenerateIngestKey() { col.data.ingestKey = randomToken(24); col.save(); return col.data.ingestKey; }

module.exports = { get, masked, update, sevAtLeast, regenerateIngestKey, decrypt };
