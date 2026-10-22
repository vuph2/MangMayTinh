'use strict';
/** Client Wazuh THAT: API (cong 55000, JWT) + Indexer/OpenSearch (cong 9200, truy van wazuh-alerts-*). */
const https = require('https');
const settings = require('./settings');
const alerts = require('./alerts');
const store = require('../db/store');
const { HttpError } = require('../http');
const { decrypt } = require('../security/crypto');

const st = store.open('wazuh_state', { lastTs: '' });
let token = { value: '', exp: 0 };

function req({ method = 'GET', port, path, headers = {}, body }) {
  const w = settings.get().wazuh;
  if (!w.host) throw new HttpError(400, 'Chua cau hinh dia chi Wazuh (Cai dat he thong)');
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = https.request({
      host: w.host, port, path, method, rejectUnauthorized: !!w.verifyTLS, timeout: 10000,
      headers: { ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...headers }
    }, res => {
      let out = ''; res.on('data', c => { out += c; });
      res.on('end', () => {
        let json = null; try { json = JSON.parse(out); } catch {}
        resolve({ status: res.statusCode, json, text: out });
      });
    });
    r.on('timeout', () => r.destroy(new Error('Wazuh timeout')));
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

async function apiToken(force = false) {
  const w = settings.get().wazuh;
  if (!force && token.value && token.exp > Date.now()) return token.value;
  const basic = Buffer.from(`${w.apiUser}:${decrypt(w.apiPassEnc)}`).toString('base64');
  const r = await req({ method: 'POST', port: w.apiPort, path: '/security/user/authenticate?raw=true', headers: { Authorization: 'Basic ' + basic } });
  if (r.status !== 200) throw new HttpError(502, `Wazuh API tu choi dang nhap (HTTP ${r.status})`);
  token = { value: r.text.trim(), exp: Date.now() + 13 * 60000 };
  return token.value;
}
async function api(path) {
  const w = settings.get().wazuh;
  let t = await apiToken();
  let r = await req({ port: w.apiPort, path, headers: { Authorization: 'Bearer ' + t } });
  if (r.status === 401) { t = await apiToken(true); r = await req({ port: w.apiPort, path, headers: { Authorization: 'Bearer ' + t } }); }
  if (r.status >= 400) throw new HttpError(502, `Wazuh API loi HTTP ${r.status}`);
  return r.json;
}
async function indexer(path, body) {
  const w = settings.get().wazuh;
  const basic = Buffer.from(`${w.indexerUser}:${decrypt(w.indexerPassEnc)}`).toString('base64');
  const r = await req({ method: body ? 'POST' : 'GET', port: w.indexerPort, path, headers: { Authorization: 'Basic ' + basic }, body });
  if (r.status >= 400) throw new HttpError(502, `Wazuh Indexer loi HTTP ${r.status}`);
  return r.json;
}

async function status() {
  const out = { configured: !!settings.get().wazuh.host, api: { ok: false }, indexer: { ok: false } };
  if (!out.configured) return out;
  try { const j = await api('/'); out.api = { ok: true, version: j && j.data && j.data.api_version, hostname: j && j.data && j.data.hostname }; } catch (e) { out.api = { ok: false, error: e.message }; }
  try { const j = await indexer('/'); out.indexer = { ok: true, cluster: j && j.cluster_name, version: j && j.version && j.version.number }; } catch (e) { out.indexer = { ok: false, error: e.message }; }
  return out;
}
async function agents() {
  const j = await api('/agents?limit=500&select=id,name,ip,status,os.name,version,lastKeepAlive,group');
  return ((j && j.data && j.data.affected_items) || []).map(a => ({ id: a.id, name: a.name, ip: a.ip, status: a.status, os: a.os && a.os.name, version: a.version, lastKeepAlive: a.lastKeepAlive, group: a.group }));
}

const levelToSev = l => (l >= 10 ? 'High' : l >= 7 ? 'Medium' : 'Low');
function mapHit(h) {
  const s = h._source || {}, rule = s.rule || {}, d = s.data || {}, agent = s.agent || {};
  const ip = d.srcip || d.src_ip || (d.alert && d.src_ip) || (s.data && s.data.srcip) || agent.ip || '';
  return {
    ts: Date.parse(s.timestamp) || Date.now(), ip, src_port: +(d.src_port || d.srcport) || 0,
    dst_ip: d.dstip || d.dest_ip || agent.ip || '', dst_port: +(d.dest_port || d.dstport) || 0, proto: String(d.proto || 'TCP').toUpperCase(),
    type: (rule.groups && rule.groups[0]) || 'Wazuh alert', tool: 'Wazuh', sev: levelToSev(rule.level), sid: +rule.id || 0,
    signature: rule.description || '', payload: String(s.full_log || '').slice(0, 1500), source: 'wazuh', agent: agent.name || '', dedupKey: 'wazuh|' + h._id
  };
}

async function searchAlerts(size = 100, since) {
  const body = { size, sort: [{ timestamp: 'asc' }], query: { range: { timestamp: { gt: since } } } };
  const j = await indexer('/wazuh-alerts-*/_search', body);
  return ((j && j.hits && j.hits.hits) || []);
}
async function recentAlerts(size = 50) {
  const j = await indexer('/wazuh-alerts-*/_search', { size, sort: [{ timestamp: 'desc' }], query: { match_all: {} } });
  return ((j && j.hits && j.hits.hits) || []).map(mapHit);
}

let polling = false;
async function poll() {
  const w = settings.get().wazuh;
  if (!w.enabled || !w.host || polling) return;
  polling = true;
  try {
    const since = st.data.lastTs || new Date(Date.now() - 3600000).toISOString();
    const hits = await searchAlerts(200, since);
    for (const h of hits) { alerts.add(mapHit(h)); const t = h._source && h._source.timestamp; if (t) st.data.lastTs = t; }
    if (hits.length) st.save();
  } catch (e) { /* Wazuh tat/hoc sai mat khau: bo qua, thu lai o chu ky sau */ }
  finally { polling = false; }
}
function start() { const loop = () => poll().finally(() => setTimeout(loop, settings.get().wazuh.pollSec * 1000)); setTimeout(loop, 3000); }

module.exports = { status, agents, recentAlerts, start, poll, mapHit };
