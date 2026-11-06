'use strict';
/**
 * routes/index.js — BAN DO API (danh sach tat ca duong dan /api/...).
 *
 * Cho nguoi moi doc file nay:
 *  - r.get / r.post / r.put / r.patch / r.delete dinh nghia 1 duong dan + ham xu ly.
 *  - Tham so thu 2 cho biet quyen: USER = can dang nhap, ADMIN = can quyen admin,
 *    { auth: 'ingest' } = cho phep may ngoai dung X-Ingest-Key. Khong co = cong khai.
 *  - Ham xu ly nhan { req, params, query, body, user } va tra ve 1 object -> gui ve dang JSON.
 *  - Moi route chi 1-2 dong: kiem tra/goi service tuong ung roi tra ket qua. Logic that nam
 *    trong cac file src/services/*. Nho vay doc o day la thay nhanh "he thong co nhung API gi".
 */
const { Router, HttpError, rateLimit, clientIp } = require('../http');
const cfg = require('../config');
const { signJwt } = require('../security/crypto');
const A = require('../auth');
const users = require('../services/users');
const vms = require('../services/vms');
const tools = require('../services/tools');
const tunnels = require('../services/tunnels');
const terminals = require('../services/terminals');
const policy = require('../services/portpolicy');
const alerts = require('../services/alerts');
const blocklist = require('../services/blocklist');
const rules = require('../services/rules');
const settings = require('../services/settings');
const telegram = require('../services/telegram');
const email = require('../services/email');
const wazuh = require('../services/wazuh');
const sensors = require('../services/sensors');
const monitor = require('../services/monitor');
const ssh = require('../services/ssh');
const audit = require('../services/audit');
const events = require('../services/events');
const whitelist = require('../services/whitelist');
const scenarios = require('../services/scenarios');


const r = new Router();
const ADMIN = { auth: true, roles: ['admin'] };
const USER = { auth: true };
// remember=true: tu dong dang nhap 30 ngay (song qua restart). Nguoc lai: 8 gio va chi hieu luc den khi backend restart.
const issueToken = (u, remember) => signJwt({ sub: u.id, role: u.role, tv: u.tokenVersion, rem: !!remember, bid: remember ? undefined : A.BOOT_ID }, remember ? 30 * 86400 : cfg.TOKEN_TTL_SEC);
const str = (v, max = 200) => String(v === undefined || v === null ? '' : v).slice(0, max);
// Lay khoang thoi gian tu query (?from=..&to=..). Khong co -> {} (che do mac dinh).
const range = q => (q.from && q.to) ? { from: parseInt(q.from, 10), to: parseInt(q.to, 10) } : {};

// ======================= AUTH =======================
r.get('/health', () => ({ ok: true, time: Date.now(), version: '2.2.0' }));

r.post('/auth/login', async ({ req, body }) => {
  const ip = clientIp(req);
  rateLimit('login:' + ip, 20, 10 * 60000);
  const u = users.authenticate(str(body.username, 64), str(body.password, 200));
  const remember = body.remember === true;
  audit.log(u, 'auth.login', remember ? 'remember' : '', ip);
  return { token: issueToken(u, remember), remember, user: users.publicUser(u) };
});
r.post('/auth/logout', USER, ({ user, req }) => { user.tokenVersion++; audit.log(user, 'auth.logout', '', clientIp(req)); return { ok: true }; });
r.get('/auth/options', () => ({ allowRegistration: !!settings.get().security.allowRegistration }));
r.post('/auth/register', ({ req, body }) => {
  rateLimit('reg:' + clientIp(req), 5, 3600000);
  if (!settings.get().security.allowRegistration) throw new HttpError(403, 'Admin da tat chuc nang dang ky');
  const u = users.register({ username: str(body.username, 64), password: str(body.password, 200), displayName: str(body.displayName, 64), email: str(body.email, 120) });
  audit.log(u, 'auth.register', 'cho admin duyet', clientIp(req));
  events.emit('user_pending', { username: u.username, ts: Date.now() }, { role: 'admin' });
  telegram.notify(`🆕 Tai khoan moi cho duyet: ${u.username}`);
  return { ok: true, pending: true };
});
r.post('/auth/forgot', ({ req, body }) => {
  rateLimit('forgot:' + clientIp(req), 5, 3600000);
  const u = users.requestReset(str(body.username, 64));
  if (u && !u.pending) {
    audit.log(u, 'auth.forgot', 'yeu cau dat lai mat khau', clientIp(req));
    events.emit('reset_requested', { username: u.username, ts: Date.now() }, { role: 'admin' });
    telegram.notify(`🔑 ${u.username} yeu cau dat lai mat khau`);
  }
  return { ok: true };   // luon tra loi giong nhau, khong lo user co ton tai hay khong
});
r.get('/auth/me', USER, ({ user }) => ({ user: users.publicUser(user), policy: policy.describe(user) }));
r.post('/auth/change-password', USER, ({ user, body, req }) => {
  rateLimit('chpw:' + user.id, 10, 10 * 60000);
  const { verifyPassword } = require('../security/crypto');
  if (!verifyPassword(str(body.oldPassword), user.passwordHash)) throw new HttpError(403, 'Mat khau hien tai khong dung');
  users.setPassword(user.id, str(body.newPassword, 200), false);
  audit.log(user, 'auth.change-password', '', clientIp(req));
  const remember = !!(req.claims && req.claims.rem);
  return { token: issueToken(user, remember), remember, user: users.publicUser(user) };
});
r.patch('/auth/profile', USER, ({ user, body }) => ({ user: users.publicUser(users.update(user.id, body, { self: true })) }));
r.post('/auth/ticket', USER, ({ user }) => ({ ticket: A.issueTicket(user) }));

// ======================= ADMIN: USERS =======================
r.get('/users', ADMIN, () => users.list());
r.post('/users', ADMIN, ({ user, body }) => {
  const u = users.create({ ...body, username: str(body.username, 64), password: str(body.password, 200), mustChangePassword: false });
  audit.log(user, 'user.create', `${u.username} (${u.role})`);
  return users.publicUser(u);
});
r.patch('/users/:id', ADMIN, ({ user, params, body }) => {
  const u = users.update(params.id, body);
  audit.log(user, 'user.update', u.username);
  if (body.portPolicy) for (const t of tunnels.all().filter(t => t.ownerId === u.id)) { try { policy.classify(u, t.localPort); } catch { tunnels.stop(t.id, 'admin-policy-change (cong khong con duoc phep)'); } }
  if (u.disabled) for (const t of tunnels.all().filter(t => t.ownerId === u.id)) tunnels.stop(t.id, 'tai khoan bi khoa');
  return users.publicUser(u);
});
r.post('/users/:id/reset-password', ADMIN, ({ user, params, body }) => {
  const pw = body.password ? str(body.password, 200) : users.randomPassword();
  const u = users.setPassword(params.id, pw, true);
  audit.log(user, 'user.reset-password', u.username);
  return { ok: true, username: u.username, password: pw };
});
r.post('/users/:id/approve', ADMIN, ({ user, params }) => { const u = users.approve(params.id); audit.log(user, 'user.approve', u.username); return users.publicUser(u); });
r.post('/users/:id/unlock', ADMIN, ({ user, params }) => { const u = users.byId(params.id); if (!u) throw new HttpError(404, 'Khong tim thay user'); u.lockedUntil = 0; u.failedLogins = 0; audit.log(user, 'user.unlock', u.username); return users.publicUser(u); });
r.delete('/users/:id', ADMIN, ({ user, params }) => {
  if (params.id === user.id) throw new HttpError(400, 'Khong the tu xoa chinh minh');
  for (const t of tunnels.all().filter(t => t.ownerId === params.id)) tunnels.remove(user, t.id);
  const u = users.remove(params.id); audit.log(user, 'user.delete', u.username);
  return { ok: true };
});

// ======================= VMs =======================
r.get('/vms', USER, ({ user }) => vms.all().map(v => vms.toPublic(v, user.role === 'admin')));
r.post('/vms', ADMIN, ({ user, body }) => { const v = vms.create(body); audit.log(user, 'vm.create', `${v.name} ${v.ip}`); monitor.checkNow(v); return vms.toPublic(v, true); });
r.patch('/vms/:id', ADMIN, ({ user, params, body }) => { const v = vms.update(params.id, body); ssh.dropControl(v.id); audit.log(user, 'vm.update', v.name); monitor.checkNow(v); sensors.sync(); return vms.toPublic(v, true); });
r.delete('/vms/:id', ADMIN, ({ user, params }) => { tunnels.stopAllForVm(params.id, 'VM bi xoa'); ssh.dropControl(params.id); const v = vms.remove(params.id); audit.log(user, 'vm.delete', v.name); sensors.sync(); return { ok: true }; });
r.post('/vms/:id/test', ADMIN, async ({ params }) => {
  const v = vms.byId(params.id); if (!v) throw new HttpError(404, 'Khong tim thay VM');
  const t0 = Date.now();
  try { const c = await ssh.connect(v); c.end(); return { ok: true, ms: Date.now() - t0 }; }
  catch (e) { return { ok: false, error: e.message }; }
});
r.post('/vms/:id/check', USER, async ({ params }) => { const v = vms.byId(params.id); if (!v) throw new HttpError(404, 'Khong tim thay VM'); await monitor.checkNow(v); return vms.toPublic(v); });

// ======================= TOOLS (Wazuh, SSH, ... + lua chon mien phi) =======================
r.get('/tools', USER, ({ user }) => tools.list(user.role === 'admin'));
r.post('/tools', ADMIN, ({ user, body }) => { const t = tools.create(body); audit.log(user, 'tool.create', t.name); return t; });
r.patch('/tools/:id', ADMIN, ({ user, params, body }) => { const t = tools.update(params.id, body); audit.log(user, 'tool.update', t.name); return t; });
r.delete('/tools/:id', ADMIN, ({ user, params }) => { tools.remove(params.id); audit.log(user, 'tool.delete', params.id); return { ok: true }; });

// ======================= GATEWAY / TUNNELS / PORTS =======================
r.get('/gateway/tunnels', USER, ({ user }) => tunnels.listFor(user));
r.post('/gateway/tunnels', USER, ({ user, body }) => tunnels.create(user, body));
r.patch('/gateway/tunnels/:id', USER, ({ user, params, body }) => tunnels.update(user, params.id, body));
r.post('/gateway/tunnels/:id/start', USER, ({ user, params }) => tunnels.start(user, params.id));
r.post('/gateway/tunnels/:id/stop', USER, ({ user, params }) => { const t = tunnels.getOwned(user, params.id); tunnels.stop(t.id, 'user'); return { ok: true }; });
r.post('/gateway/cut-all', USER, ({ user }) => { let n = 0; for (const t of tunnels.listFor(user)) if (t.running && tunnels.stop(t.id, 'user:cat-tat-ca')) n++; return { cut: n }; });
r.delete('/gateway/tunnels/:id', USER, ({ user, params }) => { tunnels.remove(user, params.id); return { ok: true }; });
r.post('/gateway/probe', USER, ({ user, body }) => tunnels.probe(user, body));

r.get('/ports/policy', USER, ({ user }) => ({ policy: policy.describe(user), reserved: [cfg.PORT, cfg.FRONTEND_PORT], bindHost: cfg.TUNNEL_BIND_HOST }));
r.get('/ports/check', USER, async ({ user, query }) => {
  const port = parseInt(query.port, 10);
  let kind = null, allowed = true, reason = '';
  try { kind = policy.classify(user, port); } catch (e) { allowed = false; reason = e.message; }
  const used = tunnels.all().find(t => t.localPort === port);
  const free = allowed && !used && await policy.canBind(port);
  return { port, allowed, kind, free, usedBy: used ? used.name : null, reason: reason || (used ? 'Cong da gan cho tunnel khac' : (!free && allowed ? 'Cong dang bi tien trinh khac su dung' : '')) };
});

// ======================= TERMINAL (SSH qua VM) =======================
r.get('/terminal', USER, ({ user }) => terminals.list(user));
r.post('/terminal', USER, ({ user, body }) => terminals.open(user, body));
r.post('/terminal/:id/input', USER, ({ user, params, body }) => { terminals.input(user, params.id, str(body.data, 8192)); return { ok: true }; });
r.post('/terminal/:id/resize', USER, ({ user, params, body }) => { terminals.resize(user, params.id, body.cols, body.rows); return { ok: true }; });
r.delete('/terminal/:id', USER, ({ user, params }) => { terminals.close(user, params.id); return { ok: true }; });

// ======================= ALERTS / STATS =======================
r.get('/alerts', USER, ({ query }) => alerts.query({ ip: query.ip, type: query.type, sev: query.sev, status: query.status, limit: query.limit }));
r.post('/alerts', { auth: 'ingest' }, ({ body }) => ({ success: true, alert: alerts.add({ ...body, source: 'ingest', dedupKey: null }) }));
r.patch('/alerts/:id', ADMIN, ({ user, params, body }) => {
  const a = alerts.setStatus(params.id, body.status);
  if (a === null) throw new HttpError(404, 'Khong tim thay canh bao');
  if (a === undefined) throw new HttpError(400, 'Trang thai khong hop le');
  audit.log(user, 'alert.status', `${a.id} -> ${a.status}`); return a;
});
r.delete('/alerts', ADMIN, ({ user }) => { alerts.clear(); audit.log(user, 'alert.clear'); return { ok: true }; });
// /stats: khong co from/to -> so lieu mac dinh (3h). Co from/to -> bao cao theo khoang thoi gian.
r.get('/stats', USER, ({ query }) => ({ ...alerts.stats(range(query)), blockedIps: blocklist.list().length, vmsOnline: vms.all().filter(v => vms.rt(v.id).on).length, vmsTotal: vms.all().length, tunnelsRunning: tunnels.running(), sse: events.count() }));
r.get('/sensors', USER, () => sensors.status());

// ======================= BLOCKLIST (Active Response) =======================
r.get('/blocklist', USER, () => blocklist.list());
r.post('/blocklist', ADMIN, ({ user, body }) => blocklist.block(str(body.ip, 64), { reason: str(body.reason), duration: body.duration, source: 'manual', ruleSid: body.ruleSid }, user));
r.post('/blocklist/:ip/reapply', ADMIN, ({ user, params }) => blocklist.reapply(params.ip, user));
r.delete('/blocklist/:ip', ADMIN, ({ user, params }) => blocklist.unblock(params.ip, user));

// ======================= SURICATA RULES =======================
r.get('/rules', USER, () => rules.list());
r.post('/rules/validate', ADMIN, ({ body }) => rules.validate(body.raw));
r.post('/rules', ADMIN, ({ user, body }) => rules.create(body, user));
r.put('/rules/:id', ADMIN, ({ user, params, body }) => rules.update(parseInt(params.id, 10), body, user));
r.delete('/rules/:id', ADMIN, ({ user, params }) => { rules.remove(parseInt(params.id, 10), user); return { ok: true }; });
r.post('/rules/deploy', ADMIN, ({ user, body }) => rules.deploy(str(body.vmId), user));

// ======================= WAZUH =======================
r.get('/wazuh/status', USER, () => wazuh.status());
r.get('/wazuh/agents', USER, () => wazuh.agents());
r.get('/wazuh/alerts', USER, ({ query }) => wazuh.recentAlerts(Math.min(parseInt(query.limit, 10) || 50, 200)));
r.post('/wazuh/sync', ADMIN, async () => { await wazuh.poll(); return { ok: true }; });

// ======================= SETTINGS / AUDIT =======================
r.get('/settings', ADMIN, () => settings.masked());
r.put('/settings', ADMIN, ({ user, body }) => { const s = settings.update(body); audit.log(user, 'settings.update', Object.keys(body).join(',')); return s; });
r.post('/settings/telegram-test', ADMIN, async ({ user, body }) => {
  try { await telegram.send('✅ Sentinel IDS: tin nhan thu nghiem that tu ' + user.username, str(body.chatId) || undefined, str(body.token) || undefined); return { ok: true }; }
  catch (e) { throw new HttpError(502, 'Telegram loi: ' + e.message); }
});
// Gui email thu nghiem: dung cau hinh da luu (neu body rong) hoac cau hinh tam trong body.
r.post('/settings/email-test', ADMIN, async ({ user, body }) => {
  const over = {};
  for (const k of ['host', 'user', 'from', 'to']) if (typeof body[k] === 'string' && body[k]) over[k] = str(body[k], 400);
  if (body.port !== undefined) over.port = parseInt(body.port, 10) || 587;
  if (body.secure !== undefined) over.secure = !!body.secure;
  if (typeof body.pass === 'string' && body.pass) over.pass = body.pass;
  try {
    await email.send({ subject: '[Sentinel IDS] Email thu nghiem', text: 'Day la email thu nghiem that, gui boi ' + user.username + '.\nNeu ban nhan duoc email nay, cau hinh SMTP da dung.' }, Object.keys(over).length ? over : undefined);
    audit.log(user, 'settings.email-test', over.to || '');
    return { ok: true };
  } catch (e) { throw new HttpError(502, 'Email loi: ' + e.message); }
});
r.post('/settings/ingest-key', ADMIN, ({ user }) => { audit.log(user, 'settings.ingest-key'); return { ingestKey: settings.regenerateIngestKey() }; });
r.get('/settings/ingest-key', ADMIN, () => ({ ingestKey: settings.get().ingestKey }));
r.get('/audit', ADMIN, ({ query }) => audit.list({ limit: parseInt(query.limit, 10) || 200, user: query.user, action: query.action }));


// ======================= WHITELIST =======================
r.get('/whitelist/ips', USER, () => ({ ips: whitelist.listIps() }));
r.post('/whitelist/ips', ADMIN, ({ user, body }) => { const e = whitelist.addIp(str(body.ip, 64), { reason: str(body.reason), addedBy: user.username }); audit.log(user, 'whitelist.ip.add', e.ip); return e; });
r.delete('/whitelist/ips/:ip', ADMIN, ({ user, params }) => { const r = whitelist.removeIp(decodeURIComponent(params.ip)); audit.log(user, 'whitelist.ip.remove', params.ip); return r; });
r.get('/whitelist/sids', USER, () => ({ sids: whitelist.listSids() }));
r.post('/whitelist/sids', ADMIN, ({ user, body }) => { const e = whitelist.addSid(body.sid, { reason: str(body.reason), addedBy: user.username }); audit.log(user, 'whitelist.sid.add', String(e.sid)); return e; });
r.delete('/whitelist/sids/:sid', ADMIN, ({ user, params }) => { const r = whitelist.removeSid(params.sid); audit.log(user, 'whitelist.sid.remove', params.sid); return r; });

// ======================= INCIDENTS / REPORTS =======================
r.get('/incidents', USER, ({ query }) => alerts.incidents(str(query.ip, 64), query.limit));
r.get('/top-ips', USER, ({ query }) => ({ data: alerts.topIps(parseInt(query.n, 10) || 10, range(query)) }));
r.get('/top-signatures', USER, ({ query }) => ({ data: alerts.topSignatures(parseInt(query.n, 10) || 10, range(query)) }));

// ======================= SCENARIOS =======================
r.get('/scenarios', ADMIN, () => scenarios.listScenarios());
r.get('/scenarios/history', ADMIN, () => scenarios.listHistory());
r.get('/scenarios/run/:id', ADMIN, ({ params }) => scenarios.getStatus(params.id));
r.post('/scenarios/run', ADMIN, async ({ user, body }) => {
  const runId = await scenarios.run(str(body.scenario, 64), str(body.vmId, 64), str(body.target, 64), user);
  audit.log(user, 'scenario.run', `${body.scenario} -> ${body.target} (${runId})`);
  return { runId };
});
module.exports = r;
