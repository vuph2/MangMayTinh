'use strict';
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
const wazuh = require('../services/wazuh');
const sensors = require('../services/sensors');
const monitor = require('../services/monitor');
const ssh = require('../services/ssh');
const audit = require('../services/audit');
const events = require('../services/events');

const r = new Router();
const ADMIN = { auth: true, roles: ['admin'] };
const USER = { auth: true };
const str = (v, max = 200) => String(v === undefined || v === null ? '' : v).slice(0, max);

// ======================= AUTH =======================
r.get('/health', () => ({ ok: true, time: Date.now(), version: '2.0.0' }));

r.post('/auth/login', async ({ req, body }) => {
  const ip = clientIp(req);
  rateLimit('login:' + ip, 20, 10 * 60000);
  const u = users.authenticate(str(body.username, 64), str(body.password, 200));
  audit.log(u, 'auth.login', '', ip);
  return { token: signJwt({ sub: u.id, role: u.role, tv: u.tokenVersion }), user: users.publicUser(u) };
});
r.post('/auth/logout', USER, ({ user, req }) => { user.tokenVersion++; audit.log(user, 'auth.logout', '', clientIp(req)); return { ok: true }; });
r.get('/auth/me', USER, ({ user }) => ({ user: users.publicUser(user), policy: policy.describe(user) }));
r.post('/auth/change-password', USER, ({ user, body, req }) => {
  rateLimit('chpw:' + user.id, 10, 10 * 60000);
  const { verifyPassword } = require('../security/crypto');
  if (!verifyPassword(str(body.oldPassword), user.passwordHash)) throw new HttpError(403, 'Mat khau hien tai khong dung');
  users.setPassword(user.id, str(body.newPassword, 200), false);
  audit.log(user, 'auth.change-password', '', clientIp(req));
  return { token: signJwt({ sub: user.id, role: user.role, tv: user.tokenVersion }), user: users.publicUser(user) };
});
r.patch('/auth/profile', USER, ({ user, body }) => ({ user: users.publicUser(users.update(user.id, body, { self: true })) }));
r.post('/auth/ticket', USER, ({ user }) => ({ ticket: A.issueTicket(user) }));

// ======================= ADMIN: USERS =======================
r.get('/users', ADMIN, () => users.list());
r.post('/users', ADMIN, ({ user, body }) => {
  const u = users.create({ ...body, username: str(body.username, 64), password: str(body.password, 200), mustChangePassword: body.mustChangePassword !== false });
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
  return { ok: true, username: u.username, password: pw, mustChangePassword: true };
});
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
r.get('/stats', USER, () => ({ ...alerts.stats(), blockedIps: blocklist.list().length, vmsOnline: vms.all().filter(v => vms.rt(v.id).on).length, vmsTotal: vms.all().length, tunnelsRunning: tunnels.running(), sse: events.count() }));
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
r.post('/settings/ingest-key', ADMIN, ({ user }) => { audit.log(user, 'settings.ingest-key'); return { ingestKey: settings.regenerateIngestKey() }; });
r.get('/settings/ingest-key', ADMIN, () => ({ ingestKey: settings.get().ingestKey }));
r.get('/audit', ADMIN, ({ query }) => audit.list({ limit: parseInt(query.limit, 10) || 200, user: query.user, action: query.action }));

module.exports = r;
