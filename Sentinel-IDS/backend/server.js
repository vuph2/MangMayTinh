'use strict';
/**
 * Sentinel IDS v2 - BACKEND (Data access + API server)
 * Chay:  cd backend && npm install && npm start
 */
const http = require('http');
const url = require('url');
const cfg = require('./src/config');
const { HttpError, sendJson, readBody, corsHeaders, rateLimit, clientIp } = require('./src/http');
const A = require('./src/auth');
const events = require('./src/services/events');
const users = require('./src/services/users');
const router = require('./src/routes');

const alerts = require('./src/services/alerts');
const blocklist = require('./src/services/blocklist');
const tunnels = require('./src/services/tunnels');
const terminals = require('./src/services/terminals');
const monitor = require('./src/services/monitor');
const sensors = require('./src/services/sensors');
const wazuh = require('./src/services/wazuh');
const ssh = require('./src/services/ssh');
const store = require('./src/db/store');
const termSvc = terminals;

users.bootstrapAdmin();
alerts.setHooks({ block: (ip, o) => blocklist.block(ip, o), cut: (a, reason) => tunnels.cutForIncident(a, reason) });

const server = http.createServer(async (req, res) => {
  const { pathname, query } = url.parse(req.url, true);
  if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders(req)); return res.end(); }
  if (!pathname.startsWith('/api/')) return sendJson(req, res, 404, { error: 'Backend chi phuc vu /api. Hay mo Frontend (mac dinh http://localhost:' + cfg.FRONTEND_PORT + ')' });
  const p = pathname.slice(4);

  try {
    rateLimit('ip:' + clientIp(req), 600, 60000);

    // --- SSE su kien realtime (xac thuc bang ve 1 lan) ---
    if (p === '/events' && req.method === 'GET') {
      const user = A.consumeTicket(query.ticket, 'sse');
      if (!user) throw new HttpError(401, 'Ve SSE khong hop le');
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', ...corsHeaders(req) });
      res.write('retry: 3000\n\n');
      events.addClient(res, user);
      return;
    }
    // --- SSE dau ra Terminal ---
    const tm = /^\/terminal\/([^/]+)\/stream$/.exec(p);
    if (tm && req.method === 'GET') {
      const user = A.consumeTicket(query.ticket, 'term:' + tm[1]);
      if (!user) throw new HttpError(401, 'Ve terminal khong hop le');
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', ...corsHeaders(req) });
      termSvc.subscribe(user, tm[1], res);
      return;
    }
    if (/^\/terminal\/[^/]+\/ticket$/.test(p) && req.method === 'POST') {
      const user = A.fromRequest(req); if (!user) throw new HttpError(401, 'Chua dang nhap');
      const id = p.split('/')[2];
      return sendJson(req, res, 200, { ticket: A.issueTicket(user, 'term:' + id) });
    }

    const m = router.match(req.method, p);
    if (!m) throw new HttpError(404, 'Khong co API: ' + req.method + ' ' + p);
    const { route, params } = m;
    let user = null;
    if (route.opts.auth === 'ingest') {
      user = A.fromRequest(req);
      if (!user && !A.checkIngestKey(req)) throw new HttpError(401, 'Thieu/sai X-Ingest-Key');
      if (user && user.role !== 'admin') throw new HttpError(403, 'Chi admin');
    } else if (route.opts.auth) {
      user = A.fromRequest(req);
      if (!user) throw new HttpError(401, 'Chua dang nhap hoac phien het han');
      if (user.mustChangePassword && p !== '/auth/change-password' && p !== '/auth/me' && p !== '/auth/logout') throw new HttpError(403, 'MUST_CHANGE_PASSWORD');
      if (route.opts.roles && !route.opts.roles.includes(user.role)) throw new HttpError(403, 'Khong du quyen (can quyen admin)');
    }
    const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readBody(req) : {};
    const result = await route.handler({ req, res, params, query, body, user });
    sendJson(req, res, route.method === 'POST' && route.opts.created ? 201 : 200, result === undefined ? { ok: true } : result);
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error('[500]', req.method, pathname, e);
    if (!res.headersSent) sendJson(req, res, status, { error: status === 500 ? 'Loi may chu' : e.message });
  }
});

server.listen(cfg.PORT, cfg.BIND_HOST, () => {
  console.log('====================================================');
  console.log('  Sentinel IDS v2 - BACKEND (API)');
  console.log(`  API:      http://${cfg.BIND_HOST}:${cfg.PORT}/api`);
  console.log(`  Frontend: ${cfg.FRONTEND_ORIGINS[0]}  (chay rieng: cd frontend && npm start)`);
  console.log('====================================================');
  monitor.start(); sensors.start(); wazuh.start();
});

function shutdown() {
  console.log('\n[shutdown] Dang dong tunnel / terminal va luu du lieu...');
  try { tunnels.stopAll('server-shutdown'); terminals.closeAll(); } catch {}
  store.flushAll(); process.exit(0);
}
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
process.on('uncaughtException', e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[unhandled]', e));
