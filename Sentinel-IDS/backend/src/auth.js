'use strict';
/** Middleware xac thuc JWT + phan quyen theo role. */
const { verifyJwt, randomToken } = require('./security/crypto');
const users = require('./services/users');
const settings = require('./services/settings');
const { safeEqual } = require('./security/crypto');
const { HttpError } = require('./http');

function fromRequest(req) {
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return null;
  const p = verifyJwt(m[1]);
  if (!p) return null;
  const u = users.byId(p.sub);
  if (!u || u.disabled || u.tokenVersion !== p.tv) return null;
  return u;
}

// Ve 1 lan cho SSE (EventSource khong gui duoc header Authorization)
const tickets = new Map();
function issueTicket(user, purpose = 'sse') {
  const t = randomToken(18);
  tickets.set(t, { userId: user.id, purpose, exp: Date.now() + 30000 });
  return t;
}
function consumeTicket(t, purpose = 'sse') {
  const r = tickets.get(t); tickets.delete(t);
  if (!r || r.exp < Date.now() || r.purpose !== purpose) return null;
  const u = users.byId(r.userId);
  return u && !u.disabled ? u : null;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of tickets) if (v.exp < n) tickets.delete(k); }, 30000).unref();

function checkIngestKey(req) {
  const k = req.headers['x-ingest-key'];
  return !!k && safeEqual(k, settings.get().ingestKey);
}

module.exports = { fromRequest, issueTicket, consumeTicket, checkIngestKey };
