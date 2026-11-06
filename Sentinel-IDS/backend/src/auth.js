'use strict';
/**
 * auth.js — Xac thuc nguoi dung (JWT) + cac "ve" tam thoi.
 *
 * Cho nguoi moi:
 *  - JWT la 1 chuoi token dinh kem o header "Authorization: Bearer <token>". No chua
 *    id user + role + phien ban token. fromRequest() giai ma va kiem tra token moi request.
 *  - "Ticket" (ve) la ma dung 1 lan, song ~30 giay — dung cho SSE (EventSource khong
 *    gui duoc header Authorization, nen phai truyen ve qua URL ?ticket=...).
 *  - "Ingest key" la khoa cho may ngoai (script day log) gui canh bao vao, thay cho dang nhap.
 */
const { verifyJwt, randomToken } = require('./security/crypto');

// Dinh danh moi lan chay backend: phien KHONG tick "tu dong dang nhap" chi song den khi backend duoc restart
const BOOT_ID = randomToken(9);
const users = require('./services/users');
const settings = require('./services/settings');
const { safeEqual } = require('./security/crypto');
const { HttpError } = require('./http');

// fromRequest(): doc token tu header, kiem tra hop le, tra ve user tuong ung (hoac null).
function fromRequest(req) {
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);      // lay phan sau chu "Bearer "
  if (!m) return null;
  const p = verifyJwt(m[1]);                  // giai ma + kiem tra chu ky/han dung
  if (!p) return null;
  if (!p.rem && p.bid !== BOOT_ID) return null;   // phien tam (khong "nho"): het hieu luc khi backend khoi dong lai
  req.claims = p;
  const u = users.byId(p.sub);                // p.sub = id user
  // Token bi vo hieu neu: user bi xoa, bi khoa, hoac da doi mat khau/dang xuat (tokenVersion doi)
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

module.exports = { BOOT_ID, fromRequest, issueTicket, consumeTicket, checkIngestKey };
