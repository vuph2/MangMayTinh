'use strict';
/** Chinh sach cong: cong local cap san (allocated) / cong private tu them / cong bi cam. */
const net = require('net');
const cfg = require('../config');
const { HttpError } = require('../http');

function parseRanges(list) {
  const out = [];
  for (const item of [].concat(list || [])) {
    const m = String(item).trim().match(/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/);
    if (!m) continue;
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a >= 1 && b <= 65535 && a <= b) out.push([a, b]);
  }
  return out;
}
const inRanges = (p, r) => r.some(([a, b]) => p >= a && p <= b);
const RESERVED = () => [cfg.PORT, cfg.FRONTEND_PORT];

function describe(user) {
  if (user.role === 'admin') return { admin: true, allocated: ['1024-65535'], privateAllowed: true, privateRange: '1024-65535', maxTunnels: 100, allowCustomTarget: true };
  return user.portPolicy;
}

/** Kiem tra cong local co duoc phep dung boi user khong. Tra ve 'allocated' | 'private'. */
function classify(user, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(400, 'Cong khong hop le (1-65535)');
  if (RESERVED().includes(port)) throw new HttpError(400, `Cong ${port} duoc he thong su dung`);
  if (user.role === 'admin') { if (port < 1024) throw new HttpError(400, 'Cong < 1024 bi cam'); return inRanges(port, parseRanges(user.portPolicy && user.portPolicy.allocated)) ? 'allocated' : 'private'; }
  const pol = user.portPolicy;
  if (inRanges(port, parseRanges(pol.allocated))) return 'allocated';
  if (pol.privateAllowed && inRanges(port, parseRanges(pol.privateRange))) return 'private';
  throw new HttpError(403, `Cong ${port} khong nam trong cong duoc cap hoac dai cong private cua ban`);
}

function canBind(port, host = cfg.TUNNEL_BIND_HOST) {
  return new Promise(resolve => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => s.close(() => resolve(true)));
    s.listen(port, host);
  });
}

/** Chon cong trong tu dong trong dai cap san */
async function pickFree(user, usedSet) {
  for (const [a, b] of parseRanges(describe(user).allocated)) {
    for (let p = Math.max(a, 1024); p <= b; p++) {
      if (usedSet.has(p) || RESERVED().includes(p)) continue;
      if (await canBind(p)) return p;
    }
  }
  throw new HttpError(409, 'Het cong local duoc cap. Hay giai phong cong hoac xin admin cap them.');
}

module.exports = { parseRanges, inRanges, classify, canBind, pickFree, describe };
