'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cfg = require('../config');

fs.mkdirSync(cfg.DATA_DIR, { recursive: true });

function loadMasterKey() {
  let secret = cfg.APP_SECRET;
  if (!secret) {
    const f = path.join(cfg.DATA_DIR, 'secret.key');
    if (fs.existsSync(f)) secret = fs.readFileSync(f, 'utf8').trim();
    else { secret = crypto.randomBytes(48).toString('hex'); fs.writeFileSync(f, secret, { mode: 0o600 }); }
  }
  return crypto.scryptSync(secret, 'sentinel-ids-salt', 32);
}
const KEY = loadMasterKey();

// ---- Hash mat khau (scrypt, salt rieng moi user) ----
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  try {
    const [alg, s, h] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const hash = crypto.scryptSync(pw, Buffer.from(s, 'base64'), 64, { N: 16384, r: 8, p: 1 });
    const exp = Buffer.from(h, 'base64');
    return exp.length === hash.length && crypto.timingSafeEqual(exp, hash);
  } catch { return false; }
}

// ---- Ma hoa du lieu nhay cam (AES-256-GCM): mat khau SSH cua VM, token Telegram... ----
function encrypt(text) {
  if (text === undefined || text === null || text === '') return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return 'enc1:' + [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.');
}
function decrypt(blob) {
  if (!blob || !String(blob).startsWith('enc1:')) return '';
  try {
    const [iv, tag, ct] = blob.slice(5).split('.').map(s => Buffer.from(s, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch { return ''; }
}

// ---- JWT HS256 ----
const b64u = b => Buffer.from(b).toString('base64url');
function signJwt(payload, ttlSec = cfg.TOKEN_TTL_SEC) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ ...payload, iat: now, exp: now + ttlSec }));
  const sig = crypto.createHmac('sha256', KEY).update(head + '.' + body).digest('base64url');
  return `${head}.${body}.${sig}`;
}
function verifyJwt(token) {
  try {
    const [h, b, s] = String(token).split('.');
    if (!h || !b || !s) return null;
    const exp = crypto.createHmac('sha256', KEY).update(h + '.' + b).digest();
    const got = Buffer.from(s, 'base64url');
    if (exp.length !== got.length || !crypto.timingSafeEqual(exp, got)) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    return p;
  } catch { return null; }
}

const randomToken = (n = 24) => crypto.randomBytes(n).toString('base64url');
const randomPassword = () => crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, 'x') + 'A1';
const safeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

module.exports = { hashPassword, verifyPassword, encrypt, decrypt, signJwt, verifyJwt, randomToken, randomPassword, safeEqual };
