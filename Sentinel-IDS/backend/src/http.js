'use strict';
/** Router + tien ich HTTP toi gian (khong can express). */
const cfg = require('./config');

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

class Router {
  constructor() { this.routes = []; }
  add(method, path, opts, handler) {
    if (typeof opts === 'function') { handler = opts; opts = {}; }
    const keys = [];
    const re = new RegExp('^' + path.replace(/:([A-Za-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
    this.routes.push({ method, re, keys, opts, handler });
  }
  get(p, o, h) { this.add('GET', p, o, h); }
  post(p, o, h) { this.add('POST', p, o, h); }
  put(p, o, h) { this.add('PUT', p, o, h); }
  patch(p, o, h) { this.add('PATCH', p, o, h); }
  delete(p, o, h) { this.add('DELETE', p, o, h); }
  match(method, pathname) {
    for (const r of this.routes) {
      if (r.method !== method) continue;
      const m = pathname.match(r.re);
      if (!m) continue;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return { route: r, params };
    }
    return null;
  }
}

function corsHeaders(req) {
  const origin = req.headers.origin;
  const h = { 'Vary': 'Origin' };
  if (origin && cfg.FRONTEND_ORIGINS.includes(origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';
    h['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Ingest-Key';
    h['Access-Control-Max-Age'] = '600';
  }
  return h;
}

function sendJson(req, res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...corsHeaders(req)
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > cfg.MAX_BODY) { reject(new HttpError(413, 'Payload qua lon')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'JSON khong hop le')); }
    });
    req.on('error', reject);
  });
}

// Gioi han toc do theo khoa (IP / user)
const buckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.n++;
  if (b.n > max) throw new HttpError(429, `Qua nhieu yeu cau. Thu lai sau ${Math.ceil((b.reset - now) / 1000)}s`);
}
setInterval(() => { const n = Date.now(); for (const [k, b] of buckets) if (b.reset < n) buckets.delete(k); }, 60000).unref();

const clientIp = req => (req.socket.remoteAddress || '').replace(/^::ffff:/, '');

module.exports = { Router, HttpError, sendJson, readBody, corsHeaders, rateLimit, clientIp };
