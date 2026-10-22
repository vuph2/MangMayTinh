'use strict';
/** Static server cho Frontend (khong can thu vien ngoai). Chay: npm start  ->  http://localhost:5173 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT, 10) || 5173;
const HOST = process.env.HOST || '127.0.0.1';
const API_BASE = process.env.API_BASE || '';   // vd: http://192.168.1.10:3000/api (de trong = tu dung cung hostname, cong 3000)
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const ROOT = __dirname;

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT) || /[\\/](serve\.js|package\.json|node_modules)([\\/]|$)/.test(file.slice(ROOT.length))) { res.writeHead(403); return res.end('Forbidden'); }
  // config.js dong: cho phep doi API_BASE bang bien moi truong
  if (p === '/js/config.js' && API_BASE) {
    res.writeHead(200, { 'Content-Type': MIME['.js'], 'Cache-Control': 'no-store' });
    return res.end(`window.SENTINEL_CONFIG = { API_BASE: ${JSON.stringify(API_BASE)} };`);
  }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer'
    });
    fs.createReadStream(file).pipe(res);
  });
}).listen(PORT, HOST, () => console.log(`Sentinel IDS Frontend: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}   (API: ${API_BASE || 'tu dong -> cung host, cong 3000'})`));
