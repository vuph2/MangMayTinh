'use strict';
const fs = require('fs');
const path = require('path');

// Nap file .env (khong can thu vien ngoai)
(function loadEnv() {
  const p = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

module.exports = {
  PORT: parseInt(process.env.PORT, 10) || 3000,
  BIND_HOST: process.env.BIND_HOST || '127.0.0.1',
  TUNNEL_BIND_HOST: process.env.TUNNEL_BIND_HOST || '127.0.0.1',
  FRONTEND_PORT: parseInt(process.env.FRONTEND_PORT, 10) || 5173,
  FRONTEND_ORIGINS: (process.env.FRONTEND_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173').split(',').map(s => s.trim()).filter(Boolean),
  ADMIN_USERNAME: process.env.ADMIN_USERNAME || 'admin',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
  APP_SECRET: process.env.APP_SECRET || '',
  DATA_DIR: process.env.DATA_DIR || path.join(__dirname, '..', 'data'),
  TOKEN_TTL_SEC: 8 * 3600,
  MAX_BODY: 1024 * 256,
  MAX_ALERTS: 2000,
  MAX_AUDIT: 5000
};
