'use strict';
/**
 * Dat lai mat khau admin (hoac tao admin neu chua co) MA KHONG xoa du lieu.
 *   1) DUNG backend (Ctrl+C)   2) cd backend   3) npm run reset-admin -- MatKhauMoi123 [username]
 */
const users = require('../src/services/users');
const store = require('../src/db/store');
const cfg = require('../src/config');

const pw = process.argv[2];
const name = process.argv[3] || cfg.ADMIN_USERNAME;
if (!pw) { console.error('Cach dung: npm run reset-admin -- <matkhau-moi> [username]'); process.exit(1); }
try {
  let u = users.byName(name);
  if (!u) { u = users.create({ username: name, password: pw, role: 'admin', displayName: 'Administrator' }); console.log(`Da TAO admin "${name}".`); }
  else { users.setPassword(u.id, pw); users.update(u.id, { role: 'admin', disabled: false }); u.lockedUntil = 0; u.failedLogins = 0; console.log(`Da dat lai mat khau cho "${name}" (quyen admin, da mo khoa).`); }
  store.flushAll();
} catch (e) { console.error('Loi:', e.message); process.exit(1); }
