'use strict';
const store = require('../db/store');
const cfg = require('../config');
const { hashPassword, verifyPassword, randomPassword } = require('../security/crypto');
const { HttpError } = require('../http');

const col = store.open('users', []);
const uid = () => 'u-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

const DEFAULT_POLICY = () => ({
  allocated: ['8080-8089'],           // cong local cap san cho user
  privateAllowed: true,               // cho phep tu them cong private
  privateRange: '20000-20999',
  maxTunnels: 5,
  allowCustomTarget: true             // cho phep nhap host/URL tuy y (qua VM)
});

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) throw new HttpError(400, 'Mat khau toi thieu 8 ky tu');
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) throw new HttpError(400, 'Mat khau can co ca chu va so');
}
function validateUsername(u) {
  if (typeof u !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(u)) throw new HttpError(400, 'Username 3-32 ky tu (chu, so, _ . -)');
}

const publicUser = u => {
  const { passwordHash, tokenVersion, ...rest } = u;
  return rest;
};
const list = () => col.data.map(publicUser);
const byId = id => col.data.find(u => u.id === id);
const byName = n => col.data.find(u => u.username.toLowerCase() === String(n).toLowerCase());

function create({ username, password, role = 'user', displayName = '', email = '', telegramChatId = '', mustChangePassword = true, portPolicy }) {
  validateUsername(username); validatePassword(password);
  if (byName(username)) throw new HttpError(409, 'Username da ton tai');
  if (!['admin', 'user'].includes(role)) throw new HttpError(400, 'Role khong hop le');
  const u = {
    id: uid(), username, passwordHash: hashPassword(password), role,
    displayName: String(displayName).slice(0, 64), email: String(email).slice(0, 120),
    telegramChatId: String(telegramChatId).slice(0, 64),
    disabled: false, mustChangePassword: !!mustChangePassword, tokenVersion: 1,
    failedLogins: 0, lockedUntil: 0, createdAt: Date.now(), lastLoginAt: 0,
    portPolicy: { ...DEFAULT_POLICY(), ...(portPolicy || {}) }
  };
  col.data.push(u); col.save();
  return u;
}

function update(id, body, { self = false } = {}) {
  const u = byId(id);
  if (!u) throw new HttpError(404, 'Khong tim thay user');
  if (typeof body.displayName === 'string') u.displayName = body.displayName.slice(0, 64);
  if (typeof body.email === 'string') u.email = body.email.slice(0, 120);
  if (typeof body.telegramChatId === 'string') u.telegramChatId = body.telegramChatId.slice(0, 64);
  if (!self) {
    if (body.role !== undefined) {
      if (!['admin', 'user'].includes(body.role)) throw new HttpError(400, 'Role khong hop le');
      if (u.role === 'admin' && body.role !== 'admin' && activeAdmins() <= 1) throw new HttpError(400, 'Phai con it nhat 1 admin hoat dong');
      if (u.role !== body.role) { u.role = body.role; u.tokenVersion++; }
    }
    if (body.disabled !== undefined) {
      if (body.disabled && u.role === 'admin' && !u.disabled && activeAdmins() <= 1) throw new HttpError(400, 'Khong the khoa admin cuoi cung');
      u.disabled = !!body.disabled; if (u.disabled) u.tokenVersion++;
    }
    if (body.portPolicy) {
      const p = body.portPolicy, cur = u.portPolicy;
      if (Array.isArray(p.allocated)) cur.allocated = p.allocated.map(String).slice(0, 50);
      if (p.privateAllowed !== undefined) cur.privateAllowed = !!p.privateAllowed;
      if (typeof p.privateRange === 'string') cur.privateRange = p.privateRange;
      if (p.maxTunnels !== undefined) cur.maxTunnels = Math.min(100, Math.max(0, parseInt(p.maxTunnels, 10) || 0));
      if (p.allowCustomTarget !== undefined) cur.allowCustomTarget = !!p.allowCustomTarget;
    }
  }
  col.save();
  return u;
}

const activeAdmins = () => col.data.filter(u => u.role === 'admin' && !u.disabled).length;

function setPassword(id, pw, mustChange = false) {
  validatePassword(pw);
  const u = byId(id);
  if (!u) throw new HttpError(404, 'Khong tim thay user');
  u.passwordHash = hashPassword(pw); u.mustChangePassword = mustChange;
  u.tokenVersion++; u.failedLogins = 0; u.lockedUntil = 0;
  col.save();
  return u;
}

function remove(id) {
  const u = byId(id);
  if (!u) throw new HttpError(404, 'Khong tim thay user');
  if (u.role === 'admin' && !u.disabled && activeAdmins() <= 1) throw new HttpError(400, 'Khong the xoa admin cuoi cung');
  col.data.splice(col.data.indexOf(u), 1); col.save();
  return u;
}

/** Xac thuc dang nhap + khoa tam thoi sau 5 lan sai */
function authenticate(username, password) {
  const u = byName(username);
  const dummy = 'scrypt$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64');
  if (!u) { verifyPassword(password, dummy); throw new HttpError(401, 'Sai ten dang nhap hoac mat khau'); }
  if (u.lockedUntil > Date.now()) throw new HttpError(423, `Tai khoan bi khoa tam thoi, thu lai sau ${Math.ceil((u.lockedUntil - Date.now()) / 60000)} phut`);
  if (!verifyPassword(password, u.passwordHash)) {
    u.failedLogins = (u.failedLogins || 0) + 1;
    if (u.failedLogins >= 5) { u.lockedUntil = Date.now() + 5 * 60000; u.failedLogins = 0; }
    col.save();
    throw new HttpError(401, 'Sai ten dang nhap hoac mat khau');
  }
  if (u.disabled) throw new HttpError(403, 'Tai khoan da bi vo hieu hoa');
  u.failedLogins = 0; u.lockedUntil = 0; u.lastLoginAt = Date.now(); col.save();
  return u;
}

function bootstrapAdmin() {
  if (col.data.length) return;
  const pw = cfg.ADMIN_PASSWORD || randomPassword();
  create({ username: cfg.ADMIN_USERNAME, password: pw, role: 'admin', displayName: 'Administrator', mustChangePassword: !cfg.ADMIN_PASSWORD });
  console.log('\n==============================================================');
  console.log('  TAI KHOAN ADMIN DAU TIEN DA DUOC TAO (chi hien 1 lan):');
  console.log(`    Username: ${cfg.ADMIN_USERNAME}`);
  console.log(cfg.ADMIN_PASSWORD ? '    Password: (lay tu bien moi truong ADMIN_PASSWORD)' : `    Password: ${pw}`);
  if (!cfg.ADMIN_PASSWORD) console.log('    (Se bat doi mat khau o lan dang nhap dau)');
  console.log('==============================================================\n');
}

module.exports = { list, byId, byName, create, update, setPassword, remove, authenticate, bootstrapAdmin, publicUser, validatePassword, DEFAULT_POLICY, randomPassword };
