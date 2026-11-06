'use strict';
/**
 * audit.js — Nhat ky hoat dong (ai lam gi, luc nao). Dung de truy vet va kiem toan.
 * Moi dong ghi: thoi gian, user, hanh dong (vd 'user.delete'), chi tiet, dia chi IP.
 * Luu toi da MAX_AUDIT dong moi nhat (cu thi bo bot).
 */
const store = require('../db/store');
const cfg = require('../config');
const col = store.open('audit', []);

// log(): ghi 1 dong nhat ky. user = null nghia la do he thong tu lam (vd tu dong chan IP).
function log(user, action, detail = '', ip = '') {
  col.data.unshift({
    ts: Date.now(),
    userId: user ? user.id : null,
    username: user ? user.username : 'system',
    action, detail: String(detail).slice(0, 500), ip
  });
  if (col.data.length > cfg.MAX_AUDIT) col.data.length = cfg.MAX_AUDIT;
  col.save();
}
function list({ limit = 200, user, action } = {}) {
  let r = col.data;
  if (user) r = r.filter(a => a.username === user);
  if (action) r = r.filter(a => a.action.startsWith(action));
  return r.slice(0, Math.min(limit, 1000));
}
module.exports = { log, list };
