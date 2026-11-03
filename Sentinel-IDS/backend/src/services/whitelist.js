'use strict';
/**
 * Danh sach trang (IP tin tuong + luat bo qua) de giam canh bao gia.
 * - IP whitelist: bo qua tat ca canh bao tu IP do.
 * - Signature whitelist: bo qua canh bao co SID nhat dinh.
 */
const store = require('../db/store');
const { HttpError } = require('../http');

const col = store.open('whitelist', { ips: [], sids: [] });

// Dam bao cau truc du lieu
if (!Array.isArray(col.data.ips)) col.data.ips = [];
if (!Array.isArray(col.data.sids)) col.data.sids = [];

function isWhitelistedIp(ip) {
  return col.data.ips.some(entry => entry.ip === ip);
}

function isWhitelistedSid(sid) {
  if (!sid) return false;
  return col.data.sids.some(entry => entry.sid === sid);
}

function isWhitelisted(alert) {
  if (isWhitelistedIp(alert.ip)) return true;
  if (isWhitelistedSid(alert.sid)) return true;
  return false;
}

function listIps() { return col.data.ips; }
function listSids() { return col.data.sids; }

function addIp(ip, { reason = '', addedBy = '' } = {}) {
  if (!ip || !/^[A-Za-z0-9.:_/-]+$/.test(ip)) throw new HttpError(400, 'IP/CIDR khong hop le');
  if (ip.length > 64) throw new HttpError(400, 'IP/CIDR qua dai');
  if (col.data.ips.some(e => e.ip === ip)) throw new HttpError(409, 'IP nay da co trong danh sach trang');
  const entry = { ip, reason: String(reason).slice(0, 200), addedBy, addedAt: Date.now() };
  col.data.ips.push(entry);
  col.save();
  return entry;
}

function removeIp(ip) {
  const idx = col.data.ips.findIndex(e => e.ip === ip);
  if (idx < 0) throw new HttpError(404, 'Khong tim thay IP trong danh sach trang');
  col.data.ips.splice(idx, 1);
  col.save();
  return { ok: true };
}

function addSid(sid, { reason = '', addedBy = '' } = {}) {
  const n = parseInt(sid, 10);
  if (!Number.isFinite(n) || n <= 0) throw new HttpError(400, 'SID phai la so nguyen duong');
  if (col.data.sids.some(e => e.sid === n)) throw new HttpError(409, 'SID nay da co trong danh sach trang');
  const entry = { sid: n, reason: String(reason).slice(0, 200), addedBy, addedAt: Date.now() };
  col.data.sids.push(entry);
  col.save();
  return entry;
}

function removeSid(sid) {
  const n = parseInt(sid, 10);
  const idx = col.data.sids.findIndex(e => e.sid === n);
  if (idx < 0) throw new HttpError(404, 'Khong tim thay SID trong danh sach trang');
  col.data.sids.splice(idx, 1);
  col.save();
  return { ok: true };
}

module.exports = { isWhitelisted, isWhitelistedIp, isWhitelistedSid, listIps, listSids, addIp, removeIp, addSid, removeSid };

