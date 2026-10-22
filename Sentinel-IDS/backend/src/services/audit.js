'use strict';
const store = require('../db/store');
const cfg = require('../config');
const col = store.open('audit', []);

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
