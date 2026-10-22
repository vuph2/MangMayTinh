'use strict';
/**
 * Data Access Layer - luu tru JSON ben vung (ghi nguyen tu: ghi file tam roi rename).
 * Moi "collection" la 1 file trong data/. Co the thay bang SQLite/MySQL ma khong phai
 * sua cac route vi moi noi chi dung store.open(name, default).data
 */
const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('../config');

fs.mkdirSync(DATA_DIR, { recursive: true });
const opened = new Map();

function open(name, defaultVal) {
  if (opened.has(name)) return opened.get(name);
  const file = path.join(DATA_DIR, name + '.json');
  let data = defaultVal;
  if (fs.existsSync(file)) {
    try { data = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); }
    catch (e) { console.error(`[store] Loi doc ${name}.json:`, e.message); fs.copyFileSync(file, file + '.corrupt-' + Date.now()); }
  }
  const col = {
    name, file, data, _timer: null,
    save(now = false) {
      if (now) return col._flush();
      if (col._timer) return;
      col._timer = setTimeout(col._flush, 150);
    },
    _flush() {
      clearTimeout(col._timer); col._timer = null;
      try {
        const tmp = file + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(col.data, null, 2), { mode: 0o600 });
        fs.renameSync(tmp, file);
      } catch (e) { console.error(`[store] Loi ghi ${name}.json:`, e.message); }
    }
  };
  opened.set(name, col);
  if (!fs.existsSync(file)) col._flush();
  return col;
}

function flushAll() { for (const c of opened.values()) if (c._timer) c._flush(); }
process.on('exit', flushAll);

module.exports = { open, flushAll };
