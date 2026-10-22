'use strict';
/** Hub Server-Sent Events: day su kien realtime xuong Frontend (co the nham toi 1 user / 1 role). */
const clients = new Map(); // id -> { res, user }
let seq = 0;

function addClient(res, user) {
  const id = ++seq;
  clients.set(id, { res, user });
  res.on('close', () => clients.delete(id));
  return id;
}

function emit(event, data, target = null) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const [id, c] of clients) {
    if (target) {
      if (target.userId && c.user.id !== target.userId && !(target.alsoAdmins && c.user.role === 'admin')) continue;
      if (target.role && c.user.role !== target.role) continue;
    }
    try { c.res.write(msg); } catch { clients.delete(id); }
  }
}

setInterval(() => { for (const [id, c] of clients) { try { c.res.write(': ping\n\n'); } catch { clients.delete(id); } } }, 25000).unref();

module.exports = { addClient, emit, count: () => clients.size };
