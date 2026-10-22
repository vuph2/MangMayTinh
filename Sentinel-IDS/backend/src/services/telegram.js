'use strict';
/** Gui thong bao Telegram THAT qua Bot API. */
const settings = require('./settings');
const { decrypt } = require('../security/crypto');

async function send(text, chatId, tokenOverride) {
  const s = settings.get().telegram;
  const token = tokenOverride || decrypt(s.tokenEnc);
  const chat = chatId || s.chatId;
  if (!token) throw new Error('Chua cau hinh Bot Token');
  if (!chat) throw new Error('Chua cau hinh Chat ID');
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chat, text: String(text).slice(0, 4000), disable_web_page_preview: true }),
    signal: AbortSignal.timeout(8000)
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok || !j.ok) throw new Error(j.description || `Telegram HTTP ${res.status}`);
  return j.result;
}

/** Gui khong nem loi (dung cho thong bao tu dong) */
async function notify(text, chatId) {
  try { if (settings.get().telegram.enabled || chatId) await send(text, chatId); return true; }
  catch (e) { console.error('[telegram]', e.message); return false; }
}

module.exports = { send, notify };
