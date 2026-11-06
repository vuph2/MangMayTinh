'use strict';
/**
 * email.js — Gui Email canh bao qua SMTP, KHONG dung thu vien ngoai.
 *
 * Giai thich cho nguoi moi (nganh mang):
 *  - SMTP la giao thuc gui mail. Ta "noi chuyen" voi may chu mail bang cac lenh text:
 *      EHLO  -> chao hoi
 *      STARTTLS -> nang cap ket noi thuong len ma hoa TLS (cong 587)
 *      AUTH LOGIN -> dang nhap (user/pass ma hoa base64)
 *      MAIL FROM / RCPT TO / DATA -> nguoi gui / nguoi nhan / noi dung
 *      QUIT -> ket thuc
 *  - May chu tra ve ma 3 so: 2xx = ok, 3xx = cho du lieu tiep, 4xx/5xx = loi.
 *  - 2 kieu bao mat:
 *      secure=true  (cong 465): ma hoa TLS NGAY tu dau.
 *      secure=false (cong 587): ket noi thuong roi dung STARTTLS de nang cap.
 */
const net = require('net');
const tls = require('tls');
const settings = require('./settings');

// Doc 1 phan hoi SMTP day du. SMTP co the tra nhieu dong: "250-..." (con nua) va "250 ..." (dong cuoi).
// Ta doi den khi gap dong co dang "<3 so><dau cach>" thi coi la het.
function readReply(sock) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = (d) => {
      buf += d.toString('utf8');
      // Tach cac dong da nhan, tim dong cuoi "250 " (co dau cach sau ma so)
      const lines = buf.split(/\r?\n/).filter(Boolean);
      const last = lines[lines.length - 1] || '';
      if (/^\d{3} /.test(last)) {
        cleanup();
        const code = parseInt(last.slice(0, 3), 10);
        resolve({ code, text: buf.trim() });
      }
    };
    const onErr = (e) => { cleanup(); reject(e); };
    const onEnd = () => { cleanup(); reject(new Error('May chu SMTP dong ket noi som')); };
    const timer = setTimeout(() => { cleanup(); reject(new Error('Het thoi gian cho SMTP')); }, 12000);
    function cleanup() { clearTimeout(timer); sock.removeListener('data', onData); sock.removeListener('error', onErr); sock.removeListener('end', onEnd); }
    sock.on('data', onData); sock.on('error', onErr); sock.on('end', onEnd);
  });
}

// Gui 1 lenh roi doc phan hoi. Neu ma tra ve khong nam trong danh sach "ok" -> nem loi.
async function cmd(sock, line, okCodes) {
  if (line !== null) sock.write(line + '\r\n');
  const rep = await readReply(sock);
  if (okCodes && !okCodes.includes(rep.code)) throw new Error(`SMTP ${rep.code}: ${rep.text}`);
  return rep;
}

// Mo ket noi TLS tu mot socket thuong (dung cho STARTTLS cong 587)
function upgradeTLS(sock, host) {
  return new Promise((resolve, reject) => {
    const secured = tls.connect({ socket: sock, servername: host, rejectUnauthorized: false }, () => resolve(secured));
    secured.once('error', reject);
  });
}

/**
 * send(): gui 1 email. Nhan cau hinh rieng (de test) hoac lay tu settings.
 * cfg = { host, port, secure, user, pass, from, to }
 */
async function send({ subject, text }, cfgOverride) {
  const s = settings.get().email;
  const cfg = {
    host: s.host, port: s.port, secure: s.secure, user: s.user,
    pass: s.passEnc ? settings.decrypt(s.passEnc) : '',
    from: s.from || s.user, to: s.to,
    ...(cfgOverride || {})
  };
  if (!cfg.host) throw new Error('Chua cau hinh may chu SMTP (host)');
  if (!cfg.to) throw new Error('Chua cau hinh nguoi nhan (to)');
  const from = cfg.from || cfg.user;
  const rcpts = String(cfg.to).split(',').map(x => x.trim()).filter(Boolean);

  // 1) Mo ket noi: secure=true -> TLS ngay; nguoc lai -> ket noi thuong roi STARTTLS
  let sock = cfg.secure
    ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host, rejectUnauthorized: false })
    : net.connect({ host: cfg.host, port: cfg.port });
  await new Promise((res, rej) => { sock.once(cfg.secure ? 'secureConnect' : 'connect', res); sock.once('error', rej); });

  try {
    await cmd(sock, null, [220]);                                  // may chu chao 220
    await cmd(sock, 'EHLO sentinel-ids', [250]);                   // tu gioi thieu
    if (!cfg.secure) {                                             // cong 587: nang cap len TLS
      await cmd(sock, 'STARTTLS', [220]);
      sock = await upgradeTLS(sock, cfg.host);
      await cmd(sock, 'EHLO sentinel-ids', [250]);                 // chao lai sau khi da ma hoa
    }
    if (cfg.user) {                                               // dang nhap neu co tai khoan
      await cmd(sock, 'AUTH LOGIN', [334]);
      await cmd(sock, Buffer.from(cfg.user).toString('base64'), [334]);
      await cmd(sock, Buffer.from(cfg.pass || '').toString('base64'), [235]);
    }
    await cmd(sock, `MAIL FROM:<${from}>`, [250]);                 // nguoi gui
    for (const r of rcpts) await cmd(sock, `RCPT TO:<${r}>`, [250, 251]); // tung nguoi nhan
    await cmd(sock, 'DATA', [354]);                                // bao sap gui noi dung
    // Tao phan dau (header) + than mail. Ket thuc bang dong chi co dau "."
    const headers = [
      `From: Sentinel IDS <${from}>`,
      `To: ${rcpts.join(', ')}`,
      `Subject: ${encodeHeader(subject)}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      ''
    ].join('\r\n');
    const body = String(text).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..'); // chong "." dau dong lam ket thuc som
    await cmd(sock, headers + body + '\r\n.', [250]);
    await cmd(sock, 'QUIT', [221]).catch(() => {});               // chao tam biet (loi o day khong quan trong)
    return true;
  } finally {
    try { sock.end(); sock.destroy(); } catch {}
  }
}

// Ma hoa tieu de co dau tieng Viet theo chuan RFC 2047 (=?utf-8?B?...?=)
function encodeHeader(str) {
  const s = String(str || '');
  if (/^[\x00-\x7F]*$/.test(s)) return s;                          // thuan ASCII -> giu nguyen
  return '=?utf-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
}

/** notify(): gui nhung KHONG nem loi (dung cho thong bao tu dong khi co canh bao). */
async function notify(subject, text) {
  try {
    if (!settings.get().email.enabled) return false;
    await send({ subject, text });
    return true;
  } catch (e) { console.error('[email]', e.message); return false; }
}

module.exports = { send, notify };
