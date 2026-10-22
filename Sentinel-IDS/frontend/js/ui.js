/** Sentinel IDS - UI helpers: h() (an toan XSS, dung textContent), icon, toast, modal, dropdown, format */
window.Views = window.Views || {};
// replaceChildren an toan: bo qua null/undefined/false, tu lam phang mang
(function () {
  const orig = Element.prototype.replaceChildren;
  const flat = a => a.flatMap(x => Array.isArray(x) ? flat(x) : [x]).filter(x => x !== null && x !== undefined && x !== false);
  Element.prototype.replaceChildren = function (...kids) { return orig.apply(this, flat(kids)); };
})();
(function () {
  const LANG_KEY = 'sentinel_lang';
  let lang = localStorage.getItem(LANG_KEY) || 'vi';
  // T("tieng viet", "english")
  const T = (vi, en) => (lang === 'en' && en !== undefined ? en : vi);
  const getLang = () => lang;
  const setLang = l => { lang = l; localStorage.setItem(LANG_KEY, l); };

  // ---------- Hyperscript ----------
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'readOnly') el[k] = !!v;
      else if (k === 'html') throw new Error('html= khong duoc phep (chong XSS)');
      else el.setAttribute(k, v === true ? '' : v);
    }
    const add = k => {
      if (k === undefined || k === null || k === false) return;
      if (Array.isArray(k)) return k.forEach(add);
      el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
    };
    kids.forEach(add);
    return el;
  }

  // ---------- Icon ----------
  const P = {
    server: '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01M12 7h5M12 17h5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>',
    shield: '<path d="M12 2.5L19.5 5.3V11.5C19.5 16.3 16.4 19.9 12 21.6C7.6 19.9 4.5 16.3 4.5 11.5V5.3Z"/><path d="M9 12l2 2 4-4"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    db: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    list: '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
    bell: '<path d="M6 16v-5a6 6 0 0112 0v5l2 2H4z"/><path d="M10 21h4"/>',
    plug: '<path d="M9 2v5M15 2v5M6 7h12v4a6 6 0 01-12 0zM12 17v5"/>',
    cube: '<path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M12 12l9-5M12 12L3 7M12 12v10"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 3-5.5 6.5-5.5s6.5 1.9 6.5 5.5M16 4.8a3.5 3.5 0 010 6.4M18 14.8c2.2.6 3.5 2.2 3.5 5.2"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
    ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    file: '<path d="M6 3h8l5 5v13H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/>',
    moon: '<path d="M20 14A8 8 0 1110 4a7 7 0 0010 10z"/>',
    volume: '<path d="M11 5L6 9H2v6h4l5 4zM15.5 8.5a5 5 0 010 7M19 5a10 10 0 010 14"/>',
    mute: '<path d="M11 5L6 9H2v6h4l5 4zM23 9l-6 6M17 9l6 6"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4"/>',
    refresh: '<path d="M20 11a8 8 0 00-14.5-4M4 4v4h4M4 13a8 8 0 0014.5 4M20 20v-4h-4"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>',
    download: '<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    power: '<path d="M12 3v9M6.5 6.5a8 8 0 1011 0"/>',
    link: '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
    arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    check: '<path d="M5 12l5 5 9-10"/>',
    eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    logout: '<path d="M9 4H5a2 2 0 00-2 2v12a2 2 0 002 2h4M16 8l4 4-4 4M20 12H9"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
    route: '<circle cx="5" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 6h7a3 3 0 010 6H10a3 3 0 000 6h7"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    home: '<path d="M3 11l9-8 9 8M5 10v10h14V10"/>',
    open: '<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>',
    scissors: '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M8.5 8l11 9M8.5 16l11-9"/>',
    warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>'
  };
  const icon = (name, size = 18) => {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', size); s.setAttribute('height', size); s.setAttribute('class', 'i');
    s.innerHTML = P[name] || P.cube;   // P la hang so noi bo, khong chua du lieu nguoi dung
    return s;
  };

  // ---------- Toast ----------
  function toast(msg, type = 'info', ms = 3500) {
    let box = document.getElementById('toasts');
    if (!box) { box = h('div', { id: 'toasts' }); document.body.appendChild(box); }
    const el = h('div', { class: 'toast ' + type }, msg);
    box.appendChild(el);
    setTimeout(() => el.classList.add('out'), ms - 300);
    setTimeout(() => el.remove(), ms);
  }

  // ---------- Modal ----------
  function modal({ title, body, actions = [], wide = false, onClose }) {
    const close = () => { ov.remove(); document.removeEventListener('keydown', esc); onClose && onClose(); };
    const esc = e => { if (e.key === 'Escape') close(); };
    const ov = h('div', { class: 'overlay', onclick: e => { if (e.target === ov) close(); } },
      h('div', { class: 'modal' + (wide ? ' wide' : '') },
        h('div', { class: 'mh' }, h('b', {}, title), h('button', { class: 'ib', onclick: close, 'aria-label': 'close' }, icon('x'))),
        h('div', { class: 'mb' }, body),
        actions.length ? h('div', { class: 'mf' }, actions.map(a => h('button', { class: 'btn ' + (a.primary ? 'primary' : a.danger ? 'danger' : ''), onclick: async e => { const r = a.onClick ? await a.onClick(e, close) : undefined; if (r !== false && a.close !== false) close(); } }, a.label))) : null));
    document.body.appendChild(ov); document.addEventListener('keydown', esc);
    return { close, el: ov };
  }
  const confirmBox = (msg, label = T('Xác nhận', 'Confirm'), danger = true) => new Promise(res => {
    modal({ title: T('Xác nhận', 'Confirm'), body: h('p', {}, msg), onClose: () => res(false), actions: [{ label: T('Huỷ', 'Cancel'), onClick: () => res(false) }, { label, primary: !danger, danger, onClick: () => res(true) }] });
  });

  // ---------- Dropdown tuy bien (nut xo cac lua chon, co icon) ----------
  function dropdown({ items, value = null, placeholder = '', onChange, grouped = false, width }) {
    let cur = value, openState = false;
    const btn = h('button', { type: 'button', class: 'dd-btn', onclick: e => { e.stopPropagation(); toggle(); } });
    const list = h('div', { class: 'dd-list' });
    const root = h('div', { class: 'dd', style: width ? { width } : {} }, btn, list);
    const render = () => {
      const it = items.find(i => i.value === cur);
      btn.replaceChildren(it && it.icon ? h('span', { class: 'dd-ic' }, icon(it.icon, 18)) : null,
        h('span', { class: 'dd-t' }, it ? h('span', {}, it.label, it.sub ? h('small', {}, it.sub) : null) : h('span', { class: 'mut' }, placeholder)),
        h('span', { class: 'dd-car' }, '▾'));
      list.replaceChildren();
      let lastGroup = null;
      for (const i of items) {
        if (grouped && i.group && i.group !== lastGroup) { list.appendChild(h('div', { class: 'dd-g' }, i.group)); lastGroup = i.group; }
        list.appendChild(h('div', { class: 'dd-i' + (i.value === cur ? ' on' : '') + (i.disabled ? ' dis' : ''), onclick: e => { e.stopPropagation(); if (i.disabled) return; cur = i.value; close(); render(); onChange && onChange(cur, i); } },
          i.icon ? h('span', { class: 'dd-ic' }, icon(i.icon, 18)) : null,
          h('span', { class: 'dd-t' }, i.label, i.sub ? h('small', {}, i.sub) : null),
          i.badge ? h('span', { class: 'chip ' + (i.badgeClass || '') }, i.badge) : null));
      }
    };
    const close = () => { openState = false; root.classList.remove('open'); document.removeEventListener('click', close); };
    const toggle = () => { if (openState) return close(); openState = true; root.classList.add('open'); document.addEventListener('click', close); };
    render();
    root.get = () => cur;
    root.set = v => { cur = v; render(); };
    root.setItems = (it, v) => { items = it; if (v !== undefined) cur = v; render(); };
    return root;
  }

  // ---------- Format ----------
  const pad = n => String(n).padStart(2, '0');
  const fmtTime = ts => { if (!ts) return '—'; const d = new Date(ts); return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const fmtDateTime = ts => { if (!ts) return '—'; const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  const timeAgo = ts => { if (!ts) return '—'; const s = Math.round((Date.now() - ts) / 1000); if (s < 10) return T('vừa xong', 'just now'); if (s < 60) return s + 's'; if (s < 3600) return Math.round(s / 60) + T(' phút trước', 'm ago'); if (s < 86400) return Math.round(s / 3600) + T(' giờ trước', 'h ago'); return Math.round(s / 86400) + T(' ngày trước', 'd ago'); };
  const fmtBytes = n => { n = n || 0; if (n < 1024) return n + ' B'; if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'; return (n / 1048576).toFixed(1) + ' MB'; };
  const fmtUptime = s => { if (!s) return '—'; const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + 'd ' : '') + hh + 'h ' + m + 'm'; };
  const copyText = async t => { try { await navigator.clipboard.writeText(t); toast(T('Đã sao chép', 'Copied'), 'ok', 1500); } catch { toast(T('Không sao chép được', 'Copy failed'), 'bad'); } };
  const download = (name, text, type = 'text/plain') => { const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name }); document.body.appendChild(a); a.click(); a.remove(); };

  // Form helpers
  const field = (label, input, hint) => h('label', { class: 'fld' }, h('span', {}, label), input, hint ? h('small', { class: 'mut' }, hint) : null);
  const input = (attrs = {}) => h('input', { class: 'inp', ...attrs });
  const select = (opts, value, attrs = {}) => h('select', { class: 'inp', ...attrs }, opts.map(([v, l]) => h('option', { value: v, selected: String(v) === String(value) }, l)));
  const check = (label, checked, attrs = {}) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked, ...attrs }), h('span', {}, label));
  const sevChip = s => h('span', { class: 'sev ' + String(s).toLowerCase() }, s);
  const empty = (msg, sub) => h('div', { class: 'empty' }, h('b', {}, msg), sub ? h('p', {}, sub) : null);

  window.UI = { h, icon, toast, modal, confirmBox, dropdown, T, getLang, setLang, fmtTime, fmtDateTime, timeAgo, fmtBytes, fmtUptime, copyText, download, field, input, select, check, sevChip, empty };
})();
