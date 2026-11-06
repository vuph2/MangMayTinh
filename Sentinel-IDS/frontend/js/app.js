/**
 * app.js — "Bo nao" cua Frontend, dieu phoi moi thu:
 *  - Dang nhap / dang ky / quen mat khau, va luu trang thai chung trong S (window.S).
 *  - Dieu huong (router): doc location.hash (vd #/reports) roi goi view tuong ung ve giao dien
 *    vao vung <main>. Moi view tu dang ky o window.Views[ten] (xem cac file views/*.js).
 *  - SSE realtime: mo 1 ket noi "luon mo" toi /api/events de nhan canh bao moi NGAY LAP TUC
 *    (khong can tai lai trang), phat am bao va cap nhat so dem.
 *  - Thanh dieu huong ben trai, doi ngon ngu (Viet/Anh), doi giao dien sang/toi.
 */
(function () {
  const { h, icon, T, toast, modal, field, input } = UI;
  const S = window.S = { me: null, policy: null, vms: [], tools: [], alerts: [], stats: null, tunnels: [], rules: [], blocklist: [], unread: 0, route: 'dashboard', sse: null, sseOk: false };
  window.Views = window.Views || {};   // moi file views/*.js tu dang ky: Views.<route> = { title, icon, admin?, render(root), onEvent?(evt,data) }

  const root = document.getElementById('root');
  const isAdmin = () => S.me && S.me.role === 'admin';
  const theme = () => localStorage.getItem('th') || 'dark';
  const setTheme = t => { localStorage.setItem('th', t); document.documentElement.setAttribute('data-theme', t); };
  setTheme(theme());

  // ================= LOGIN / REGISTER / FORGOT (cac trang nay KHONG phai hop thoai: boi den, copy/paste khong bi thoat) =================
  function authCard(subtitle, ...kids) {
    root.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' },
      h('h1', {}, icon('shield', 26), 'Sentinel IDS'),
      h('p', { class: 'mut', style: { marginTop: 0 } }, subtitle), ...kids,
      h('div', { class: 'row', style: { marginTop: '14px', justifyContent: 'space-between' } },
        h('small', { class: 'mut' }, 'API: ' + API.base),
        h('button', { class: 'btn sm', type: 'button', onclick: () => { UI.setLang(UI.getLang() === 'vi' ? 'en' : 'vi'); location.reload(); } }, UI.getLang() === 'vi' ? 'English' : 'Tiếng Việt')))));
  }
  const banner = (cls, text) => h('div', { class: 'banner ' + cls, style: { display: text ? 'flex' : 'none' } }, text || '');
  const show = (el, cls, text) => { el.className = 'banner ' + cls; el.textContent = text; el.style.display = 'flex'; };
  const wide = { width: '100%', justifyContent: 'center' };

  async function showLogin(msg) {
    closeSse();
    let allowReg = false;
    try { allowReg = (await API.get('/auth/options')).allowRegistration; } catch {}
    const u = input({ autocomplete: 'username', placeholder: 'username' });
    const p = UI.pw({ autocomplete: 'current-password', placeholder: '••••••••' });
    const err = banner('bad', msg);
    const rem = UI.check(T('Tự động đăng nhập (ghi nhớ trên máy này)', 'Keep me signed in (auto login)'), localStorage.getItem('sentinel_remember_pref') === '1');
    const remBox = rem.querySelector('input');
    const go = async () => {
      err.style.display = 'none';
      try {
        const r = await API.post('/auth/login', { username: u.value.trim(), password: p.value, remember: remBox.checked });
        localStorage.setItem('sentinel_remember_pref', remBox.checked ? '1' : '0');
        API.setToken(r.token, remBox.checked); await boot();
      }
      catch (e) { show(err, 'bad', e.message); }
    };
    p.addEventListener('keydown', e => e.key === 'Enter' && go());
    u.addEventListener('keydown', e => e.key === 'Enter' && p.focus());
    authCard(T('Đăng nhập để vào hệ thống giám sát an ninh mạng', 'Sign in to the network security monitor'), err,
      field(T('Tên đăng nhập', 'Username'), u), field(T('Mật khẩu', 'Password'), p), rem,
      h('button', { class: 'btn primary', type: 'button', style: Object.assign({ marginTop: '6px' }, wide), onclick: go }, T('Đăng nhập', 'Sign in')),
      h('div', { class: 'auth-links' }, h('a', { onclick: showForgot }, T('Quên mật khẩu?', 'Forgot password?')), allowReg ? h('a', { onclick: showRegister }, T('Đăng ký tài khoản', 'Create account')) : null));
    setTimeout(() => u.focus(), 50);
  }

  function showRegister() {
    const u = input({ autocomplete: 'username', placeholder: 'username' }), dn = input({ placeholder: T('Tên hiển thị (tuỳ chọn)', 'Display name (optional)') }), em = input({ type: 'email', placeholder: 'Email (' + T('tuỳ chọn', 'optional') + ')' });
    const p1 = UI.pw({ autocomplete: 'new-password' }), p2 = UI.pw({ autocomplete: 'new-password' });
    const msg = banner('bad', '');
    const go = async () => {
      if (p1.value !== p2.value) return show(msg, 'bad', T('Mật khẩu nhập lại không khớp', 'Passwords do not match'));
      try {
        await API.post('/auth/register', { username: u.value.trim(), password: p1.value, displayName: dn.value, email: em.value });
        authCard(T('Đăng ký thành công', 'Registration sent'), banner('ok', T('Tài khoản đã được tạo và đang CHỜ ADMIN DUYỆT. Sau khi được duyệt bạn có thể đăng nhập.', 'Your account is awaiting admin approval. You can sign in once approved.')),
          h('button', { class: 'btn primary', type: 'button', style: wide, onclick: () => showLogin() }, T('Về trang đăng nhập', 'Back to sign in')));
      } catch (e) { show(msg, 'bad', e.message); }
    };
    authCard(T('Tạo tài khoản mới (cần admin duyệt)', 'Create an account (admin approval required)'), msg,
      field(T('Tên đăng nhập', 'Username'), u, T('3-32 ký tự: chữ, số, _ . -', '3-32 chars: letters, digits, _ . -')), field(T('Tên hiển thị', 'Display name'), dn), field('Email', em),
      field(T('Mật khẩu (≥8 ký tự, có chữ và số)', 'Password (8+ chars, letters and digits)'), p1), field(T('Nhập lại mật khẩu', 'Repeat password'), p2),
      h('button', { class: 'btn primary', type: 'button', style: wide, onclick: go }, T('Đăng ký', 'Register')),
      h('div', { class: 'auth-links' }, h('a', { onclick: () => showLogin() }, '← ' + T('Về đăng nhập', 'Back to sign in'))));
  }

  function showForgot() {
    const u = input({ autocomplete: 'username', placeholder: 'username' });
    const msg = banner('ok', '');
    const go = async () => {
      try { await API.post('/auth/forgot', { username: u.value.trim() }); show(msg, 'ok', T('Nếu tài khoản tồn tại, yêu cầu đặt lại mật khẩu đã được gửi tới admin. Admin sẽ cấp mật khẩu tạm cho bạn.', 'If the account exists, a reset request was sent to the admin, who will give you a temporary password.')); }
      catch (e) { show(msg, 'bad', e.message); }
    };
    u.addEventListener('keydown', e => e.key === 'Enter' && go());
    authCard(T('Quên mật khẩu', 'Forgot password'), msg,
      h('p', { class: 'mut', style: { fontSize: '13px' } }, T('Nhập tên đăng nhập. Hệ thống không có email nên yêu cầu sẽ gửi cho admin (kèm thông báo Telegram nếu đã cấu hình).', 'Enter your username. The request goes to an admin (and Telegram if configured).')),
      field(T('Tên đăng nhập', 'Username'), u), h('button', { class: 'btn primary', type: 'button', style: wide, onclick: go }, T('Gửi yêu cầu', 'Send request')),
      h('div', { class: 'auth-links' }, h('a', { onclick: () => showLogin() }, '← ' + T('Về đăng nhập', 'Back to sign in'))));
    setTimeout(() => u.focus(), 50);
  }

  async function logout() {
    try { await API.post('/auth/logout'); } catch {}
    API.setToken(null); S.me = null; showLogin();
  }

  // ================= LAYOUT =================
  const NAV = [
    ['dashboard', 'Tổng quan', 'Overview', 'home'], ['alerts', 'Cảnh báo', 'Alerts', 'bell'],
    ['gateway', 'Cổng kết nối (Gateway)', 'Gateway', 'route'], ['ports', 'Cổng & Port', 'Ports', 'plug'],
    ['security', 'Chặn IP & Luật', 'Blocklist & Rules', 'ban'], ['wazuh', 'Wazuh', 'Wazuh', 'server'],
    ['reports', 'Báo cáo', 'Reports', 'file'], ['account', 'Tài khoản', 'Account', 'user'],
    ['--admin'], ['a-scenarios', 'Kịch bản tấn công', 'Attack Scenarios', 'bolt'], ['a-users', 'Quản lý User', 'Users', 'users'], ['a-vms', 'Máy ảo (VM)', 'Virtual machines', 'server'],
    ['a-tools', 'Công cụ Gateway', 'Gateway tools', 'cube'], ['a-system', 'Cài đặt hệ thống', 'System settings', 'gear'], ['a-audit', 'Nhật ký (Audit)', 'Audit log', 'list']
  ];

  function layout() {
    const nav = h('nav', { class: 'nav', id: 'nav' });
    NAV.forEach(n => {
      if (n[0] === '--admin') { if (isAdmin()) nav.appendChild(h('h4', {}, T('Quản trị', 'Administration'))); return; }
      if (n[0].startsWith('a-') && !isAdmin()) return;
      nav.appendChild(h('a', { href: '#/' + n[0], 'data-r': n[0] }, icon(n[3]), T(n[1], n[2]), n[0] === 'alerts' ? h('span', { class: 'bd', id: 'bd', style: { display: 'none' } }) : null));
    });
    const snd = h('button', { class: 'ib', id: 'snd', title: T('Âm thanh cảnh báo', 'Alert sound'), onclick: () => { sounds.init(); sounds.toggle(); updateSnd(); } });
    const th = h('button', { class: 'ib', title: T('Sáng/tối', 'Theme'), onclick: () => { setTheme(theme() === 'dark' ? 'light' : 'dark'); th.replaceChildren(icon(theme() === 'dark' ? 'sun' : 'moon')); } }, icon(theme() === 'dark' ? 'sun' : 'moon'));
    const lg = h('button', { class: 'btn sm', onclick: () => { UI.setLang(UI.getLang() === 'vi' ? 'en' : 'vi'); layout(); renderView(); } }, UI.getLang() === 'vi' ? 'EN' : 'VI');
    const live = h('span', { id: 'live', class: 'chip', title: 'Realtime' }, h('span', { class: 'dot unk', style: { width: '7px', height: '7px', boxShadow: 'none', marginRight: '5px' } }), 'live');
    root.replaceChildren(h('div', { class: 'app' },
      h('header', { class: 'tb' },
        h('button', { class: 'ib', onclick: () => nav.classList.toggle('show') }, icon('menu')),
        h('span', { class: 'brand' }, icon('shield', 24), 'Sentinel IDS', h('small', {}, 'Đồ án Mạng Máy Tính')),
        h('span', { class: 'sp' }), live, snd, th, lg,
        h('span', { class: 'chip', title: S.me.role }, icon('user', 12), ' ', S.me.displayName || S.me.username, ' · ', S.me.role),
        h('button', { class: 'ib', title: T('Đăng xuất', 'Sign out'), onclick: logout }, icon('logout'))),
      h('div', { class: 'body' }, nav, h('main', { class: 'main', id: 'main' }))));
    updateSnd(); updateLive(); updateBadge();
  }
  function updateSnd() { const b = document.getElementById('snd'); if (b) b.replaceChildren(icon(sounds.enabled ? 'volume' : 'mute')); }
  function updateLive() { const l = document.getElementById('live'); if (l) { l.firstChild.className = 'dot ' + (S.sseOk ? '' : 'off'); } }
  function updateBadge() { const b = document.getElementById('bd'); if (b) { b.style.display = S.unread ? '' : 'none'; b.textContent = S.unread > 99 ? '99+' : S.unread; } }

  function route() { return (location.hash.replace(/^#\//, '') || 'dashboard').split('?')[0]; }
  async function renderView() {
    const r = route();
    const view = window.Views[r === 'wazuh' ? 'wazuh' : r];
    const main = document.getElementById('main');
    if (!main) return;
    S.route = r;
    document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.r === r));
    document.getElementById('nav').classList.remove('show');
    if (!view || (r.startsWith('a-') && !isAdmin())) { main.replaceChildren(UI.empty(T('Không tìm thấy trang', 'Page not found'))); return; }
    if (r === 'alerts') { S.unread = 0; updateBadge(); }
    main.replaceChildren(h('div', { class: 'mut' }, T('Đang tải…', 'Loading…')));
    try { await view.render(main); } catch (e) { main.replaceChildren(h('div', { class: 'banner bad' }, icon('warn'), e.message)); }
  }

  // ================= DATA + REALTIME =================
  async function loadAll() {
    const [vms, tools, tunnels, alerts, stats, rules, bl] = await Promise.all([
      API.get('/vms'), API.get('/tools'), API.get('/gateway/tunnels'), API.get('/alerts?limit=1000'), API.get('/stats'), API.get('/rules'), API.get('/blocklist')]);
    Object.assign(S, { vms, tools, tunnels, alerts: alerts.data, stats, rules, blocklist: bl });
  }
  window.refreshState = async (which) => {
    const map = { vms: ['/vms', 'vms'], tools: ['/tools', 'tools'], tunnels: ['/gateway/tunnels', 'tunnels'], rules: ['/rules', 'rules'], blocklist: ['/blocklist', 'blocklist'], stats: ['/stats', 'stats'] };
    for (const k of [].concat(which)) { const [p, key] = map[k]; S[key] = await API.get(p); }
  };

  function closeSse() { if (S.sse) { S.sse.close(); S.sse = null; } S.sseOk = false; }
  async function openSse() {
    closeSse();
    try {
      const t = await API.ticket();
      const es = new EventSource(`${API.base}/events?ticket=${encodeURIComponent(t)}`);
      S.sse = es;
      es.onopen = () => { S.sseOk = true; updateLive(); };
      es.onerror = () => { S.sseOk = false; updateLive(); es.close(); if (S.me) setTimeout(openSse, 3000); };   // ve chi dung 1 lan -> xin ve moi
      const on = (ev, fn) => es.addEventListener(ev, e => { let d = {}; try { d = JSON.parse(e.data); } catch {} fn(d); const v = window.Views[S.route]; v && v.onEvent && v.onEvent(ev, d); });
      on('new_alert', a => { S.alerts.unshift(a); if (S.alerts.length > 1000) S.alerts.pop(); if (S.stats) { S.stats.total++; S.stats.last1h++; } if (S.route !== 'alerts') { S.unread++; updateBadge(); } sounds.init(); sounds.playAlert(a.sev); if (a.sev === 'High') toast('🚨 ' + a.type + ' — ' + a.ip, 'bad', 5000); });
      on('alert_updated', a => { const i = S.alerts.findIndex(x => x.id === a.id); if (i >= 0) S.alerts[i] = a; });
      on('cleared', () => { S.alerts = []; });
      on('agents_updated', list => { S.vms = S.vms.map(v => { const n = list.find(x => x.id === v.id); return n ? { ...v, ...n } : v; }); for (const n of list) if (!S.vms.find(v => v.id === n.id)) S.vms.push(n); });
      on('vm_down', d => toast(T('VM mất kết nối: ', 'VM down: ') + d.name, 'warn', 5000));
      on('tunnel_state', t => { const i = S.tunnels.findIndex(x => x.id === t.id); if (i >= 0) S.tunnels[i] = t; else S.tunnels.unshift(t); });
      on('tunnel_removed', d => { S.tunnels = S.tunnels.filter(t => t.id !== d.id); });
      on('gateway_cut', d => { sounds.init(); sounds.playAlert('High'); toast('🔌 ' + d.message, 'bad', 9000); });
      on('ip_blocked', e => { S.blocklist = [e, ...S.blocklist.filter(b => b.ip !== e.ip)]; });
      on('ip_unblocked', e => { S.blocklist = S.blocklist.filter(b => b.ip !== e.ip); });
      on('rules_updated', r => { S.rules = r; });
      on('user_pending', d => toast('🆕 ' + T('Tài khoản chờ duyệt: ', 'Account awaiting approval: ') + d.username, 'warn', 7000));
      on('reset_requested', d => toast('🔑 ' + d.username + T(' yêu cầu đặt lại mật khẩu', ' requested a password reset'), 'warn', 7000));
    } catch { if (S.me) setTimeout(openSse, 4000); }
  }

  // ================= BOOT =================
  async function boot() {
    if (!API.hasToken()) return showLogin();
    try {
      const me = await API.get('/auth/me');
      S.me = me.user; S.policy = me.policy;
      layout();
      await loadAll(); await openSse();
      if (!location.hash) location.hash = '#/dashboard';
      renderView();
    } catch (e) {
      if (e.network) { root.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' }, h('h1', {}, icon('shield', 26), 'Sentinel IDS'), h('div', { class: 'banner bad' }, e.message), h('button', { class: 'btn primary', onclick: boot }, T('Thử lại', 'Retry'))))); }
      else showLogin(e.message);
    }
  }
  API.on(() => { API.setToken(null); S.me = null; showLogin(T('Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại', 'Session expired, please sign in again')); }, () => {});
  window.addEventListener('hashchange', () => S.me && renderView());
  setInterval(() => { const v = window.Views[S.route]; if (S.me && v && v.tick) v.tick(); }, 1000);
  boot();
})();
