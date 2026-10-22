/** Sentinel IDS - Frontend core: dang nhap, dieu huong, trang thai chung, SSE realtime */
(function () {
  const { h, icon, T, toast, modal, field, input } = UI;
  const S = window.S = { me: null, policy: null, vms: [], tools: [], alerts: [], stats: null, tunnels: [], rules: [], blocklist: [], unread: 0, route: 'dashboard', sse: null, sseOk: false };
  window.Views = window.Views || {};   // moi file views/*.js tu dang ky: Views.<route> = { title, icon, admin?, render(root), onEvent?(evt,data) }

  const root = document.getElementById('root');
  const isAdmin = () => S.me && S.me.role === 'admin';
  const theme = () => localStorage.getItem('th') || 'dark';
  const setTheme = t => { localStorage.setItem('th', t); document.documentElement.setAttribute('data-theme', t); };
  setTheme(theme());

  // ================= LOGIN =================
  function showLogin(msg) {
    closeSse();
    const u = input({ autocomplete: 'username', placeholder: 'username', autofocus: true });
    const p = input({ type: 'password', autocomplete: 'current-password', placeholder: '••••••••' });
    const err = h('div', { class: 'banner bad', style: { display: msg ? 'flex' : 'none' } }, msg || '');
    const go = async () => {
      err.style.display = 'none';
      try {
        const r = await API.post('/auth/login', { username: u.value.trim(), password: p.value });
        API.setToken(r.token); await boot();
      } catch (e) { err.textContent = e.message; err.style.display = 'flex'; }
    };
    p.addEventListener('keydown', e => e.key === 'Enter' && go());
    u.addEventListener('keydown', e => e.key === 'Enter' && p.focus());
    root.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' },
      h('h1', {}, icon('shield', 26), 'Sentinel IDS'),
      h('p', { class: 'mut', style: { marginTop: 0 } }, T('Đăng nhập để vào hệ thống giám sát an ninh mạng', 'Sign in to the network security monitor')),
      err, field(T('Tên đăng nhập', 'Username'), u), field(T('Mật khẩu', 'Password'), p),
      h('button', { class: 'btn primary', style: { width: '100%', justifyContent: 'center' }, onclick: go }, T('Đăng nhập', 'Sign in')),
      h('div', { class: 'row', style: { marginTop: '14px', justifyContent: 'space-between' } },
        h('small', { class: 'mut' }, 'API: ' + API.base),
        h('button', { class: 'btn sm', onclick: () => { UI.setLang(UI.getLang() === 'vi' ? 'en' : 'vi'); showLogin(msg); } }, UI.getLang() === 'vi' ? 'English' : 'Tiếng Việt')))));
    setTimeout(() => u.focus(), 50);
  }

  function forcePasswordChange() {
    if (document.getElementById('force-pw')) return;
    const o = input({ type: 'password' }), n = input({ type: 'password' }), n2 = input({ type: 'password' });
    const err = h('div', { class: 'banner bad', style: { display: 'none' } });
    const m = modal({
      title: T('Bạn cần đổi mật khẩu để tiếp tục', 'You must change your password'),
      body: h('div', { id: 'force-pw' }, err, field(T('Mật khẩu hiện tại', 'Current password'), o), field(T('Mật khẩu mới (≥8 ký tự, có chữ và số)', 'New password (8+ chars, letters and digits)'), n), field(T('Nhập lại mật khẩu mới', 'Repeat new password'), n2)),
      onClose: () => { if (S.me && S.me.mustChangePassword) logout(); },
      actions: [{ label: T('Đổi mật khẩu', 'Change password'), primary: true, close: false, onClick: async (e, close) => {
        if (n.value !== n2.value) { err.textContent = T('Mật khẩu nhập lại không khớp', 'Passwords do not match'); err.style.display = 'flex'; return false; }
        try { const r = await API.post('/auth/change-password', { oldPassword: o.value, newPassword: n.value }); API.setToken(r.token); S.me = r.user; toast(T('Đã đổi mật khẩu', 'Password changed'), 'ok'); m.close(); await boot(); }
        catch (e2) { err.textContent = e2.message; err.style.display = 'flex'; }
        return false;
      } }]
    });
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
    ['--admin'], ['a-users', 'Quản lý User', 'Users', 'users'], ['a-vms', 'Máy ảo (VM)', 'Virtual machines', 'server'],
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
    } catch { if (S.me) setTimeout(openSse, 4000); }
  }

  // ================= BOOT =================
  async function boot() {
    if (!API.hasToken()) return showLogin();
    try {
      const me = await API.get('/auth/me');
      S.me = me.user; S.policy = me.policy;
      layout();
      if (S.me.mustChangePassword) { forcePasswordChange(); return; }
      await loadAll(); await openSse();
      if (!location.hash) location.hash = '#/dashboard';
      renderView();
    } catch (e) {
      if (e.network) { root.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' }, h('h1', {}, icon('shield', 26), 'Sentinel IDS'), h('div', { class: 'banner bad' }, e.message), h('button', { class: 'btn primary', onclick: boot }, T('Thử lại', 'Retry'))))); }
      else showLogin(e.message);
    }
  }
  API.on(() => { API.setToken(null); S.me = null; showLogin(T('Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại', 'Session expired, please sign in again')); }, forcePasswordChange);
  window.addEventListener('hashchange', () => S.me && !S.me.mustChangePassword && renderView());
  setInterval(() => { const v = window.Views[S.route]; if (S.me && v && v.tick) v.tick(); }, 1000);
  boot();
})();
