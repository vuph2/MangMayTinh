/** Tai khoan ca nhan + Bao cao (in PDF / CSV) */
(function () {
  const { h, icon, T, toast, field, input, fmtDateTime, fmtTime, download, empty } = UI;

  window.Views.account = {
    async render(root) {
      const me = (await API.get('/auth/me')).user; S.me = me;
      const dn = input({ value: me.displayName || '' }), em = input({ value: me.email || '' }), tg = input({ value: me.telegramChatId || '', placeholder: T('Chat ID Telegram của bạn', 'Your Telegram chat ID') });
      const o = input({ type: 'password' }), n = input({ type: 'password' }), n2 = input({ type: 'password' }), pmsg = h('div');
      const sessions = (await API.get('/gateway/tunnels')).filter(t => t.running);
      root.replaceChildren(
        h('div', { class: 'page-h' }, h('h2', {}, T('Tài khoản của tôi', 'My account')), h('span', { class: 'chip' }, me.role)),
        h('div', { class: 'grid g2' },
          h('div', { class: 'card' }, h('h3', {}, icon('user'), T('Hồ sơ', 'Profile')),
            field('Username', input({ value: me.username, disabled: true })), field(T('Tên hiển thị', 'Display name'), dn), field('Email', em),
            field(T('Telegram Chat ID (nhận thông báo khi kết nối bị ngắt)', 'Telegram chat ID (gets notified when a link is cut)'), tg, T('Admin phải cấu hình Bot Token trong Cài đặt hệ thống.', 'An admin must configure the Bot Token in System settings.')),
            h('button', { class: 'btn primary', onclick: async () => { try { const r = await API.patch('/auth/profile', { displayName: dn.value, email: em.value, telegramChatId: tg.value.trim() }); S.me = r.user; toast(T('Đã lưu', 'Saved'), 'ok'); } catch (e) { toast(e.message, 'bad'); } } }, T('Lưu', 'Save'))),
          h('div', { class: 'card' }, h('h3', {}, icon('lock'), T('Đổi mật khẩu', 'Change password')), pmsg,
            field(T('Mật khẩu hiện tại', 'Current password'), o), field(T('Mật khẩu mới', 'New password'), n), field(T('Nhập lại', 'Repeat'), n2),
            h('button', { class: 'btn primary', onclick: async () => {
              if (n.value !== n2.value) { pmsg.className = 'banner bad'; pmsg.textContent = T('Mật khẩu nhập lại không khớp', 'Passwords differ'); return; }
              try { const r = await API.post('/auth/change-password', { oldPassword: o.value, newPassword: n.value }); API.setToken(r.token); pmsg.className = 'banner ok'; pmsg.textContent = T('Đã đổi mật khẩu', 'Password changed'); o.value = n.value = n2.value = ''; } catch (e) { pmsg.className = 'banner bad'; pmsg.textContent = e.message; }
            } }, T('Đổi mật khẩu', 'Change password')))),
        h('div', { class: 'card', style: { marginTop: '14px' } }, h('h3', {}, icon('route'), T('Kết nối Gateway đang chạy', 'Running gateway connections'), ' ', h('span', { class: 'chip' }, sessions.length)),
          sessions.length ? sessions.map(t => h('div', { class: 'mono', style: { padding: '3px 0' } }, `:${t.localPort} → ${t.vmName} → ${t.targetHost}:${t.targetPort}`)) : h('span', { class: 'mut' }, T('Không có', 'None'))));
    }
  };

  // ================= BAO CAO =================
  const top = (arr, k, n = 5) => Object.entries(arr.reduce((m, a) => (m[a[k]] = (m[a[k]] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]).slice(0, n);

  function buildReport() {
    const A = S.alerts, rep = document.getElementById('rep');
    const sev = s => A.filter(a => a.sev === s).length;
    const tbl = (head, rows) => h('table', {}, h('thead', {}, h('tr', {}, head.map(c => h('th', {}, c)))), h('tbody', {}, rows.map(r => h('tr', {}, r.map(c => h('td', {}, String(c)))))));
    rep.replaceChildren(
      h('h1', {}, 'Sentinel IDS — ' + T('Báo cáo an ninh mạng', 'Network security report')),
      h('p', {}, `${T('Tạo lúc', 'Generated')}: ${fmtDateTime(Date.now())} · ${T('Người tạo', 'By')}: ${S.me.username}`),
      h('h2', {}, T('Tổng kết rủi ro', 'Risk summary')), tbl(['High', 'Medium', 'Low', T('Tổng', 'Total'), T('IP bị chặn', 'Blocked')], [[sev('High'), sev('Medium'), sev('Low'), A.length, S.blocklist.length]]),
      h('h2', {}, T('Top IP tấn công', 'Top attackers')), tbl(['IP', T('Số cảnh báo', 'Alerts')], top(A, 'ip')),
      h('h2', {}, T('Loại tấn công', 'Attack types')), tbl([T('Loại', 'Type'), T('Số lượng', 'Count')], top(A, 'type', 10)),
      h('h2', {}, T('Máy ảo', 'Virtual machines')), tbl(['VM', 'IP', T('Trạng thái', 'Status'), 'CPU', 'RAM'], S.vms.map(v => [v.name, v.ip, v.status, v.cpu == null ? '—' : v.cpu + '%', v.mem == null ? '—' : v.mem + '%'])),
      h('h2', {}, T('Danh sách cảnh báo (200 mới nhất)', 'Alerts (latest 200)')), tbl([T('Thời gian', 'Time'), 'Sev', T('Loại', 'Type'), T('Nguồn', 'Source'), T('Đích', 'Dest'), T('Chữ ký', 'Signature')], A.slice(0, 200).map(a => [fmtDateTime(a.ts), a.sev, a.type, a.ip, `${a.dst_ip}:${a.dst_port}`, a.signature])));
  }

  window.Views.reports = {
    async render(root) {
      const r = await API.get('/alerts?limit=1000'); S.alerts = r.data; await refreshState(['vms', 'blocklist']);
      const A = S.alerts;
      root.replaceChildren(
        h('div', { class: 'page-h' }, h('h2', {}, T('Báo cáo', 'Reports')), h('span', { style: { flex: 1 } }),
          h('button', { class: 'btn primary', onclick: () => { buildReport(); setTimeout(() => window.print(), 50); } }, icon('file', 16), T('Xuất PDF / In báo cáo', 'Export PDF / Print'))),
        h('div', { class: 'grid g4' }, ['High', 'Medium', 'Low'].map(s => h('div', { class: 'card stat' }, h('b', {}, A.filter(a => a.sev === s).length), h('span', {}, s))), h('div', { class: 'card stat' }, h('b', {}, A.length), h('span', {}, T('Tổng', 'Total')))),
        h('div', { class: 'grid g2', style: { marginTop: '14px' } },
          h('div', { class: 'card' }, h('h3', {}, T('Top IP tấn công', 'Top attackers')), A.length ? top(A, 'ip').map(([k, v]) => h('div', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', { class: 'mono' }, k), h('b', {}, v))) : empty(T('Chưa có dữ liệu', 'No data'))),
          h('div', { class: 'card' }, h('h3', {}, T('Loại tấn công', 'Attack types')), A.length ? top(A, 'type', 8).map(([k, v]) => h('div', { class: 'row', style: { justifyContent: 'space-between' } }, h('span', {}, k), h('b', {}, v))) : empty(T('Chưa có dữ liệu', 'No data'))),
        ), h('p', { class: 'mut' }, T('Báo cáo được tạo từ dữ liệu thật đang lưu trong hệ thống.', 'Reports use the real data stored in the system.')));
    }
  };
})();
