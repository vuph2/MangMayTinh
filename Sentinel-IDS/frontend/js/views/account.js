/**
 * account.js — Trang "Tai khoan cua toi".
 *  - Sua ho so (ten hien thi, email, Telegram chat ID)
 *  - Doi mat khau
 *  - Xem cac ket noi Gateway dang chay cua minh
 *
 * Luu y: trang "Bao cao" KHONG con o day nua — no da duoc tach rieng sang reports.js
 * (ban moi: co thong ke, top IP/chu ky, MITRE, chon khoang thoi gian, xuat CSV/PDF).
 */
(function () {
  const { h, icon, T, toast, field, input } = UI;

  window.Views.account = {
    async render(root) {
      const me = (await API.get('/auth/me')).user; S.me = me;                 // lay thong tin minh
      // Cac o nhap ho so
      const dn = input({ value: me.displayName || '' }), em = input({ value: me.email || '' }), tg = input({ value: me.telegramChatId || '', placeholder: T('Chat ID Telegram của bạn', 'Your Telegram chat ID') });
      const o = UI.pw(), n = UI.pw(), n2 = UI.pw(), pmsg = h('div');          // o doi mat khau (pw = co nut hien/an)
      const sessions = (await API.get('/gateway/tunnels')).filter(t => t.running);
      root.replaceChildren(
        h('div', { class: 'page-h' }, h('h2', {}, T('Tài khoản của tôi', 'My account')), h('span', { class: 'chip' }, me.role)),
        h('div', { class: 'grid g2' },
          // --- The Ho so ---
          h('div', { class: 'card' }, h('h3', {}, icon('user'), T('Hồ sơ', 'Profile')),
            field('Username', input({ value: me.username, disabled: true })), field(T('Tên hiển thị', 'Display name'), dn), field('Email', em),
            field(T('Telegram Chat ID (nhận thông báo khi kết nối bị ngắt)', 'Telegram chat ID (gets notified when a link is cut)'), tg, T('Admin phải cấu hình Bot Token trong Cài đặt hệ thống.', 'An admin must configure the Bot Token in System settings.')),
            h('button', { class: 'btn primary', onclick: async () => { try { const r = await API.patch('/auth/profile', { displayName: dn.value, email: em.value, telegramChatId: tg.value.trim() }); S.me = r.user; toast(T('Đã lưu', 'Saved'), 'ok'); } catch (e) { toast(e.message, 'bad'); } } }, T('Lưu', 'Save'))),
          // --- The Doi mat khau ---
          h('div', { class: 'card' }, h('h3', {}, icon('lock'), T('Đổi mật khẩu', 'Change password')), pmsg,
            field(T('Mật khẩu hiện tại', 'Current password'), o), field(T('Mật khẩu mới', 'New password'), n), field(T('Nhập lại', 'Repeat'), n2),
            h('button', { class: 'btn primary', onclick: async () => {
              if (n.value !== n2.value) { pmsg.className = 'banner bad'; pmsg.textContent = T('Mật khẩu nhập lại không khớp', 'Passwords differ'); return; }
              try { const r = await API.post('/auth/change-password', { oldPassword: o.value, newPassword: n.value }); API.setToken(r.token); pmsg.className = 'banner ok'; pmsg.textContent = T('Đã đổi mật khẩu', 'Password changed'); o.value = n.value = n2.value = ''; } catch (e) { pmsg.className = 'banner bad'; pmsg.textContent = e.message; }
            } }, T('Đổi mật khẩu', 'Change password')))),
        // --- Danh sach ket noi Gateway dang chay ---
        h('div', { class: 'card', style: { marginTop: '14px' } }, h('h3', {}, icon('route'), T('Kết nối Gateway đang chạy', 'Running gateway connections'), ' ', h('span', { class: 'chip' }, sessions.length)),
          sessions.length ? sessions.map(t => h('div', { class: 'mono', style: { padding: '3px 0' } }, `:${t.localPort} → ${t.vmName} → ${t.targetHost}:${t.targetPort}`)) : h('span', { class: 'mut' }, T('Không có', 'None'))));
    }
  };
})();
