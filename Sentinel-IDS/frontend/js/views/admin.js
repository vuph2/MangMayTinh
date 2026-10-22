/** Quan tri: User, May ao (VM), Cong cu Gateway, Cai dat he thong, Nhat ky */
(function () {
  const { h, icon, T, toast, modal, confirmBox, field, input, select, check, fmtDateTime, timeAgo, empty, copyText, dropdown } = UI;
  const page = (title, sub, ...extra) => h('div', { class: 'page-h' }, h('h2', {}, title), sub ? h('p', {}, sub) : null, h('span', { style: { flex: 1 } }), ...extra);
  const err = (m) => toast(m, 'bad', 6000);

  // ================= USERS =================
  async function usersView(root) {
    const list = await API.get('/users');
    const draw = async () => usersView(root);
    const rows = list.map(u => h('tr', {},
      h('td', {}, h('b', {}, u.username), h('br'), h('small', { class: 'mut' }, u.displayName || '')),
      h('td', {}, h('span', { class: 'chip ' + (u.role === 'admin' ? 'pri' : '') }, u.role)),
      h('td', {}, u.disabled ? h('span', { class: 'chip bad' }, T('Bị khoá', 'Disabled')) : u.lockedUntil > Date.now() ? h('span', { class: 'chip warn' }, T('Khoá tạm', 'Locked')) : h('span', { class: 'chip ok' }, T('Hoạt động', 'Active')), u.mustChangePassword ? h('span', { class: 'chip warn' }, T('Chờ đổi MK', 'Must change pw')) : null),
      h('td', { class: 'mono' }, (u.portPolicy.allocated || []).join(', ') || '—'), h('td', {}, u.lastLoginAt ? timeAgo(u.lastLoginAt) : '—'),
      h('td', { class: 'act' },
        h('button', { class: 'btn sm', onclick: () => userModal(u, draw) }, icon('edit', 14), T('Sửa', 'Edit')), ' ',
        h('button', { class: 'btn sm', onclick: async () => { if (!await confirmBox(T(`Đặt lại mật khẩu của ${u.username}?`, `Reset ${u.username}'s password?`), T('Đặt lại', 'Reset'), false)) return; try { const r = await API.post(`/users/${u.id}/reset-password`, {}); modal({ title: T('Mật khẩu tạm thời', 'Temporary password'), body: h('div', {}, h('p', {}, T('Chỉ hiển thị một lần. User sẽ phải đổi khi đăng nhập.', 'Shown once. The user must change it at next login.')), h('pre', { class: 'pl mono' }, r.password)), actions: [{ label: T('Sao chép', 'Copy'), close: false, onClick: () => copyText(r.password) }, { label: 'OK', primary: true }] }); } catch (e) { err(e.message); } } }, icon('key', 14)), ' ',
        u.lockedUntil > Date.now() ? h('button', { class: 'btn sm', onclick: async () => { await API.post(`/users/${u.id}/unlock`); draw(); } }, T('Mở khoá', 'Unlock')) : null, ' ',
        u.id !== S.me.id ? h('button', { class: 'btn sm', onclick: async () => { if (await confirmBox(T(`Xoá user ${u.username}? Các kết nối Gateway của họ cũng bị xoá.`, `Delete ${u.username}?`))) { try { await API.del('/users/' + u.id); draw(); } catch (e) { err(e.message); } } } }, icon('trash', 14)) : null)));
    root.replaceChildren(page(T('Quản lý tài khoản User', 'User accounts'), T('Admin tạo, khoá, đổi quyền, cấp cổng cho từng user.', 'Create, disable, change roles and allocate ports.'),
      h('button', { class: 'btn primary', onclick: () => userModal(null, draw) }, icon('plus', 14), T('Thêm user', 'Add user'))),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['User', T('Quyền', 'Role'), T('Trạng thái', 'Status'), T('Cổng cấp sẵn', 'Allocated ports'), T('Đăng nhập cuối', 'Last login'), ''].map(c => h('th', {}, c)))), h('tbody', {}, rows))));
  }

  function userModal(u, done) {
    const pol = u ? u.portPolicy : { allocated: ['8080-8089'], privateAllowed: true, privateRange: '20000-20999', maxTunnels: 5, allowCustomTarget: true };
    const un = input({ value: u ? u.username : '', disabled: !!u }), pw = input({ type: 'password', placeholder: u ? '' : T('≥8 ký tự, có chữ và số', '8+ chars, letters and digits') }), dn = input({ value: u ? u.displayName : '' }), em = input({ value: u ? u.email : '' });
    const role = select([['user', 'user'], ['admin', 'admin']], u ? u.role : 'user'), tg = input({ value: u ? u.telegramChatId : '' });
    const alloc = input({ value: (pol.allocated || []).join(', '), placeholder: '8080-8089, 9000' }), priv = check(T('Cho phép tự thêm cổng private', 'Allow private ports'), pol.privateAllowed), privR = input({ value: pol.privateRange }), max = input({ type: 'number', value: pol.maxTunnels });
    const cust = check(T('Cho phép nhập host/website tuỳ ý', 'Allow custom targets'), pol.allowCustomTarget), dis = check(T('Khoá tài khoản', 'Disable account'), u ? u.disabled : false);
    modal({ title: u ? T('Sửa user ', 'Edit user ') + u.username : T('Thêm user', 'Add user'), wide: true, body: h('div', { class: 'form-grid' },
      field('Username', un), u ? h('span') : field(T('Mật khẩu ban đầu', 'Initial password'), pw), field(T('Tên hiển thị', 'Display name'), dn), field('Email', em), field(T('Quyền', 'Role'), role), field('Telegram Chat ID', tg),
      h('div', { class: 'full' }, h('b', {}, T('Chính sách cổng', 'Port policy'))), field(T('Cổng local cấp sẵn (cách nhau bởi dấu phẩy)', 'Allocated ports (comma separated)'), alloc), field(T('Dải cổng private', 'Private range'), privR), field(T('Số kết nối tối đa', 'Max connections'), max),
      h('div', {}, priv, cust, u ? dis : null)),
      actions: [{ label: T('Huỷ', 'Cancel') }, { label: T('Lưu', 'Save'), primary: true, close: false, onClick: async (e, close) => {
        const portPolicy = { allocated: alloc.value.split(',').map(s => s.trim()).filter(Boolean), privateAllowed: priv.querySelector('input').checked, privateRange: privR.value.trim(), maxTunnels: +max.value, allowCustomTarget: cust.querySelector('input').checked };
        try {
          if (u) await API.patch('/users/' + u.id, { displayName: dn.value, email: em.value, role: role.value, telegramChatId: tg.value, disabled: dis.querySelector('input').checked, portPolicy });
          else await API.post('/users', { username: un.value.trim(), password: pw.value, displayName: dn.value, email: em.value, role: role.value, telegramChatId: tg.value, portPolicy });
          close(); toast(T('Đã lưu', 'Saved'), 'ok'); done();
        } catch (er) { err(er.message); } return false; } }] });
  }

  // ================= VMs =================
  const ROLE_INFO = { gateway: T('Máy trung gian (Gateway)', 'Gateway'), sensor: T('Sensor Suricata (đọc log)', 'Suricata sensor'), victim: T('Được bảo vệ (nhận iptables)', 'Protected (iptables)'), attacker: T('Máy tấn công (lab)', 'Attacker (lab)'), siem: 'SIEM (Wazuh…)' };
  async function vmsView(root) {
    const [list, sensors] = await Promise.all([API.get('/vms'), API.get('/sensors')]);
    S.vms = list;
    const draw = () => vmsView(root);
    const rows = list.map(v => h('tr', {},
      h('td', {}, h('span', { class: 'dot ' + (v.status === 'unknown' ? 'unk' : v.on ? '' : 'off') }), ' ', h('b', {}, v.name)), h('td', { class: 'mono' }, `${v.ip}:${v.sshPort}`), h('td', {}, v.sshUser || '—'),
      h('td', {}, (v.roles || []).map(r => h('span', { class: 'chip' }, r))),
      h('td', {}, v.cpu != null ? `CPU ${v.cpu}% · RAM ${v.mem}%` : '—', (v.roles || []).includes('sensor') ? h('div', {}, h('small', { class: 'mut' }, 'sensor: ' + ((sensors[v.id] || {}).status || '—') + ((sensors[v.id] || {}).error ? ' — ' + sensors[v.id].error : ''))) : null),
      h('td', { class: 'act' },
        h('button', { class: 'btn sm', onclick: async e => { e.target.disabled = true; try { const r = await API.post(`/vms/${v.id}/test`); toast(r.ok ? `SSH OK (${r.ms} ms)` : 'SSH: ' + r.error, r.ok ? 'ok' : 'bad', 6000); } catch (er) { err(er.message); } e.target.disabled = false; } }, T('Thử SSH', 'Test SSH')), ' ',
        h('button', { class: 'btn sm', onclick: () => vmModal(v, draw) }, icon('edit', 14)), ' ',
        h('button', { class: 'btn sm', onclick: async () => { if (await confirmBox(T(`Xoá VM ${v.name}? Mọi tunnel qua VM này sẽ bị ngắt.`, `Delete ${v.name}?`))) { try { await API.del('/vms/' + v.id); draw(); } catch (er) { err(er.message); } } } }, icon('trash', 14)))));
    root.replaceChildren(page(T('Máy ảo (VM)', 'Virtual machines'), T('Mật khẩu SSH được mã hoá AES-256-GCM, không bao giờ gửi về trình duyệt.', 'SSH secrets are AES-256-GCM encrypted and never sent to browsers.'), h('button', { class: 'btn primary', onclick: () => vmModal(null, draw) }, icon('plus', 14), T('Thêm VM', 'Add VM'))),
      list.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['VM', 'SSH', 'User', T('Vai trò', 'Roles'), T('Tình trạng', 'Health'), ''].map(c => h('th', {}, c)))), h('tbody', {}, rows))) : empty(T('Chưa có VM', 'No VMs'), T('Thêm VM của lab (Victim, Wazuh, Kali…) để bắt đầu thu thập dữ liệu thật.', 'Add your lab VMs to start collecting real data.')));
  }

  function vmModal(v, done) {
    const f = {
      name: input({ value: v ? v.name : '' }), ip: input({ value: v ? v.ip : '', placeholder: '192.168.56.102' }), sshPort: input({ type: 'number', value: v ? v.sshPort : 22 }), sshUser: input({ value: v ? v.sshUser : '' }),
      sshPass: input({ type: 'password', placeholder: v && v.hasSshPass ? T('(giữ nguyên nếu để trống)', '(unchanged if empty)') : '' }),
      sshKey: h('textarea', { class: 'inp mono', rows: 3, placeholder: v && v.hasSshKey ? T('(đã có khoá — để trống để giữ nguyên)', '(key set — leave empty to keep)') : '-----BEGIN OPENSSH PRIVATE KEY-----' }),
      sudoMode: select([['password', T('sudo cần mật khẩu', 'sudo needs password')], ['nopasswd', T('sudo không cần mật khẩu (NOPASSWD)', 'passwordless sudo')]], v ? v.sudoMode : 'password'),
      sudoPass: input({ type: 'password', placeholder: T('Trống = dùng mật khẩu SSH', 'Empty = SSH password') }), healthPort: input({ type: 'number', value: v ? v.healthPort || '' : '', placeholder: T('Trống = cổng SSH', 'Empty = SSH port') }),
      logPath: input({ value: v ? v.logPath : '/var/log/suricata/fast.log' }), os: input({ value: v ? v.os : '' }), notes: input({ value: v ? v.notes : '' })
    };
    const roles = Object.keys(ROLE_INFO).map(r => check(ROLE_INFO[r], v ? (v.roles || []).includes(r) : r === 'gateway', { 'data-role': r }));
    const en = check(T('Đang bật', 'Enabled'), v ? v.enabled : true), rk = check(T('Reset host key (khi VM cài lại)', 'Reset host key (VM reinstalled)'), false);
    modal({ title: v ? T('Sửa VM ', 'Edit VM ') + v.name : T('Thêm VM', 'Add VM'), wide: true, body: h('div', { class: 'form-grid' },
      field(T('Tên', 'Name'), f.name), field('IP / host', f.ip), field(T('Cổng SSH', 'SSH port'), f.sshPort), field(T('User SSH', 'SSH user'), f.sshUser), field(T('Mật khẩu SSH', 'SSH password'), f.sshPass), field(T('Hoặc private key', 'Or private key'), f.sshKey),
      field('sudo', f.sudoMode), field(T('Mật khẩu sudo', 'sudo password'), f.sudoPass), field(T('Cổng kiểm tra sống/chết', 'Health-check port'), f.healthPort), field(T('Đường dẫn fast.log (sensor)', 'fast.log path (sensor)'), f.logPath), field(T('Hệ điều hành', 'OS'), f.os), field(T('Ghi chú', 'Notes'), f.notes),
      h('div', { class: 'full' }, h('b', {}, T('Vai trò', 'Roles')), h('div', {}, roles)), h('div', {}, en, v ? rk : null),
      v && v.hostKey ? h('small', { class: 'mut mono full' }, 'Host key SHA256: ' + v.hostKey.slice(0, 32) + '…') : null),
      actions: [{ label: T('Huỷ', 'Cancel') }, { label: T('Lưu', 'Save'), primary: true, close: false, onClick: async (e, close) => {
        const body = { name: f.name.value, ip: f.ip.value.trim(), sshPort: +f.sshPort.value || 22, sshUser: f.sshUser.value.trim(), sshPass: f.sshPass.value, sshKey: f.sshKey.value, sudoMode: f.sudoMode.value, sudoPass: f.sudoPass.value, healthPort: +f.healthPort.value || 0, logPath: f.logPath.value, os: f.os.value, notes: f.notes.value, enabled: en.querySelector('input').checked, resetHostKey: rk.querySelector('input').checked, roles: roles.filter(c => c.querySelector('input').checked).map(c => c.querySelector('input').dataset.role) };
        try { if (v) await API.patch('/vms/' + v.id, body); else await API.post('/vms', body); close(); toast(T('Đã lưu VM', 'Saved'), 'ok'); done(); } catch (er) { err(er.message); } return false; } }] });
  }

  // ================= TOOLS =================
  async function toolsView(root) {
    const list = await API.get('/tools'); S.tools = list;
    const draw = () => toolsView(root);
    const rows = list.map(t => h('tr', {}, h('td', {}, h('span', { class: 'dd-ic', style: { display: 'inline-grid', verticalAlign: 'middle' } }, icon(t.icon, 18)), ' ', h('b', {}, t.name), t.builtin ? h('span', { class: 'chip' }, T('có sẵn', 'built-in')) : null), h('td', {}, t.category), h('td', {}, t.kind), h('td', { class: 'mono' }, t.kind === 'url' || t.kind === 'tcp' ? '—' : `${t.scheme}://…:${t.port}${t.path}`), h('td', {}, t.description),
      h('td', { class: 'act' }, check('', t.enabled, { onchange: async e => { await API.patch('/tools/' + t.id, { enabled: e.target.checked }); } }), h('button', { class: 'btn sm', onclick: () => toolModal(t, draw) }, icon('edit', 14)), ' ', !t.builtin ? h('button', { class: 'btn sm', onclick: async () => { await API.del('/tools/' + t.id); draw(); } }, icon('trash', 14)) : null)));
    root.replaceChildren(page(T('Công cụ Gateway', 'Gateway tools'), T('Wazuh và các lựa chọn miễn phí tương đương xuất hiện trong nút xổ chọn chức năng.', 'Wazuh and free alternatives appear in the tool dropdown.'), h('button', { class: 'btn primary', onclick: () => toolModal(null, draw) }, icon('plus', 14), T('Thêm công cụ', 'Add tool'))),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, [T('Công cụ', 'Tool'), T('Nhóm', 'Category'), T('Loại', 'Kind'), T('Địa chỉ mặc định', 'Default'), T('Mô tả', 'Description'), T('Bật', 'On')].map(c => h('th', {}, c)))), h('tbody', {}, rows))));
  }
  function toolModal(t, done) {
    const f = { name: input({ value: t ? t.name : '' }), description: input({ value: t ? t.description : '' }), category: select([['siem', 'SIEM/IDS'], ['monitor', 'Monitor'], ['web', 'Web'], ['remote', 'Remote'], ['other', 'Other']], t ? t.category : 'other'),
      kind: select([['web', 'web (HTTP/HTTPS)'], ['tcp', 'tcp'], ['url', 'url'], ['ssh', 'ssh']], t ? t.kind : 'web'), scheme: select([['http', 'http'], ['https', 'https']], t ? t.scheme : 'http'), port: input({ type: 'number', value: t ? t.port : 80 }), path: input({ value: t ? t.path : '/' }),
      icon: select([['server', 'server'], ['globe', 'globe'], ['terminal', 'terminal'], ['shield', 'shield'], ['chart', 'chart'], ['db', 'db'], ['bolt', 'bolt'], ['list', 'list'], ['bell', 'bell'], ['plug', 'plug'], ['cube', 'cube']], t ? t.icon : 'globe') };
    modal({ title: t ? T('Sửa công cụ', 'Edit tool') : T('Thêm công cụ', 'Add tool'), wide: true, body: h('div', { class: 'form-grid' }, field(T('Tên', 'Name'), f.name), field('Icon', f.icon), field(T('Nhóm', 'Category'), f.category), field(T('Loại', 'Kind'), f.kind), field('Scheme', f.scheme), field(T('Cổng mặc định', 'Default port'), f.port), field('Path', f.path), field(T('Mô tả', 'Description'), f.description)),
      actions: [{ label: T('Huỷ', 'Cancel') }, { label: T('Lưu', 'Save'), primary: true, close: false, onClick: async (e, close) => { const b = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value])); try { if (t) await API.patch('/tools/' + t.id, b); else await API.post('/tools', b); close(); done(); } catch (er) { err(er.message); } return false; } }] });
  }

  // ================= SYSTEM SETTINGS =================
  async function systemView(root) {
    const s = await API.get('/settings'), key = (await API.get('/settings/ingest-key')).ingestKey;
    const tg = s.telegram, w = s.wazuh, ab = s.autoBlock, inc = s.incident, g = s.gateway;
    const f = {
      tgEn: check(T('Bật gửi cảnh báo Telegram', 'Enable Telegram alerts'), tg.enabled), tgTok: input({ type: 'password', placeholder: tg.hasToken ? T('(đã lưu — để trống để giữ)', '(saved — empty to keep)') : '123456:ABC…' }), tgChat: input({ value: tg.chatId }), tgSev: select([['High', 'High'], ['Medium', 'Medium+'], ['Low', 'Low+']], tg.minSeverity),
      wEn: check(T('Bật đồng bộ cảnh báo từ Wazuh Indexer', 'Sync alerts from Wazuh Indexer'), w.enabled), wHost: input({ value: w.host, placeholder: '192.168.56.103' }), wApiPort: input({ type: 'number', value: w.apiPort }), wApiUser: input({ value: w.apiUser }), wApiPass: input({ type: 'password', placeholder: w.hasApiPass ? T('(đã lưu)', '(saved)') : '' }),
      wIdxPort: input({ type: 'number', value: w.indexerPort }), wIdxUser: input({ value: w.indexerUser }), wIdxPass: input({ type: 'password', placeholder: w.hasIndexerPass ? T('(đã lưu)', '(saved)') : '' }), wTls: check(T('Kiểm tra chứng chỉ TLS (tắt nếu Wazuh dùng chứng chỉ tự ký)', 'Verify TLS cert'), w.verifyTLS), wPoll: input({ type: 'number', value: w.pollSec }),
      abEn: check(T('Tự động chặn IP khi lặp lại nhiều lần', 'Auto-block repeat offenders'), ab.enabled), abTh: input({ type: 'number', value: ab.threshold }), abWin: input({ type: 'number', value: ab.windowSec }), abDur: input({ type: 'number', value: ab.durationSec }),
      incCut: check(T('Tự động NGẮT kết nối Gateway liên quan khi có sự cố', 'Auto-cut related gateway links on incident'), inc.autoCut), incSev: select([['High', 'High'], ['Medium', 'Medium+'], ['Low', 'Low+']], inc.minSeverity),
      gLife: input({ type: 'number', value: g.maxLifetimeMin }), gIdle: input({ type: 'number', value: g.idleMin }), gMax: input({ type: 'number', value: g.maxTunnelsPerUser }), health: input({ type: 'number', value: s.healthIntervalSec })
    };
    const v = c => c.querySelector('input').checked;
    const save = async () => {
      try {
        await API.put('/settings', {
          telegram: { enabled: v(f.tgEn), token: f.tgTok.value, chatId: f.tgChat.value, minSeverity: f.tgSev.value },
          wazuh: { enabled: v(f.wEn), host: f.wHost.value, apiPort: f.wApiPort.value, apiUser: f.wApiUser.value, apiPass: f.wApiPass.value, indexerPort: f.wIdxPort.value, indexerUser: f.wIdxUser.value, indexerPass: f.wIdxPass.value, verifyTLS: v(f.wTls), pollSec: f.wPoll.value },
          autoBlock: { enabled: v(f.abEn), threshold: f.abTh.value, windowSec: f.abWin.value, durationSec: f.abDur.value },
          incident: { autoCut: v(f.incCut), minSeverity: f.incSev.value },
          gateway: { maxLifetimeMin: f.gLife.value, idleMin: f.gIdle.value, maxTunnelsPerUser: f.gMax.value }, healthIntervalSec: f.health.value });
        toast(T('Đã lưu cài đặt', 'Settings saved'), 'ok'); systemView(root);
      } catch (e) { err(e.message); }
    };
    const ingest = `python3 eve_forwarder.py --server http://<BACKEND>:3000 --key ${key}`;
    root.replaceChildren(page(T('Cài đặt hệ thống', 'System settings'), '', h('button', { class: 'btn primary', onclick: save }, T('Lưu tất cả', 'Save all'))),
      h('div', { class: 'grid g2' },
        h('div', { class: 'card' }, h('h3', {}, 'Telegram Bot'), f.tgEn, field('Bot Token', f.tgTok), field('Chat ID (nhóm/kênh nhận cảnh báo)', f.tgChat), field(T('Mức tối thiểu', 'Min severity'), f.tgSev),
          h('button', { class: 'btn', onclick: async () => { try { await API.post('/settings/telegram-test', { token: f.tgTok.value, chatId: f.tgChat.value }); toast(T('Đã gửi tin nhắn Telegram thật', 'Real Telegram message sent'), 'ok'); } catch (e) { err(e.message); } } }, T('Gửi tin thử (thật)', 'Send real test'))),
        h('div', { class: 'card' }, h('h3', {}, 'Wazuh'), f.wEn, h('div', { class: 'form-grid' }, field('Host/IP Wazuh', f.wHost), field(T('Chu kỳ đồng bộ (giây)', 'Poll (s)'), f.wPoll), field('API port', f.wApiPort), field('API user', f.wApiUser), field('API password', f.wApiPass), field('Indexer port', f.wIdxPort), field('Indexer user', f.wIdxUser), field('Indexer password', f.wIdxPass)), f.wTls),
        h('div', { class: 'card' }, h('h3', {}, T('Xử lý sự cố', 'Incident response')), f.incCut, field(T('Ngắt khi mức ≥', 'Cut when ≥'), f.incSev), f.abEn, h('div', { class: 'form-grid' }, field(T('Ngưỡng số cảnh báo', 'Threshold'), f.abTh), field(T('Trong (giây)', 'Window (s)'), f.abWin), field(T('Chặn trong (giây, 0=vĩnh viễn)', 'Block for (s, 0=forever)'), f.abDur))),
        h('div', { class: 'card' }, h('h3', {}, 'Gateway'), h('div', { class: 'form-grid' }, field(T('Thời gian tối đa mỗi kết nối (phút, 0=không giới hạn)', 'Max lifetime (min, 0=∞)'), f.gLife), field(T('Ngắt khi rảnh (phút, 0=tắt)', 'Idle cut (min, 0=off)'), f.gIdle), field(T('Số kết nối tối đa / user', 'Max links per user'), f.gMax), field(T('Chu kỳ health-check (giây)', 'Health interval (s)'), f.health))),
        h('div', { class: 'card' }, h('h3', {}, T('Khoá đẩy log từ máy ngoài (X-Ingest-Key)', 'Ingest key')), h('pre', { class: 'pl mono' }, key), h('pre', { class: 'pl mono' }, ingest),
          h('div', { class: 'row' }, h('button', { class: 'btn sm', onclick: () => copyText(key) }, icon('copy', 14), T('Sao chép khoá', 'Copy key')), h('button', { class: 'btn sm danger', onclick: async () => { if (await confirmBox(T('Tạo khoá mới? Script cũ sẽ ngừng hoạt động.', 'New key? Old scripts will stop.'))) { await API.post('/settings/ingest-key'); systemView(root); } } }, T('Tạo khoá mới', 'Regenerate'))))));
  }

  // ================= AUDIT =================
  async function auditView(root) {
    const u = input({ placeholder: 'username' }), a = input({ placeholder: T('hành động (vd: tunnel, user, auth)', 'action prefix') });
    const body = h('tbody'), load = async () => {
      const list = await API.get(`/audit?limit=300&user=${encodeURIComponent(u.value)}&action=${encodeURIComponent(a.value)}`);
      body.replaceChildren(...list.map(e => h('tr', {}, h('td', {}, fmtDateTime(e.ts)), h('td', {}, e.username), h('td', {}, h('span', { class: 'chip' }, e.action)), h('td', {}, e.detail), h('td', { class: 'mono' }, e.ip || ''))));
    };
    u.addEventListener('change', load); a.addEventListener('change', load);
    root.replaceChildren(page(T('Nhật ký hoạt động (Audit)', 'Audit log')), h('div', { class: 'row', style: { marginBottom: '12px' } }, h('div', { style: { width: '180px' } }, u), h('div', { style: { width: '260px' } }, a), h('button', { class: 'btn', onclick: load }, icon('refresh', 14))),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, [T('Thời gian', 'Time'), 'User', T('Hành động', 'Action'), T('Chi tiết', 'Detail'), 'IP'].map(c => h('th', {}, c)))), body)));
    await load();
  }

  Object.assign(window.Views, { 'a-users': { render: usersView }, 'a-vms': { render: vmsView }, 'a-tools': { render: toolsView }, 'a-system': { render: systemView }, 'a-audit': { render: auditView } });
})();
