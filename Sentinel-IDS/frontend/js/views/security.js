/** Chan IP (Active Response that) + Luat Suricata (deploy that) + Wazuh (API/Indexer that) */
(function () {
  const { h, icon, T, toast, modal, confirmBox, field, input, select, check, fmtTime, fmtDateTime, empty, sevChip, copyText, dropdown } = UI;
  const admin = () => S.me.role === 'admin';
  let secRoot, wzRoot;

  // ================= BLOCKLIST + RULES (1 trang, 2 tab) =================
  let tab = 'bl';
  const stCls = s => s === 'applied' ? 'ok' : s === 'partial' || s === 'no-enforcer' ? 'warn' : 'bad';
  const stTxt = s => ({ applied: T('Đã chặn trên VM', 'Applied on VM'), partial: T('Một phần', 'Partial'), failed: T('Thất bại', 'Failed'), 'no-enforcer': T('Chưa có VM "victim" để chặn', 'No "victim" VM to enforce') }[s] || s);

  function blTab() {
    const ipI = input({ placeholder: '192.168.56.101' }), reason = input({ placeholder: T('Lý do', 'Reason') }), dur = select([[0, T('Vĩnh viễn', 'Permanent')], [3600, '1 ' + T('giờ', 'hour')], [86400, '24 ' + T('giờ', 'hours')], [604800, '7 ' + T('ngày', 'days')]], 3600);
    const rows = S.blocklist.map(b => h('tr', {},
      h('td', { class: 'mono' }, b.ip), h('td', {}, b.reason), h('td', {}, fmtTime(b.blockedAt)), h('td', {}, b.duration ? Math.round(b.duration / 60) + ' ' + T('phút', 'min') : T('Vĩnh viễn', 'Permanent')),
      h('td', {}, h('span', { class: 'chip ' + stCls(b.status), title: (b.results || []).map(r => `${r.vm}: ${r.ok ? 'OK' : r.error}`).join('\n') }, stTxt(b.status))),
      admin() ? h('td', { class: 'act' }, h('button', { class: 'btn sm', onclick: async () => { try { await API.post(`/blocklist/${encodeURIComponent(b.ip)}/reapply`); toast(T('Đã áp dụng lại', 'Re-applied'), 'ok'); } catch (e) { toast(e.message, 'bad'); } await refreshState('blocklist'); draw(); } }, icon('refresh', 14)), ' ',
        h('button', { class: 'btn sm', onclick: async () => { try { await API.del('/blocklist/' + encodeURIComponent(b.ip)); } catch (e) { toast(e.message, 'bad'); } await refreshState('blocklist'); draw(); } }, T('Bỏ chặn', 'Unblock'))) : null));
    const script = () => S.blocklist.map(b => `sudo iptables -I INPUT -s ${b.ip} -j DROP`).join('\n');
    return h('div', {},
      admin() ? h('div', { class: 'card', style: { marginBottom: '14px' } }, h('h3', {}, icon('ban'), T('Chặn IP (chạy iptables thật trên VM có vai trò "victim")', 'Block IP (real iptables on "victim" VMs)')),
        h('div', { class: 'row' }, h('div', { style: { width: '190px' } }, ipI), h('div', { style: { flex: 1, minWidth: '160px' } }, reason), h('div', { style: { width: '140px' } }, dur),
          h('button', { class: 'btn danger', onclick: async () => { try { const r = await API.post('/blocklist', { ip: ipI.value.trim(), reason: reason.value, duration: +dur.value }); toast(stTxt(r.status), stCls(r.status) === 'ok' ? 'ok' : 'warn', 5000); await refreshState('blocklist'); draw(); } catch (e) { toast(e.message, 'bad'); } } }, icon('ban', 14), T('Chặn', 'Block')))) : null,
      S.blocklist.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['IP', T('Lý do', 'Reason'), T('Lúc', 'At'), T('Thời hạn', 'Duration'), T('Trạng thái', 'State'), admin() ? '' : null].map(c => c === null ? null : h('th', {}, c)))), h('tbody', {}, rows))) : empty(T('Chưa chặn IP nào', 'No blocked IPs')),
      S.blocklist.length ? h('div', { class: 'row', style: { marginTop: '10px' } }, h('button', { class: 'btn sm', onclick: () => copyText(script()) }, icon('copy', 14), T('Sao chép lệnh iptables', 'Copy iptables commands'))) : null);
  }

  function ruleModal(r) {
    const raw = h('textarea', { class: 'inp mono', rows: 4 }, r ? r.raw : 'alert tcp any any -> $HOME_NET 22 (msg:"Custom SSH rule"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000100; rev:1;)');
    const desc = input({ value: r ? r.desc : '' }), out = h('div');
    const val = async () => { const v = await API.post('/rules/validate', { raw: raw.value }); out.className = 'banner ' + (v.valid ? 'ok' : 'bad'); out.textContent = v.valid ? '✔ ' + T('Cú pháp hợp lệ', 'Valid syntax') : v.errors.join('; '); return v.valid; };
    modal({ title: r ? T('Sửa luật', 'Edit rule') : T('Thêm luật Suricata', 'Add Suricata rule'), wide: true, body: h('div', {}, field(T('Luật (1 dòng)', 'Rule (one line)'), raw), field(T('Mô tả', 'Description'), desc), out),
      actions: [{ label: T('Kiểm tra cú pháp', 'Validate'), close: false, onClick: val }, { label: T('Lưu', 'Save'), primary: true, close: false, onClick: async (e, close) => {
        try { if (r) await API.put('/rules/' + r.id, { raw: raw.value, desc: desc.value }); else await API.post('/rules', { raw: raw.value, desc: desc.value }); await refreshState('rules'); close(); draw(); } catch (er) { out.className = 'banner bad'; out.textContent = er.message; } return false; } }] });
  }

  function rulesTab() {
    const sensors = S.vms.filter(v => (v.roles || []).includes('sensor'));
    const vmSel = select(sensors.map(v => [v.id, `${v.name} (${v.ip})`]), sensors[0] && sensors[0].id);
    const rows = S.rules.map(r => h('tr', {}, h('td', { class: 'mono' }, r.sid), h('td', {}, r.name, h('br'), h('small', { class: 'mono mut' }, r.raw.slice(0, 90) + (r.raw.length > 90 ? '…' : ''))), h('td', {}, r.deployedAt ? fmtTime(r.deployedAt) : '—'),
      h('td', {}, admin() ? check('', r.enabled, { onchange: async e => { await API.put('/rules/' + r.id, { enabled: e.target.checked }); await refreshState('rules'); } }) : (r.enabled ? '✔' : '—')),
      admin() ? h('td', { class: 'act' }, h('button', { class: 'btn sm', onclick: () => ruleModal(r) }, icon('edit', 14)), ' ', h('button', { class: 'btn sm', onclick: async () => { if (await confirmBox(T('Xoá luật?', 'Delete rule?'))) { await API.del('/rules/' + r.id); await refreshState('rules'); draw(); } } }, icon('trash', 14))) : null));
    return h('div', {},
      admin() ? h('div', { class: 'row', style: { marginBottom: '12px' } }, h('button', { class: 'btn primary', onclick: () => ruleModal() }, icon('plus', 14), T('Thêm luật', 'Add rule')), h('span', { style: { flex: 1 } }),
        h('div', { style: { width: '220px' } }, vmSel),
        h('button', { class: 'btn', disabled: !sensors.length, onclick: async e => { e.target.disabled = true; try { const r = await API.post('/rules/deploy', { vmId: vmSel.value }); modal({ title: r.ok ? '✔ ' + T('Triển khai thành công', 'Deployed') : '✘ ' + T('Triển khai thất bại', 'Deploy failed'), body: h('div', {}, h('p', {}, `${r.vm}: ${r.count} ${T('luật đang bật', 'enabled rules')}`), h('pre', { class: 'pl' }, r.output || '—')), actions: [{ label: 'OK', primary: true }] }); await refreshState('rules'); draw(); } catch (er) { toast(er.message, 'bad', 6000); } e.target.disabled = false; } }, icon('server', 14), T('Đồng bộ luật xuống Victim (SSH + suricata -T + restart)', 'Deploy to sensor (SSH + suricata -T + restart)'))) : null,
      S.rules.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['SID', T('Luật', 'Rule'), T('Triển khai', 'Deployed'), T('Bật', 'On'), admin() ? '' : null].map(c => c === null ? null : h('th', {}, c)))), h('tbody', {}, rows))) : empty(T('Chưa có luật tuỳ chỉnh', 'No custom rules'), T('Thêm luật rồi đồng bộ xuống máy sensor.', 'Add rules and deploy them to the sensor.')));
  }

  function draw() {
    secRoot.replaceChildren(
      h('div', { class: 'page-h' }, h('h2', {}, T('Chặn IP & Luật Suricata', 'Blocklist & Suricata rules')),
        h('div', { class: 'row' }, [['bl', T('Danh sách chặn', 'Blocklist')], ['ru', T('Luật Suricata', 'Rules')]].map(([k, l]) => h('button', { class: 'btn' + (tab === k ? ' primary' : ''), onclick: () => { tab = k; draw(); } }, l)))),
      tab === 'bl' ? blTab() : rulesTab());
  }
  window.Views.security = { async render(root) { secRoot = root; await refreshState(['blocklist', 'rules', 'vms']); draw(); }, onEvent(ev) { if (['ip_blocked', 'ip_unblocked', 'rules_updated'].includes(ev) && secRoot && document.contains(secRoot) && !document.querySelector('.overlay')) draw(); } };

  // ================= WAZUH =================
  window.Views.wazuh = {
    async render(root) {
      wzRoot = root;
      const st = await API.get('/wazuh/status');
      const pill = (name, s) => h('div', { class: 'card stat' }, h('b', {}, s.ok ? '✔' : '✘'), h('span', {}, `${name}${s.version ? ' v' + s.version : ''}${s.cluster ? ' · ' + s.cluster : ''}`), s.error ? h('small', { class: 'mut', style: { display: 'block' } }, s.error) : null);
      const parts = [h('div', { class: 'page-h' }, h('h2', {}, 'Wazuh'), h('p', {}, T('Kết nối trực tiếp Wazuh API (JWT, cổng 55000) và Indexer/OpenSearch (cổng 9200).', 'Direct Wazuh API (JWT, 55000) and Indexer/OpenSearch (9200).')))];
      if (!st.configured) { parts.push(h('div', { class: 'banner warn' }, icon('warn'), h('div', {}, T('Chưa cấu hình Wazuh. ', 'Wazuh not configured. '), admin() ? h('a', { href: '#/a-system' }, T('Mở Cài đặt hệ thống', 'Open System settings')) : T('Nhờ admin cấu hình.', 'Ask an admin.')))); root.replaceChildren(...parts); return; }
      parts.push(h('div', { class: 'grid g3' }, pill('Wazuh API', st.api), pill('Wazuh Indexer', st.indexer)));
      let agents = [], alerts = [];
      if (st.api.ok) try { agents = await API.get('/wazuh/agents'); } catch (e) { parts.push(h('div', { class: 'banner bad' }, e.message)); }
      if (st.indexer.ok) try { alerts = await API.get('/wazuh/alerts?limit=50'); } catch (e) { parts.push(h('div', { class: 'banner bad' }, e.message)); }
      parts.push(h('h3', { style: { margin: '18px 0 8px' } }, 'Agents (' + agents.length + ')'),
        agents.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['ID', 'Name', 'IP', T('Trạng thái', 'Status'), 'OS', 'Version'].map(c => h('th', {}, c)))), h('tbody', {}, agents.map(a => h('tr', {}, h('td', {}, a.id), h('td', {}, a.name), h('td', { class: 'mono' }, a.ip), h('td', {}, h('span', { class: 'chip ' + (a.status === 'active' ? 'ok' : 'bad') }, a.status)), h('td', {}, a.os || '—'), h('td', {}, a.version || '—')))))) : empty(T('Không có agent', 'No agents')),
        h('h3', { style: { margin: '18px 0 8px' } }, T('Cảnh báo mới nhất từ Indexer', 'Latest alerts from Indexer')),
        alerts.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, [T('Thời gian', 'Time'), 'Level', 'Agent', T('Mô tả', 'Description'), 'IP'].map(c => h('th', {}, c)))), h('tbody', {}, alerts.map(a => h('tr', {}, h('td', {}, fmtTime(a.ts)), h('td', {}, sevChip(a.sev)), h('td', {}, a.agent), h('td', {}, a.signature), h('td', { class: 'mono' }, a.ip)))))) : empty(T('Chưa có cảnh báo', 'No alerts')));
      if (admin()) parts.push(h('div', { class: 'row', style: { marginTop: '12px' } }, h('button', { class: 'btn', onclick: async () => { await API.post('/wazuh/sync'); toast(T('Đã đồng bộ cảnh báo Wazuh vào danh sách chung', 'Wazuh alerts synced'), 'ok'); } }, icon('refresh', 14), T('Đồng bộ cảnh báo Wazuh ngay', 'Sync Wazuh alerts now'))));
      root.replaceChildren(...parts);
    }
  };
})();
