(function () {
  const { h, icon, T, toast, modal, confirmBox, fmtTime, fmtDateTime, sevChip, dropdown, copyText, download, empty, input, select } = UI;
  let f = { ip: '', type: '', sev: '', status: '' };
  let rootEl, tbody, countEl;

  const statusLabel = s => ({ active: T('Đang xử lý', 'Active'), resolved: T('Đã giải quyết', 'Resolved'), false_positive: T('Báo động giả', 'False positive') }[s] || s);
  const filtered = () => S.alerts.filter(a => (!f.ip || a.ip.includes(f.ip) || a.dst_ip.includes(f.ip)) && (!f.type || a.type === f.type) && (!f.sev || a.sev === f.sev) && (!f.status || a.status === f.status));

  function csv(list) {
    const esc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const cols = ['id', 'ts', 'sev', 'type', 'ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'sid', 'signature', 'source', 'agent', 'status'];
    return '\uFEFF' + cols.join(',') + '\n' + list.map(a => cols.map(c => esc(c === 'ts' ? fmtDateTime(a.ts) : a[c])).join(',')).join('\n');
  }

  function detail(a) {
    const admin = S.me.role === 'admin';
    const row = (k, v) => h('tr', {}, h('td', { class: 'mut' }, k), h('td', {}, v));
    const blocked = S.blocklist.some(b => b.ip === a.ip);
    const act = [];
    if (admin) {
      act.push({ label: T('Đã giải quyết', 'Resolve'), close: false, onClick: async (e, close) => { await API.patch('/alerts/' + a.id, { status: 'resolved' }); a.status = 'resolved'; renderRows(); close(); } });
      act.push({ label: T('Báo động giả', 'False positive'), close: false, onClick: async (e, close) => { await API.patch('/alerts/' + a.id, { status: 'false_positive' }); a.status = 'false_positive'; renderRows(); close(); } });
      if (!blocked) act.push({ label: T('Chặn IP nguồn', 'Block source IP'), danger: true, close: false, onClick: async (e, close) => {
        try { const r = await API.post('/blocklist', { ip: a.ip, reason: a.type + ' (' + a.signature + ')', ruleSid: a.sid }); toast(T('Đã gửi lệnh chặn: ', 'Block sent: ') + r.status, r.status === 'applied' ? 'ok' : 'warn'); close(); } catch (er) { toast(er.message, 'bad'); }
      } });
    }
    act.push({ label: T('Tải JSON', 'Download JSON'), close: false, onClick: () => download(`alert-${a.id}.json`, JSON.stringify(a, null, 2), 'application/json') });
    act.push({ label: T('Đóng', 'Close') });
    modal({ title: `${a.type} — ${a.id}`, wide: true, actions: act, body: h('div', {},
      h('table', { class: 'tbl', style: { minWidth: 0 } }, h('tbody', {},
        row(T('Thời gian', 'Time'), fmtDateTime(a.ts)), row(T('Mức độ', 'Severity'), sevChip(a.sev)), row(T('Nguồn → Đích', 'Source → Dest'), `${a.ip}:${a.src_port || '—'} → ${a.dst_ip}:${a.dst_port || '—'} (${a.proto})`),
        row(T('Chữ ký', 'Signature'), a.signature), row('SID', a.sid || '—'), row(T('Nguồn dữ liệu', 'Data source'), `${a.source}${a.agent ? ' / ' + a.agent : ''}`), row(T('Trạng thái', 'Status'), statusLabel(a.status)))),
      h('b', {}, 'Payload / Log'), h('pre', { class: 'pl' }, a.payload || '—')) });
  }

  function renderRows() {
    const list = filtered();
    countEl.textContent = `${list.length} / ${S.alerts.length}`;
    tbody.replaceChildren(...(list.length ? list.slice(0, 300).map(a => h('tr', { class: 'click', onclick: () => detail(a) },
      h('td', {}, fmtTime(a.ts)), h('td', {}, sevChip(a.sev)), h('td', {}, a.type, h('br'), h('small', { class: 'mut' }, a.signature.slice(0, 70))),
      h('td', { class: 'mono' }, `${a.ip}${a.src_port ? ':' + a.src_port : ''}`), h('td', { class: 'mono' }, `${a.dst_ip}:${a.dst_port || '—'}`),
      h('td', {}, h('span', { class: 'chip' }, a.source)), h('td', {}, statusLabel(a.status)))) :
      [h('tr', {}, h('td', { colspan: 7 }, empty(T('Không có cảnh báo phù hợp', 'No matching alerts'), T('Chỉ hiển thị dữ liệu thật từ Suricata/Wazuh/nguồn đẩy log.', 'Only real data from Suricata/Wazuh/ingest is shown.'))))]));
  }

  async function render(root) {
    rootEl = root;
    const r = await API.get('/alerts?limit=1000'); S.alerts = r.data;
    const types = [...new Set(S.alerts.map(a => a.type))];
    const ipI = input({ placeholder: T('Lọc theo IP…', 'Filter by IP…'), value: f.ip, oninput: e => { f.ip = e.target.value.trim(); renderRows(); } });
    const mk = (key, opts) => { const s = select(opts, f[key], { onchange: e => { f[key] = e.target.value; renderRows(); } }); return s; };
    tbody = h('tbody'); countEl = h('span', { class: 'chip' });
    const admin = S.me.role === 'admin';
    root.replaceChildren(
      h('div', { class: 'page-h' }, h('h2', {}, T('Danh sách cảnh báo an ninh', 'Security alerts')), countEl, h('span', { class: 'sp', style: { flex: 1 } }),
        h('button', { class: 'btn', onclick: () => download('sentinel-alerts.csv', csv(filtered()), 'text/csv') }, icon('download', 16), 'CSV'),
        admin ? h('button', { class: 'btn danger', onclick: async () => { if (await confirmBox(T('Xoá toàn bộ cảnh báo?', 'Delete all alerts?'))) { await API.del('/alerts'); S.alerts = []; renderRows(); } } }, icon('trash', 16), T('Xoá tất cả', 'Clear all')) : null),
      h('div', { class: 'row', style: { marginBottom: '12px' } }, h('div', { style: { width: '200px' } }, ipI),
        h('div', { style: { width: '190px' } }, mk('type', [['', T('Mọi kiểu tấn công', 'All types')], ...types.map(t => [t, t])])),
        h('div', { style: { width: '150px' } }, mk('sev', [['', T('Mọi mức độ', 'All severities')], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']])),
        h('div', { style: { width: '170px' } }, mk('status', [['', T('Mọi trạng thái', 'All statuses')], ['active', statusLabel('active')], ['resolved', statusLabel('resolved')], ['false_positive', statusLabel('false_positive')]]))),
      h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Thời gian|Time', 'Mức|Level', 'Loại tấn công|Attack', 'Nguồn|Source', 'Đích|Destination', 'Nguồn log|Origin', 'Trạng thái|Status'].map(c => { const [v, e] = c.split('|'); return h('th', {}, T(v, e)); }))), tbody)));
    renderRows();
  }

  window.Views.alerts = { render, onEvent(ev) { if (['new_alert', 'alert_updated', 'cleared'].includes(ev) && tbody && document.contains(tbody)) { S.unread = 0; renderRows(); } } };
})();
