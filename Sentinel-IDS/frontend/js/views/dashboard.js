(function () {
  const { h, icon, T, fmtTime, fmtUptime, timeAgo, sevChip, empty } = UI;
  let rootEl = null;

  const barCls = v => v >= 85 ? 'bar hot' : v >= 60 ? 'bar mid' : 'bar';
  const meter = (label, v) => h('div', { class: 'mrow' }, h('span', { class: 'mut' }, label),
    h('div', { class: v === null || v === undefined ? 'bar' : barCls(v) }, h('i', { style: { width: (v || 0) + '%' } })),
    h('b', {}, v === null || v === undefined ? '—' : v + '%'));

  function vmCard(v) {
    const up = v.on === 1;
    return h('div', { class: 'card vm' },
      h('div', { class: 'top' }, h('span', { class: 'av' }, icon('server', 22)),
        h('div', { style: { flex: 1, minWidth: 0 } }, h('b', {}, v.name), h('br'), h('small', {}, v.ip + (v.latencyMs >= 0 && up ? ' · ' + v.latencyMs + ' ms' : ''))),
        h('span', { class: 'dot ' + (v.status === 'unknown' ? 'unk' : up ? '' : 'off'), title: v.status })),
      h('div', {}, (v.roles || []).map(r => h('span', { class: 'chip' }, r))),
      meter('CPU', up ? v.cpu : null), meter('RAM', up ? v.mem : null),
      h('small', {}, up ? `Uptime ${fmtUptime(v.uptime)} · load ${v.load || '—'}` : T('Mất kết nối', 'Disconnected') + (v.lastSeen ? ' · ' + timeAgo(v.lastSeen) : '')));
  }

  function timeline(tl) {
    const max = Math.max(1, ...tl.map(p => p.count)), W = 400, H = 100;
    const pts = tl.map((p, i) => `${(i / (tl.length - 1) * W).toFixed(1)},${(H - 8 - p.count / max * (H - 16)).toFixed(1)}`).join(' ');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('class', 'chart');
    svg.innerHTML = `<polyline points="0,${H - 8} ${pts} ${W},${H - 8}" fill="var(--acc)" fill-opacity=".15" stroke="none"/><polyline points="${pts}" fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke"/>`;
    return svg;
  }

  async function render(root) {
    rootEl = root;
    await refreshState(['stats', 'vms']);
    const st = S.stats, running = S.tunnels.filter(t => t.running).length;
    const total = st.total;
    root.replaceChildren(
      h('div', { class: 'page-h' }, h('h2', {}, T('Tổng quan hệ thống', 'System overview')), h('p', {}, T('Dữ liệu 100% thật từ máy ảo, Suricata và Wazuh', 'Live data from your VMs, Suricata and Wazuh'))),
      !S.vms.length ? h('div', { class: 'banner warn' }, icon('warn'), h('div', {}, h('b', {}, T('Chưa có máy ảo nào được đăng ký. ', 'No virtual machines registered. ')),
        S.me.role === 'admin' ? h('a', { href: '#/a-vms' }, T('Thêm VM trong Quản trị → Máy ảo', 'Add a VM in Administration → VMs')) : T('Hãy nhờ admin thêm VM.', 'Ask an admin to add a VM.'))) : null,
      h('div', { class: 'grid g4' },
        ...[[T('VM đang online', 'VMs online'), `${st.vmsOnline}/${st.vmsTotal}`], [T('Tổng cảnh báo', 'Total alerts'), total], [T('Cảnh báo 1 giờ qua', 'Alerts last hour'), st.last1h],
          [T('IP đang bị chặn', 'Blocked IPs'), st.blockedIps], [T('Kết nối Gateway', 'Active tunnels'), running]].map(([l, v]) => h('div', { class: 'card stat' }, h('b', {}, v), h('span', {}, l)))),
      h('h3', { style: { margin: '20px 0 10px' } }, T('Máy ảo', 'Virtual machines')),
      h('div', { class: 'grid g3', id: 'vmgrid' }, S.vms.map(vmCard)),
      h('div', { class: 'grid g2', style: { marginTop: '14px' } },
        h('div', { class: 'card' }, h('h3', {}, icon('activity'), T('Cảnh báo theo chu kỳ 5 phút (3 giờ qua)', 'Alerts per 5 min (last 3h)')), timeline(st.timeline)),
        h('div', { class: 'card' }, h('h3', {}, icon('bell'), T('Cảnh báo mới nhất', 'Latest alerts')),
          S.alerts.length ? h('div', { id: 'recent' }, S.alerts.slice(0, 8).map(a => h('div', { class: 'row', style: { justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--line)' } },
            h('span', {}, sevChip(a.sev), ' ', a.type), h('small', { class: 'mut' }, a.ip + ' · ' + timeAgo(a.ts))))) : empty(T('Chưa có cảnh báo nào', 'No alerts yet'), T('Cảnh báo xuất hiện khi Suricata/Wazuh phát hiện tấn công thật.', 'Alerts appear when Suricata/Wazuh detect real attacks.')))));
  }

  window.Views.dashboard = {
    render,
    onEvent(ev) {
      if (!rootEl || !document.contains(rootEl)) return;
      if (ev === 'agents_updated') { const g = document.getElementById('vmgrid'); if (g) g.replaceChildren(...S.vms.map(vmCard)); }
      if (ev === 'new_alert') { const r = document.getElementById('recent'); if (r) render(rootEl); }
    }
  };
})();
