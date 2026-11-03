/** Bao cao: Top IP, Top chu ky, Top loai tan cong, MITRE ATT&CK, duong thoi gian */
(function () {
  const { h, icon, T, fmtDateTime, timeAgo, sevChip, empty, download } = UI;

  function bar(label, count, max, cls) {
    const pct = max ? Math.round(count / max * 100) : 0;
    return h('div', { class: 'rep-row' },
      h('span', { class: 'rep-label', title: label }, label),
      h('div', { class: 'rep-bar-wrap' }, h('div', { class: 'rep-bar ' + (cls || ''), style: { width: pct + '%' } })),
      h('b', { class: 'rep-count' }, count));
  }

  function topCard(title, items, labelKey, countKey, cls) {
    const max = items.length ? items[0][countKey] : 0;
    return h('div', { class: 'card' },
      h('h3', {}, title),
      items.length ? h('div', { class: 'rep-list' }, items.map(it => bar(it[labelKey], it[countKey], max, cls)))
        : empty(T('Chưa có dữ liệu', 'No data yet')));
  }

  function mitreCard(byMitreTactic) {
    const entries = Object.entries(byMitreTactic || {}).sort((a, b) => b[1] - a[1]);
    const max = entries.length ? entries[0][1] : 0;
    const COLOR = {
      'Reconnaissance': 'mitre-re', 'Credential Access': 'mitre-ca', 'Initial Access': 'mitre-ia',
      'Impact': 'mitre-im', 'Discovery': 'mitre-di', 'Execution': 'mitre-ex',
      'Privilege Escalation': 'mitre-pe', 'Lateral Movement': 'mitre-lm'
    };
    return h('div', { class: 'card' },
      h('h3', {}, icon('shield', 16), ' MITRE ATT&CK — ', T('Chiến thuật phát hiện', 'Detected Tactics')),
      entries.length
        ? h('div', { class: 'rep-list' }, entries.map(([tactic, count]) => bar(tactic, count, max, COLOR[tactic] || '')))
        : empty(T('Chưa có ánh xạ MITRE', 'No MITRE mappings yet'), T('Cảnh báo sẽ tự động ánh xạ theo chữ ký.', 'Alerts are mapped automatically from signatures.')));
  }

  function typeCard(byType) {
    const entries = Object.entries(byType || {}).sort((a, b) => b[1] - a[1]);
    const max = entries.length ? entries[0][1] : 0;
    return h('div', { class: 'card' },
      h('h3', {}, T('Phân loại tấn công', 'Attack types')),
      entries.length
        ? h('div', { class: 'rep-list' }, entries.map(([type, count]) => bar(type, count, max)))
        : empty(T('Chưa có dữ liệu', 'No data yet')));
  }

  function timelineChart(tl) {
    if (!tl || !tl.length) return h('div', { class: 'mut' }, T('Không có dữ liệu', 'No data'));
    const max = Math.max(1, ...tl.map(p => p.count));
    const W = 600, H = 120;
    const pts = tl.map((p, i) => `${(i / (tl.length - 1) * W).toFixed(1)},${(H - 10 - p.count / max * (H - 20)).toFixed(1)}`).join(' ');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('class', 'chart');
    svg.innerHTML = `<polyline points="0,${H - 10} ${pts} ${W},${H - 10}" fill="var(--acc)" fill-opacity=".15" stroke="none"/><polyline points="${pts}" fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke"/>`;
    // Them nhan thoi gian
    const wrap = h('div', { style: { position: 'relative' } });
    wrap.appendChild(svg);
    const labels = h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--mut)', marginTop: '2px' } });
    const step = Math.floor(tl.length / 6);
    for (let i = 0; i < tl.length; i += step) {
      const d = new Date(tl[i].t);
      labels.appendChild(h('span', {}, `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`));
    }
    wrap.appendChild(labels);
    return wrap;
  }

  function csv(st) {
    const lines = ['Metric,Value'];
    lines.push('Total alerts,' + st.total);
    lines.push('Last 1h,' + st.last1h);
    lines.push('High,' + (st.bySev && st.bySev.High || 0));
    lines.push('Medium,' + (st.bySev && st.bySev.Medium || 0));
    lines.push('Low,' + (st.bySev && st.bySev.Low || 0));
    lines.push('');
    lines.push('Type,Count');
    for (const [k, v] of Object.entries(st.byType || {})) lines.push(`"${k}",${v}`);
    lines.push('');
    lines.push('Source IP,Count');
    for (const [k, v] of Object.entries(st.byIp || {})) lines.push(`${k},${v}`);
    return '\uFEFF' + lines.join('\n');
  }

  async function render(root) {
    const [st, topIps, topSigs] = await Promise.all([
      API.get('/stats'),
      API.get('/top-ips?n=10'),
      API.get('/top-signatures?n=10')
    ]);
    S.stats = st;

    const sevCard = h('div', { class: 'card' },
      h('h3', {}, T('Mức độ nghiêm trọng', 'Severity breakdown')),
      h('div', { class: 'grid g3', style: { marginTop: '8px' } },
        ...['High', 'Medium', 'Low'].map(s => h('div', { class: 'stat-mini' }, h('b', { style: { color: s === 'High' ? 'var(--bad)' : s === 'Medium' ? 'var(--warn)' : 'var(--ok)' } }, st.bySev[s] || 0), h('span', {}, s)))));

    const statusCard = h('div', { class: 'card' },
      h('h3', {}, T('Trạng thái xử lý', 'Alert status')),
      h('div', { class: 'grid g3', style: { marginTop: '8px' } },
        ...Object.entries(st.byStatus || {}).map(([s, n]) => h('div', { class: 'stat-mini' }, h('b', {}, n), h('span', {}, s)))));

    root.replaceChildren(
      h('div', { class: 'page-h' },
        h('h2', {}, icon('file', 18), ' ', T('Báo cáo & Thống kê', 'Reports & Statistics')),
        h('span', { style: { flex: 1 } }),
        h('button', { class: 'btn', onclick: () => download('sentinel-report.csv', csv(st), 'text/csv') }, icon('download', 14), T('Xuất CSV', 'Export CSV'))),
      h('div', { class: 'grid g4', style: { marginBottom: '14px' } },
        h('div', { class: 'card stat' }, h('b', {}, st.total), h('span', {}, T('Tổng cảnh báo', 'Total alerts'))),
        h('div', { class: 'card stat' }, h('b', {}, st.last1h), h('span', {}, T('Cảnh báo 1h qua', '1h alerts'))),
        h('div', { class: 'card stat' }, h('b', {}, st.bySev && st.bySev.High || 0), h('span', {}, 'High')),
        h('div', { class: 'card stat' }, h('b', {}, Object.keys(st.byIp || {}).length), h('span', {}, T('IP nguồn riêng biệt', 'Unique source IPs')))),
      h('div', { class: 'card', style: { marginBottom: '14px' } },
        h('h3', {}, icon('activity', 16), ' ', T('Cảnh báo theo chu kỳ 5 phút (3 giờ qua)', 'Alerts per 5 min (last 3h)')),
        timelineChart(st.timeline)),
      h('div', { class: 'grid g2', style: { marginBottom: '14px' } }, sevCard, statusCard),
      h('div', { class: 'grid g2', style: { marginBottom: '14px' } },
        topCard(icon('bell', 14) + ' ' + T('Top 10 chữ ký (Signature)', 'Top 10 Signatures'), topSigs.data, 'sig', 'count'),
        topCard(icon('ban', 14) + ' ' + T('Top 10 IP tấn công', 'Top 10 Source IPs'), topIps.data, 'ip', 'count')),
      h('div', { class: 'grid g2' },
        typeCard(st.byType),
        mitreCard(st.byMitreTactic)));
  }

  window.Views.reports = {
    render,
    onEvent(ev) {
      // tu dong lam moi sau moi canh bao moi (neu dang xem trang nay)
    }
  };
})();

