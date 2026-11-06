/**
 * reports.js — Trang "Bao cao & Thong ke".
 *
 * Cho nguoi moi:
 *  - Trang nay goi 3 API: /stats (tong hop), /top-ips, /top-signatures.
 *  - MOI: co the chon KHOANG THOI GIAN (From/To hoac nut nhanh 1h/24h/7d...).
 *    Khi co khoang, ta them ?from=..&to=.. (mili-giay) vao URL de backend chi tinh trong khoang do.
 *  - MOI: nut "Xuat PDF" dung chuc nang in cua trinh duyet (CSS @media print an thanh ben/nut).
 *  - Ve bieu do bang SVG (polyline) — nhe, khong can thu vien ngoai.
 */
(function () {
  const { h, icon, T, fmtDateTime, timeAgo, sevChip, empty, download, input } = UI;

  // Khoang thoi gian dang xem. Mac dinh: 24 gio gan nhat. null = de backend dung mac dinh (3h).
  let range = { from: Date.now() - 86400000, to: Date.now() };

  // 1 thanh ngang trong bieu do top (IP/chu ky/loai): dai theo ty le count/max
  function bar(label, count, max, cls) {
    const pct = max ? Math.round(count / max * 100) : 0;
    return h('div', { class: 'rep-row' },
      h('span', { class: 'rep-label', title: label }, label),
      h('div', { class: 'rep-bar-wrap' }, h('div', { class: 'rep-bar ' + (cls || ''), style: { width: pct + '%' } })),
      h('b', { class: 'rep-count' }, count));
  }

  // 1 the "Top N ..." gom nhieu thanh ngang.
  // title co the la chuoi HOAC mang cac phan tu (vd [icon, ' chu ...']) de khong bi loi "[object SVG...]".
  function topCard(title, items, labelKey, countKey, cls) {
    const max = items.length ? items[0][countKey] : 0;
    return h('div', { class: 'card' },
      h('h3', {}, ...(Array.isArray(title) ? title : [title])),
      items.length ? h('div', { class: 'rep-list' }, items.map(it => bar(it[labelKey], it[countKey], max, cls)))
        : empty(T('Chưa có dữ liệu', 'No data yet')));
  }

  // The MITRE ATT&CK: moi chien thuat 1 mau rieng
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
        ? h('div', { class: 'rep-list' }, entries.map(([tac, n]) => bar(tac, n, max, COLOR[tac] || '')))
        : empty(T('Chưa có ánh xạ MITRE', 'No MITRE mappings yet'), T('Cảnh báo sẽ tự động ánh xạ theo chữ ký.', 'Alerts are mapped automatically from signatures.')));
  }

  // The "Phan loai tan cong" theo type
  function typeCard(byType) {
    const entries = Object.entries(byType || {}).sort((a, b) => b[1] - a[1]);
    const max = entries.length ? entries[0][1] : 0;
    return h('div', { class: 'card' },
      h('h3', {}, T('Phân loại tấn công', 'Attack types')),
      entries.length
        ? h('div', { class: 'rep-list' }, entries.map(([type, count]) => bar(type, count, max)))
        : empty(T('Chưa có dữ liệu', 'No data yet')));
  }

  // Bieu do duong theo thoi gian (so canh bao moi moc). Ve bang SVG polyline.
  function timelineChart(tl) {
    if (!tl || !tl.length) return h('div', { class: 'mut' }, T('Không có dữ liệu', 'No data'));
    const max = Math.max(1, ...tl.map(p => p.count));
    const W = 600, H = 120;
    // Doi (index, count) -> toa do (x, y) trong khung W x H
    const pts = tl.map((p, i) => `${(i / (tl.length - 1) * W).toFixed(1)},${(H - 10 - p.count / max * (H - 20)).toFixed(1)}`).join(' ');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('class', 'chart');
    // 1 vung to nhat ben duoi + 1 duong dam ben tren
    svg.innerHTML = `<polyline points="0,${H - 10} ${pts} ${W},${H - 10}" fill="var(--acc)" fill-opacity=".15" stroke="none"/><polyline points="${pts}" fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke"/>`;
    const wrap = h('div', { style: { position: 'relative' } });
    wrap.appendChild(svg);
    // Nhan thoi gian o truc hoanh (6 moc). Neu khoang > 1 ngay thi hien NGAY/THANG, nguoc lai hien GIO:PHUT.
    const span = tl.length > 1 ? tl[tl.length - 1].t - tl[0].t : 0;
    const wide = span > 86400000;
    const pad = n => n.toString().padStart(2, '0');
    const labels = h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--mut)', marginTop: '2px' } });
    const step = Math.max(1, Math.floor(tl.length / 6));
    for (let i = 0; i < tl.length; i += step) {
      const d = new Date(tl[i].t);
      labels.appendChild(h('span', {}, wide ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : `${pad(d.getHours())}:${pad(d.getMinutes())}`));
    }
    wrap.appendChild(labels);
    return wrap;
  }

  // Xuat CSV (mo bang Excel). ﻿ o dau giup Excel hieu dung tieng Viet UTF-8.
  function csv(st) {
    const lines = ['Metric,Value'];
    lines.push('Total alerts,' + st.total);
    lines.push('Last 1h,' + st.last1h);
    lines.push('High,' + (st.bySev && st.bySev.High || 0));
    lines.push('Medium,' + (st.bySev && st.bySev.Medium || 0));
    lines.push('Low,' + (st.bySev && st.bySev.Low || 0));
    lines.push(''); lines.push('Type,Count');
    for (const [k, v] of Object.entries(st.byType || {})) lines.push(`"${k}",${v}`);
    lines.push(''); lines.push('Source IP,Count');
    for (const [k, v] of Object.entries(st.byIp || {})) lines.push(`${k},${v}`);
    return '﻿' + lines.join('\n');
  }

  // Dung noi dung IN (PDF) vao phan tu #rep. CSS @media print se an giao dien, chi in #rep.
  // Bao cao in ra bam theo KHOANG THOI GIAN dang chon.
  function buildPrintReport(st, topIps, topSigs) {
    const rep = document.getElementById('rep');
    const tbl = (head, rows) => h('table', {}, h('thead', {}, h('tr', {}, head.map(c => h('th', {}, c)))), h('tbody', {}, rows.map(r => h('tr', {}, r.map(c => h('td', {}, String(c)))))));
    rep.replaceChildren(
      h('h1', {}, 'Sentinel IDS — ' + T('Báo cáo an ninh mạng', 'Network security report')),
      h('p', {}, `${T('Khoảng', 'Range')}: ${fmtDateTime(range.from)} → ${fmtDateTime(range.to)} · ${T('Tạo lúc', 'Generated')}: ${fmtDateTime(Date.now())} · ${T('Người tạo', 'By')}: ${S.me.username}`),
      h('h2', {}, T('Tổng kết', 'Summary')), tbl(['High', 'Medium', 'Low', T('Tổng', 'Total'), T('IP riêng biệt', 'Unique IPs')],
        [[st.bySev.High || 0, st.bySev.Medium || 0, st.bySev.Low || 0, st.total, Object.keys(st.byIp || {}).length]]),
      h('h2', {}, T('Top IP tấn công', 'Top attackers')), tbl(['IP', T('Số cảnh báo', 'Alerts')], topIps.map(x => [x.ip, x.count])),
      h('h2', {}, T('Top chữ ký', 'Top signatures')), tbl([T('Chữ ký', 'Signature'), T('Số lượng', 'Count')], topSigs.map(x => [x.sig, x.count])),
      h('h2', {}, T('Loại tấn công', 'Attack types')), tbl([T('Loại', 'Type'), T('Số lượng', 'Count')], Object.entries(st.byType || {}).sort((a, b) => b[1] - a[1])),
      h('h2', {}, 'MITRE ATT&CK'), tbl([T('Chiến thuật', 'Tactic'), T('Số lượng', 'Count')], Object.entries(st.byMitreTactic || {}).sort((a, b) => b[1] - a[1])));
  }

  // Doi (ms) -> chuoi cho input datetime-local (YYYY-MM-DDTHH:mm theo gio may)
  function toLocalInput(ms) {
    const d = new Date(ms - new Date().getTimezoneOffset() * 60000);
    return d.toISOString().slice(0, 16);
  }

  let rootRef;

  // Thanh cong cu chon khoang thoi gian + xuat bao cao
  function toolbar() {
    const fromI = input({ type: 'datetime-local', value: toLocalInput(range.from) });
    const toI = input({ type: 'datetime-local', value: toLocalInput(range.to) });
    // Nut nhanh: dat khoang = X gan nhat roi ve lai
    const preset = (label, ms) => h('button', { class: 'btn sm', onclick: () => { range = { from: Date.now() - ms, to: Date.now() }; render(rootRef); } }, label);
    return h('div', { class: 'card rep-toolbar no-print', style: { marginBottom: '14px' } },
      h('div', { class: 'row', style: { alignItems: 'flex-end', flexWrap: 'wrap', gap: '8px' } },
        // Moi o gom nhan nho + o nhap; dung display:grid de o nhap co chieu cao chuan,
        // nho vay nut "Ap dung" (cung chieu cao) nam CAN GIUA theo chieu doc so voi o lich "Den".
        h('div', { style: { display: 'grid', gap: '2px' } }, h('small', { class: 'mut' }, T('Từ', 'From')), fromI),
        h('div', { style: { display: 'grid', gap: '2px' } }, h('small', { class: 'mut' }, T('Đến', 'To')), toI),
        h('button', { class: 'btn primary', onclick: () => {
          const f = new Date(fromI.value).getTime(), t = new Date(toI.value).getTime();
          if (isFinite(f) && isFinite(t) && f < t) { range = { from: f, to: t }; render(rootRef); }
        } }, icon('refresh', 14), T('Áp dụng', 'Apply')),
        h('span', { style: { width: '10px' } }),
        preset('1h', 3600000), preset('6h', 21600000), preset('24h', 86400000), preset('7 ' + T('ngày', 'days'), 604800000),
        h('button', { class: 'btn sm', onclick: () => { range = { from: Date.now() - 2592000000, to: Date.now() }; render(rootRef); } }, T('Tất cả', 'All'))));
  }

  async function render(root) {
    rootRef = root;
    // Xay chuoi query ?from=..&to=.. (don vi ms). Backend se tinh so lieu trong khoang nay.
    const qs = `?from=${range.from}&to=${range.to}`;
    const [st, topIps, topSigs] = await Promise.all([
      API.get('/stats' + qs),
      API.get('/top-ips?n=10&from=' + range.from + '&to=' + range.to),
      API.get('/top-signatures?n=10&from=' + range.from + '&to=' + range.to)
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

    // Nhan mo ta khoang thoi gian dang xem (hien o dau bao cao, in ra ca PDF)
    const rangeLabel = T('Khoảng: ', 'Range: ') + fmtDateTime(range.from) + ' → ' + fmtDateTime(range.to);

    root.replaceChildren(
      h('div', { class: 'page-h' },
        h('h2', {}, icon('file', 18), ' ', T('Báo cáo & Thống kê', 'Reports & Statistics')),
        h('span', { style: { flex: 1 } }),
        h('button', { class: 'btn no-print', onclick: () => download('sentinel-report.csv', csv(st), 'text/csv') }, icon('download', 14), T('Xuất CSV', 'Export CSV')),
        h('button', { class: 'btn no-print', onclick: () => { buildPrintReport(st, topIps.data, topSigs.data); setTimeout(() => window.print(), 50); } }, icon('file', 14), T('Xuất PDF', 'Export PDF'))),
      toolbar(),
      h('div', { class: 'mut', style: { marginBottom: '10px' } }, rangeLabel),
      h('div', { class: 'grid g4', style: { marginBottom: '14px' } },
        h('div', { class: 'card stat' }, h('b', {}, st.total), h('span', {}, T('Tổng cảnh báo', 'Total alerts'))),
        h('div', { class: 'card stat' }, h('b', {}, st.last1h), h('span', {}, T('Cảnh báo 1h qua', '1h alerts'))),
        h('div', { class: 'card stat' }, h('b', {}, st.bySev && st.bySev.High || 0), h('span', {}, 'High')),
        h('div', { class: 'card stat' }, h('b', {}, Object.keys(st.byIp || {}).length), h('span', {}, T('IP nguồn riêng biệt', 'Unique source IPs')))),
      h('div', { class: 'card', style: { marginBottom: '14px' } },
        h('h3', {}, icon('activity', 16), ' ', T('Cảnh báo theo thời gian', 'Alerts over time')),
        timelineChart(st.timeline)),
      h('div', { class: 'grid g2', style: { marginBottom: '14px' } }, sevCard, statusCard),
      h('div', { class: 'grid g2', style: { marginBottom: '14px' } },
        topCard([icon('bell', 14), ' ' + T('Top 10 chữ ký (Signature)', 'Top 10 Signatures')], topSigs.data, 'sig', 'count'),
        topCard([icon('ban', 14), ' ' + T('Top 10 IP tấn công', 'Top 10 Source IPs')], topIps.data, 'ip', 'count')),
      h('div', { class: 'grid g2' },
        typeCard(st.byType),
        mitreCard(st.byMitreTactic)));
  }

  window.Views.reports = {
    render,
    onEvent(ev) {
      // Co the tu lam moi sau moi canh bao moi (tam thoi de trong de khong gian doan khi dang xem)
    }
  };
})();
