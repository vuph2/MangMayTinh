/**
 * scenarios.js — Trang "Kich ban tan cong & Do hieu qua IDS" (CHI admin).
 *  - Chon 1 kich ban co san (Nmap, Hydra, sqlmap, hping3...) chay tu VM vai tro "attacker"
 *    nham vao may "victim" trong phong lab — de KIEM TRA xem IDS co phat hien duoc khong.
 *  - Sau khi chay, he thong tu do hieu qua: co phat hien khong, bao nhieu canh bao, do tre
 *    (latency) tu luc tan cong den luc co canh bao dau tien.
 * Day la cong cu hoc tap phong thu (blue team) — chi chay trong lab cua chinh minh.
 */
(function () {
  const { h, icon, T, toast, modal, select, fmtDateTime, empty, sevChip } = UI;
  let rootEl;

  async function render(root) {
    rootEl = root;
    if (S.me.role !== 'admin') {
      root.replaceChildren(h('div', { class: 'banner warn' }, icon('warn'), h('div', {}, T('Chức năng này chỉ dành cho Admin.', 'This feature is admin-only.'))));
      return;
    }

    const [scenarioList, histList] = await Promise.all([
      API.get('/scenarios'),
      API.get('/scenarios/history')
    ]);

    const attackers = S.vms.filter(v => (v.roles || []).includes('attacker'));
    const victims  = S.vms.filter(v => (v.roles || []).includes('victim'));

    // Form chon kich ban
    const vmSel = select(attackers.map(v => [v.id, `${v.name} (${v.ip})`]), attackers[0] && attackers[0].id);
    const scSel = select(scenarioList.map(s => [s.id, s.name]), scenarioList[0] && scenarioList[0].id);
    const targetSel = select(
      [['custom', T('Nhập thủ công…', 'Custom…')], ...victims.map(v => [v.ip, `${v.name} — ${v.ip}`])],
      victims[0] ? victims[0].ip : 'custom'
    );
    const customTarget = h('input', { class: 'inp', placeholder: '192.168.56.102', style: { display: victims.length ? 'none' : '' } });
    targetSel.addEventListener('change', () => { customTarget.style.display = targetSel.value === 'custom' ? '' : 'none'; });

    // Mo ta kich ban
    const scDesc = h('p', { class: 'mut', style: { margin: '4px 0 0' } });
    const updateDesc = () => { const sc = scenarioList.find(s => s.id === scSel.value); scDesc.textContent = sc ? sc.desc : ''; };
    scSel.addEventListener('change', updateDesc);
    updateDesc();

    // Lich su chay
    const histBody = h('tbody');
    function renderHist(list) {
      histBody.replaceChildren(...(list.length ? list.map(r => {
        const m = r.metrics || {};
        const detChip = r.done
          ? (m.detected
              ? h('span', { class: 'chip ok', title: `${m.alertCount} cảnh báo (${(m.types || []).join(', ')})` }, `✔ ${T('Phát hiện', 'Detected')} (${m.alertCount})`)
              : h('span', { class: 'chip warn' }, T('Chưa thấy cảnh báo', 'No alert')))
          : h('span', { class: 'chip mut' }, '…');

        return h('tr', { class: 'click', onclick: () => showResult(r) },
          h('td', {}, fmtDateTime(r.startAt)),
          h('td', {}, h('span', { class: 'chip' }, r.scenarioName || r.scenario)),
          h('td', { class: 'mono' }, r.target),
          h('td', {}, r.vmName || r.vmId),
          h('td', {}, r.done
            ? (r.error ? h('span', { class: 'chip bad' }, T('Lỗi', 'Error')) : h('span', { class: 'chip ok' }, 'Done'))
            : h('span', { class: 'chip warn' }, T('Đang chạy…', 'Running…'))),
          h('td', {}, detChip),
          h('td', { class: 'mut' }, r.user || ''));
      })
      : [h('tr', {}, h('td', { colspan: 7 }, empty(T('Chưa có lịch sử kịch bản', 'No scenario history yet'), T('Nhấn Chạy kịch bản để bắt đầu.', 'Click Run scenario to start.'))))]));
    }
    renderHist(histList);

    function showResult(r) {
      const m = r.metrics || {};
      modal({
        title: `${r.scenarioName || r.scenario} → ${r.target}`,
        wide: true,
        body: h('div', {},
          h('div', { class: 'row', style: { marginBottom: '12px', gap: '8px' } },
            h('span', { class: 'chip' }, T('Máy tấn công', 'Attacker') + ': ' + (r.vmName || r.vmId)),
            h('span', { class: 'chip mono' }, T('Mục tiêu', 'Target') + ': ' + r.target),
            h('span', { class: 'chip' }, T('Bắt đầu', 'Started') + ': ' + fmtDateTime(r.startAt)),
            r.endAt ? h('span', { class: 'chip' }, T('Thời gian chạy', 'Duration') + ': ' + Math.round((r.endAt - r.startAt) / 1000) + 's') : null,
            r.exitCode !== undefined ? h('span', { class: 'chip ' + (r.exitCode === 0 ? 'ok' : 'warn') }, 'Exit code: ' + r.exitCode) : null),

          // Card do hieu qua tu dong
          h('div', { class: 'card', style: { marginBottom: '14px', background: 'var(--card2)' } },
            h('h3', {}, icon('activity', 16), ' ', T('Đo hiệu quả phát hiện tự động (IDS Detection)', 'Automated IDS Detection Metrics')),
            h('div', { class: 'grid g3', style: { margin: '8px 0' } },
              h('div', { class: 'stat-mini' },
                h('b', { style: { color: m.detected ? 'var(--ok)' : 'var(--warn)' } }, m.detected ? T('ĐÃ PHÁT HIỆN', 'DETECTED') : T('CHƯA PHÁT HIỆN', 'NOT DETECTED')),
                h('span', {}, T('Trạng thái IDS', 'IDS Status'))),
              h('div', { class: 'stat-mini' },
                h('b', {}, m.alertCount || 0),
                h('span', {}, T('Số cảnh báo kích hoạt', 'Triggered alerts'))),
              h('div', { class: 'stat-mini' },
                h('b', {}, m.latencyMs != null ? m.latencyMs + ' ms' : '—'),
                h('span', {}, T('Độ trễ phát hiện', 'Detection latency')))),
            (m.types && m.types.length)
              ? h('div', { style: { marginTop: '8px', fontSize: '13px' } },
                  h('b', {}, T('Kiểu tấn công nhận diện: ', 'Identified types: ')),
                  m.types.map(t => h('span', { class: 'chip' }, t)))
              : null,
            (m.signatures && m.signatures.length)
              ? h('div', { style: { marginTop: '6px', fontSize: '13px' } },
                  h('b', {}, T('Chữ ký Suricata/Wazuh: ', 'Triggered signatures: ')),
                  m.signatures.map(s => h('span', { class: 'chip pri' }, s)))
              : null),

          h('b', {}, T('Nhật ký / Output lệnh tấn công:', 'Command output:')),
          h('pre', { class: 'pl', style: { maxHeight: '280px', overflow: 'auto' } }, r.output || '—')),
        actions: [{ label: 'OK', primary: true }]
      });
    }

    // Nut chay
    const runBtn = h('button', { class: 'btn danger', onclick: async () => {
      if (!attackers.length) { toast(T('Chưa có VM vai trò "attacker"', 'No "attacker" VM registered'), 'bad'); return; }
      const target = targetSel.value === 'custom' ? customTarget.value.trim() : targetSel.value;
      if (!target) { toast(T('Nhập IP/host mục tiêu', 'Enter target IP/host'), 'bad'); return; }
      runBtn.disabled = true;
      try {
        const { runId } = await API.post('/scenarios/run', { scenario: scSel.value, vmId: vmSel.value, target });
        toast(T('Đã khởi chạy kịch bản (ID: ', 'Scenario started (ID: ') + runId + ')', 'ok', 5000);
        // polling ket qua
        const poll = async () => {
          try {
            const status = await API.get('/scenarios/run/' + runId);
            const idx = histList.findIndex(x => x.id === runId);
            if (idx >= 0) histList[idx] = status; else histList.unshift(status);
            renderHist(histList);
            if (!status.done) {
              setTimeout(poll, 2000);
            } else {
              runBtn.disabled = false;
              // Cho 2s them de dong bo metrics roi mo hop thoai
              setTimeout(async () => {
                const refreshed = await API.get('/scenarios/run/' + runId).catch(() => status);
                showResult(refreshed);
              }, 1500);
            }
          } catch { runBtn.disabled = false; }
        };
        histList.unshift({
          id: runId, scenario: scSel.value,
          scenarioName: (scenarioList.find(s => s.id === scSel.value) || {}).name,
          target, vmId: vmSel.value,
          vmName: (attackers.find(v => v.id === vmSel.value) || {}).name,
          startAt: Date.now(), done: false, user: S.me.username,
          metrics: { detected: false, alertCount: 0 }
        });
        renderHist(histList);
        setTimeout(poll, 2000);
      } catch (e) { toast(e.message, 'bad'); runBtn.disabled = false; }
    }}, icon('bolt', 14), ' ', T('Chạy kịch bản', 'Run scenario'));

    root.replaceChildren(
      h('div', { class: 'page-h' },
        h('h2', {}, icon('bolt', 18), ' ', T('Kịch bản tấn công & Đo hiệu quả IDS (Lab)', 'Attack Scenarios & IDS Effectiveness (Lab)')),
        h('p', {}, T('Chỉ chạy trên VM có vai trò "attacker". Tự động đo lường hiệu quả phát hiện của Suricata và Wazuh.', 'Runs on "attacker" VM. Automatically measures detection rate & latency of Suricata and Wazuh.'))),
      attackers.length === 0
        ? h('div', { class: 'banner warn' }, icon('warn'), h('div', {}, T('Chưa có VM nào có vai trò "attacker". ', 'No VM with "attacker" role. '), h('a', { href: '#/a-vms' }, T('Thêm VM', 'Add VM'))))
        : null,
      h('div', { class: 'card', style: { marginBottom: '16px' } },
        h('h3', {}, T('Cấu hình kịch bản', 'Scenario configuration')),
        h('div', { class: 'form-grid' },
          h('div', {}, h('label', { class: 'lbl' }, T('VM tấn công (Attacker)', 'Attack VM')), vmSel),
          h('div', {}, h('label', { class: 'lbl' }, T('Kịch bản tấn công', 'Scenario')), scSel, scDesc),
          h('div', {}, h('label', { class: 'lbl' }, T('Mục tiêu (Victim)', 'Target (Victim)')), targetSel, customTarget)),
        h('div', { style: { marginTop: '12px' } }, runBtn,
          h('span', { class: 'mut', style: { marginLeft: '12px', fontSize: '13px' } },
            T('⚠ Chỉ dùng trong môi trường lab an toàn.', '⚠ For safe lab use only.')))),
      h('div', { class: 'card' },
        h('h3', {}, T('Lịch sử thực thi & Hiệu quả phát hiện', 'Run history & Detection metrics')),
        h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' },
          h('thead', {}, h('tr', {}, [T('Thời gian', 'Time'), T('Kịch bản', 'Scenario'), T('Mục tiêu', 'Target'), 'VM', T('Lệnh', 'Command'), T('Hiệu quả phát hiện', 'Detection'), 'User'].map(c => h('th', {}, c)))),
          histBody))));
  }

  window.Views.scenarios = window.Views['a-scenarios'] = { render };
})();
