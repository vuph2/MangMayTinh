/**
 * Gateway: User -> [Chuc nang/Tool] -> [May ao trung gian] -> [Website/Duong link/Dich vu]
 * Dich chi nhin thay IP cua may ao. Khi co su co, ket noi bi ngat TAI may ao va user duoc thong bao.
 */
(function () {
  const { h, icon, T, toast, modal, confirmBox, dropdown, field, input, fmtBytes, copyText, empty } = UI;
  const CAT = { siem: ['SIEM / IDS (Wazuh & lựa chọn miễn phí)', 'SIEM / IDS (Wazuh & free alternatives)'], monitor: ['Giám sát hạ tầng', 'Infrastructure monitoring'], web: ['Website / Link', 'Websites / Links'], remote: ['Truy cập từ xa', 'Remote access'], other: ['Khác', 'Other'] };
  const ORDER = ['siem', 'monitor', 'remote', 'web', 'other'];
  let st = { tool: null, vmId: null, port: 'auto', privatePort: '', probe: null };
  let listEl, pathEl, formEl, rootEl;

  const gwVms = () => S.vms.filter(v => v.gateway && v.enabled);
  const toolById = id => S.tools.find(t => t.id === id);
  const parseRanges = list => (list || []).map(x => String(x).match(/^(\d+)(?:-(\d+))?$/)).filter(Boolean).map(m => [+m[1], +(m[2] || m[1])]);
  const openUrl = t => `${t.scheme === 'https' ? 'https' : 'http'}://${API.host}:${t.localPort}${t.path || '/'}`;

  function freeAllocated() {
    const used = new Set(S.tunnels.map(t => t.localPort)), out = [];
    for (const [a, b] of parseRanges((S.policy || {}).allocated)) for (let p = Math.max(a, 1024); p <= b && out.length < 30; p++) if (!used.has(p)) out.push(p);
    return out;
  }

  // ---------- Duong di truc quan ----------
  function pathView(opts = {}) {
    const tool = st.tool, vm = S.vms.find(v => v.id === st.vmId);
    const node = (cls, ic, title, sub) => h('div', { class: 'node ' + cls }, h('div', { class: 'ic' }, icon(ic, 24)), h('b', {}, title), h('small', {}, sub || ''));
    const link = (txt, hid) => h('div', { class: 'link' + (hid ? ' hid' : '') }, h('span', {}, txt));
    const target = (st.target && st.target.trim()) || (vm ? vm.ip : '…');
    return h('div', { class: 'path' + (opts.live ? ' live' : '') + (opts.cut ? ' cut' : '') },
      node('you', 'user', T('Bạn', 'You'), T('IP được ẩn', 'IP hidden')), link(':' + (st.port === 'auto' ? 'auto' : st.port === 'private' ? (st.privatePort || '?') : st.port), true),
      node('', tool ? tool.icon : 'cube', tool ? tool.name : T('Chức năng', 'Tool'), tool ? (tool.kind === 'ssh' ? 'SSH' : tool.scheme.toUpperCase()) : ''),
      link('SSH', false), node('', 'server', vm ? vm.name : T('Máy ảo trung gian', 'Gateway VM'), vm ? vm.ip : ''),
      link(T('đầu ra', 'egress'), false), node('', tool && (tool.kind === 'url') ? 'globe' : 'globe', T('Đích', 'Target'), target));
  }

  // ---------- Form ----------
  function buildForm() {
    const tools = S.tools.filter(t => t.enabled);
    const toolDd = dropdown({
      grouped: true, placeholder: T('Chọn chức năng…', 'Choose a tool…'), value: st.tool && st.tool.id,
      items: tools.map(t => ({ value: t.id, label: t.name, sub: t.description, icon: t.icon, cat: t.category, group: T(...(CAT[t.category] || CAT.other)) })).sort((a, b) => ORDER.indexOf(a.cat) - ORDER.indexOf(b.cat)),
      onChange: id => { st.tool = toolById(id); st.target = ''; st.probe = null; refresh(); }
    });
    const vmItems = gwVms().map(v => ({ value: v.id, label: v.name, sub: v.ip, icon: 'server', badge: v.on ? 'online' : 'offline', badgeClass: v.on ? 'ok' : 'bad' }));
    const vmDd = dropdown({ items: vmItems, value: st.vmId, placeholder: gwVms().length ? T('Chọn máy ảo trung gian…', 'Choose gateway VM…') : T('Chưa có VM gateway', 'No gateway VM'), onChange: id => { st.vmId = id; st.probe = null; refresh(); } });

    const tool = st.tool;
    const hostI = input({ placeholder: T('Mặc định: IP của VM', 'Default: VM IP'), value: st.host || '', oninput: e => { st.host = e.target.value; st.target = e.target.value; pathUpdate(); } });
    const portI = input({ type: 'number', min: 1, max: 65535, value: st.tport || (tool && tool.port) || '', oninput: e => { st.tport = e.target.value; } });
    const urlI = input({ placeholder: 'https://example.com/path', value: st.url || '', oninput: e => { st.url = e.target.value; try { st.target = new URL(e.target.value).hostname; } catch { st.target = ''; } pathUpdate(); } });
    const userI = input({ placeholder: T('Tài khoản trên máy đích', 'Username on target'), value: st.user || '', oninput: e => { st.user = e.target.value; } });
    const passI = input({ type: 'password', placeholder: T('Mật khẩu máy đích', 'Target password'), oninput: e => { st.pass = e.target.value; } });

    // Cong local
    const free = freeAllocated();
    const portItems = [{ value: 'auto', label: T('Tự động (cổng cấp sẵn còn trống)', 'Auto (free allocated port)'), icon: 'plug' },
      ...free.slice(0, 12).map(p => ({ value: String(p), label: ':' + p, sub: T('cổng cấp sẵn', 'allocated port'), icon: 'plug' })),
      ...((S.policy && (S.policy.privateAllowed || S.policy.admin)) ? [{ value: 'private', label: T('Cổng private (tự nhập)…', 'Private port (custom)…'), sub: (S.policy.privateRange || ''), icon: 'lock' }] : [])];
    const portDd = dropdown({ items: portItems, value: st.port === 'auto' || st.port === 'private' ? st.port : String(st.port), onChange: v => { st.port = v === 'auto' || v === 'private' ? v : +v; refresh(); } });
    const privI = input({ type: 'number', placeholder: T('Cổng private', 'Private port'), value: st.privatePort, oninput: e => { st.privatePort = e.target.value; pathUpdate(); } });
    const privMsg = h('small', { class: 'mut' });
    const privBtn = h('button', { class: 'btn sm', onclick: async () => { try { const r = await API.get('/ports/check?port=' + encodeURIComponent(st.privatePort)); privMsg.textContent = r.allowed && r.free ? '✔ ' + T('Cổng dùng được', 'Port available') : '✘ ' + r.reason; } catch (e) { privMsg.textContent = e.message; } } }, T('Kiểm tra', 'Check'));

    const targetFields = !tool ? null : tool.kind === 'url' ? field(T('Website / đường link', 'Website / link'), urlI, T('VM sẽ là bên truy cập website này; website không thấy IP của bạn.', 'The VM visits the site; the site never sees your IP.'))
      : h('div', { class: 'form-grid' }, field(T('Host đích', 'Target host'), hostI, T('Để trống = chính VM trung gian', 'Empty = the gateway VM itself')), field(T('Cổng đích', 'Target port'), portI));

    const probeMsg = h('div', { id: 'probe-msg', class: st.probe ? 'banner ' + (st.probe.open ? 'ok' : 'bad') : '', style: { display: st.probe ? 'flex' : 'none' } },
      st.probe ? (st.probe.open ? `✔ ${T('Từ VM tới đích: MỞ', 'From VM to target: OPEN')} (${st.probe.latencyMs} ms)` : `✘ ${T('Từ VM không tới được đích', 'VM cannot reach target')}: ${st.probe.error || ''}`) : '');

    const getTarget = () => {
      if (tool.kind === 'url') return { url: st.url };
      return { targetHost: (st.host || '').trim(), targetPort: +(st.tport || tool.port) };
    };

    const probeBtn = h('button', { class: 'btn', disabled: !tool || !st.vmId || tool.kind === 'url', onclick: async () => {
      const t = getTarget();
      try { st.probe = await API.post('/gateway/probe', { vmId: st.vmId, host: t.targetHost || undefined, port: t.targetPort }); } catch (e) { st.probe = { open: false, error: e.message, latencyMs: 0 }; }
      refresh();
    } }, icon('activity', 16), T('Kiểm tra đích qua VM', 'Test target via VM'));

    let openBtn;
    if (tool && tool.kind === 'ssh') {
      openBtn = h('button', { class: 'btn primary', disabled: !st.vmId, onclick: () => openTerminal({ vmId: st.vmId, targetHost: (st.host || '').trim(), targetPort: +(st.tport || 22), username: st.user, password: st.pass }) }, icon('terminal', 16), T('Mở SSH Terminal', 'Open SSH terminal'));
    } else {
      openBtn = h('button', { class: 'btn primary', disabled: !tool || !st.vmId, onclick: async () => {
        const body = { toolId: tool.id, vmId: st.vmId, ...getTarget() };
        if (st.port === 'private') body.localPort = +st.privatePort; else if (st.port !== 'auto') body.localPort = +st.port;
        try {
          const t = await API.post('/gateway/tunnels', body);
          await refreshState('tunnels'); toast(T('Đã mở kết nối qua VM, cổng ', 'Tunnel up, port ') + t.localPort, 'ok'); refresh();
          if (tool.kind !== 'tcp') window.open(openUrl(t), '_blank', 'noopener');
        } catch (e) { toast(e.message, 'bad', 6000); }
      } }, icon('power', 16), T('Mở kết nối', 'Open connection'));
    }

    return h('div', { class: 'card' },
      h('h3', {}, icon('route'), T('Tạo kết nối mới', 'New connection')),
      h('div', { class: 'form-grid' }, field('1. ' + T('Chức năng', 'Tool'), toolDd), field('2. ' + T('Máy ảo trung gian (gateway)', 'Gateway VM'), vmDd)),
      tool ? h('div', {}, h('p', { class: 'mut', style: { marginTop: 0 } }, tool.description), field('3. ' + T('Đích (website / dịch vụ)', 'Target'), targetFields || h('span'))) : null,
      tool && tool.kind === 'ssh' ? h('div', { class: 'form-grid' }, field(T('Tài khoản', 'Username'), userI), field(T('Mật khẩu', 'Password'), passI)) : null,
      tool && tool.kind !== 'ssh' ? h('div', { class: 'form-grid' }, field('4. ' + T('Cổng local để mở', 'Local port'), portDd),
        st.port === 'private' ? field(T('Cổng private', 'Private port'), h('div', { class: 'row' }, h('div', { style: { flex: 1 } }, privI), privBtn), '') : h('span')) : null,
      st.port === 'private' ? privMsg : null,
      probeMsg,
      h('div', { class: 'row' }, probeBtn, openBtn));
  }

  // ---------- Danh sach tunnel ----------
  function tunnelCard(t) {
    const tool = toolById(t.toolId);
    const exp = t.running && t.expiresAt ? h('span', { 'data-exp': t.expiresAt, class: 'chip' }) : null;
    const u = openUrl(t);
    return h('div', { class: 'card tun' },
      h('div', { class: 'row' }, h('span', { class: 'dd-ic' }, icon(tool ? tool.icon : 'plug', 22)), h('b', {}, t.name),
        h('span', { class: 'chip ' + (t.running ? 'ok' : '') }, t.running ? T('Đang chạy', 'Running') : T('Đã ngắt', 'Stopped')), h('span', { class: 'chip' }, t.kind === 'allocated' ? T('cổng cấp sẵn', 'allocated') : 'private'),
        S.me.role === 'admin' ? h('span', { class: 'chip pri' }, t.ownerName) : null, exp),
      h('div', { class: 'meta mono' }, `Bạn → :${t.localPort} → ${t.vmName} (${t.vmIp}) → ${t.targetHost}:${t.targetPort}`),
      h('div', { class: 'meta' }, t.running ? `${T('Kết nối', 'Conns')}: ${t.connections} · ↓ ${fmtBytes(t.bytesIn)} · ↑ ${fmtBytes(t.bytesOut)}` : (t.lastStopReason && t.lastStopReason !== 'user' ? '⚠ ' + T('Bị ngắt: ', 'Cut: ') + t.lastStopReason : (t.lastError || ''))),
      h('div', { class: 'row' },
        t.running ? (tool && tool.kind !== 'tcp' ? h('a', { class: 'btn sm primary', href: u, target: '_blank', rel: 'noopener' }, icon('open', 14), T('Mở', 'Open')) : h('button', { class: 'btn sm', onclick: () => copyText(`${API.host}:${t.localPort}`) }, icon('copy', 14), `${API.host}:${t.localPort}`)) : null,
        t.running ? h('button', { class: 'btn sm danger', onclick: async () => { await API.post(`/gateway/tunnels/${t.id}/stop`); await refreshState('tunnels'); refresh(); } }, icon('scissors', 14), T('Ngắt ngay', 'Cut now'))
          : h('button', { class: 'btn sm', onclick: async () => { try { await API.post(`/gateway/tunnels/${t.id}/start`); } catch (e) { toast(e.message, 'bad'); } await refreshState('tunnels'); refresh(); } }, icon('power', 14), T('Bật lại', 'Start')),
        h('button', { class: 'btn sm', onclick: () => window.GatewayUI.changePort(t, refresh) }, icon('edit', 14), T('Đổi port', 'Change port')),
        h('button', { class: 'btn sm', onclick: async () => { if (await confirmBox(T('Xoá kết nối này?', 'Delete this connection?'))) { await API.del('/gateway/tunnels/' + t.id); await refreshState('tunnels'); refresh(); } } }, icon('trash', 14))));
  }

  function renderList() {
    const running = S.tunnels.filter(t => t.running).length;
    listEl.replaceChildren(
      h('div', { class: 'row', style: { margin: '18px 0 10px', justifyContent: 'space-between' } }, h('h3', {}, T('Kết nối đang có', 'Your connections'), ' ', h('span', { class: 'chip' }, S.tunnels.length)),
        running ? h('button', { class: 'btn danger sm', onclick: async () => { const r = await API.post('/gateway/cut-all'); toast(T('Đã ngắt ', 'Cut ') + r.cut, 'ok'); await refreshState('tunnels'); refresh(); } }, icon('scissors', 14), T('Ngắt tất cả', 'Cut all')) : null),
      S.tunnels.length ? h('div', { class: 'grid g2' }, S.tunnels.map(tunnelCard)) : empty(T('Chưa có kết nối nào', 'No connections'), T('Chọn chức năng và máy ảo ở trên để bắt đầu.', 'Pick a tool and a gateway VM above.')));
  }

  function pathUpdate() { const n = pathView({ live: S.tunnels.some(t => t.running) }); pathEl.replaceWith(n); pathEl = n; }
  function refresh() { const f = buildForm(); formEl.replaceWith(f); formEl = f; pathUpdate(); renderList(); }

  // ---------- SSH Terminal ----------
  async function openTerminal(body) {
    let info;
    try { info = await API.post('/terminal', { ...body, cols: 110, rows: 28 }); } catch (e) { return toast(e.message, 'bad', 6000); }
    const out = h('pre', {}), inp = h('input', { placeholder: T('Nhập lệnh rồi Enter…', 'Type a command, Enter…'), autocomplete: 'off' });
    let es, closed = false;
    const strip = s => s.replace(/\x1b\][^\x07]*\x07/g, '').replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '').replace(/\r\n/g, '\n').replace(/\r/g, '');
    const append = s => { out.textContent += strip(s); if (out.textContent.length > 60000) out.textContent = out.textContent.slice(-40000); out.scrollTop = out.scrollHeight; };
    const send = d => API.post(`/terminal/${info.id}/input`, { data: d }).catch(e => append('\n[' + e.message + ']\n'));
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter') { send(inp.value + '\n'); inp.value = ''; }
      else if (e.ctrlKey && e.key.toLowerCase() === 'c') { e.preventDefault(); send('\x03'); }
      else if (e.ctrlKey && e.key.toLowerCase() === 'd') { e.preventDefault(); send('\x04'); }
      else if (e.key === 'Tab') { e.preventDefault(); send(inp.value + '\t'); inp.value = ''; }
    });
    const m = modal({ title: 'SSH — ' + info.label, wide: true, onClose: () => { closed = true; es && es.close(); API.del('/terminal/' + info.id).catch(() => {}); },
      body: h('div', { class: 'term' }, out, h('div', { class: 'in' }, h('span', { style: { color: '#2ee6b8' } }, '$'), inp)),
      actions: [{ label: 'Ctrl+C', close: false, onClick: () => send('\x03') }, { label: T('Ngắt kết nối', 'Disconnect'), danger: true }] });
    try {
      const { ticket } = await API.post(`/terminal/${info.id}/ticket`);
      es = new EventSource(`${API.base}/terminal/${info.id}/stream?ticket=${encodeURIComponent(ticket)}`);
      es.onmessage = e => append(JSON.parse(e.data));
      es.addEventListener('closed', e => { append('\n[' + JSON.parse(e.data) + ']\n'); es.close(); });
      es.onerror = () => { if (!closed) { es.close(); } };
    } catch (e) { append(e.message); }
    setTimeout(() => inp.focus(), 100);
  }

  // Dung chung voi trang Ports
  window.GatewayUI = {
    openUrl,
    changePort(t, done) {
      const pI = input({ type: 'number', value: t.localPort }), msg = h('small', { class: 'mut' });
      const check = async () => { try { const r = await API.get('/ports/check?port=' + encodeURIComponent(pI.value)); msg.textContent = (+pI.value === t.localPort) ? T('Cổng hiện tại', 'Current port') : r.allowed && r.free ? '✔ ' + T('Dùng được (', 'OK (') + (r.kind === 'allocated' ? T('cổng cấp sẵn', 'allocated') : 'private') + ')' : '✘ ' + r.reason; } catch (e) { msg.textContent = e.message; } };
      modal({ title: T('Đổi port local', 'Change local port'), body: h('div', {}, h('p', { class: 'mut' }, `${t.name}: ${T('kết nối đang chạy sẽ được khởi động lại trên cổng mới.', 'a running tunnel restarts on the new port.')}`), field(T('Cổng mới', 'New port'), h('div', { class: 'row' }, h('div', { style: { flex: 1 } }, pI), h('button', { class: 'btn sm', onclick: check }, T('Kiểm tra', 'Check')))), msg),
        actions: [{ label: T('Huỷ', 'Cancel') }, { label: T('Lưu', 'Save'), primary: true, close: false, onClick: async (e, close) => { try { await API.patch('/gateway/tunnels/' + t.id, { localPort: +pI.value }); await refreshState('tunnels'); toast(T('Đã đổi port', 'Port changed'), 'ok'); close(); done && done(); } catch (er) { msg.textContent = '✘ ' + er.message; } return false; } }] });
    }
  };

  async function render(root) {
    rootEl = root;
    await refreshState(['vms', 'tools', 'tunnels']);
    if (!st.vmId && gwVms().length === 1) st.vmId = gwVms()[0].id;
    pathEl = h('div'); formEl = h('div'); listEl = h('div');
    root.replaceChildren(
      h('div', { class: 'page-h' }, h('h2', {}, T('Cổng kết nối qua máy ảo (Gateway)', 'Gateway via virtual machine')),
        h('p', {}, T('Bạn → chức năng → máy ảo → website/đường link. Khi có sự cố, kết nối bị ngắt ngay tại máy ảo và bạn được báo mà IP của bạn không bị lộ.', 'You → tool → VM → website/link. On an incident the link is cut at the VM and you are notified, without exposing your IP.'))),
      !gwVms().length ? h('div', { class: 'banner warn' }, icon('warn'), T('Chưa có máy ảo có vai trò "gateway". Admin cần thêm trong Quản trị → Máy ảo.', 'No VM with the "gateway" role yet. An admin must add one in Administration → VMs.')) : null,
      h('div', { class: 'card' }, pathEl), h('div', { style: { height: '14px' } }), formEl, listEl);
    refresh();
  }

  window.Views.gateway = {
    render,
    tick() { document.querySelectorAll('[data-exp]').forEach(el => { const s = Math.max(0, Math.round((+el.dataset.exp - Date.now()) / 1000)); el.textContent = '⏱ ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }); },
    onEvent(ev) { if (['tunnel_state', 'tunnel_removed', 'gateway_cut', 'agents_updated'].includes(ev) && listEl && document.contains(listEl)) { renderList(); pathUpdate(); } }
  };
})();
