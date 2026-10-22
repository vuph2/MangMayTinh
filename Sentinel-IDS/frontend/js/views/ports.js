/** Quan ly cong: xem chinh sach, doi port, them port (cong cap san hoac private), kiem tra cong dich qua VM */
(function () {
  const { h, icon, T, toast, confirmBox, dropdown, field, input, select, empty, modal } = UI;
  let rootEl;

  async function render(root) {
    rootEl = root;
    const [pol] = await Promise.all([API.get('/ports/policy'), refreshState(['vms', 'tools', 'tunnels'])]);
    const p = pol.policy; S.policy = p;
    const gw = S.vms.filter(v => v.gateway && v.enabled);
    const tools = S.tools.filter(t => t.enabled && t.kind !== 'ssh' && t.kind !== 'url');
    const st = { toolId: (tools.find(t => t.id === 'tcp') || tools[0] || {}).id, vmId: gw[0] && gw[0].id, host: '', port: '', local: '', url: '' };
    const msg = h('div');

    const toolDd = dropdown({ items: tools.map(t => ({ value: t.id, label: t.name, icon: t.icon })), value: st.toolId, onChange: v => { st.toolId = v; } });
    const vmDd = dropdown({ items: gw.map(v => ({ value: v.id, label: v.name, sub: v.ip, icon: 'server' })), value: st.vmId, onChange: v => { st.vmId = v; } });
    const hostI = input({ placeholder: T('Trống = IP của VM', 'Empty = VM IP'), oninput: e => { st.host = e.target.value; } });
    const portI = input({ type: 'number', placeholder: T('Cổng đích', 'Target port'), oninput: e => { st.port = e.target.value; } });
    const localI = input({ type: 'number', placeholder: T('Trống = tự chọn cổng cấp sẵn', 'Empty = auto allocated'), oninput: e => { st.local = e.target.value; } });
    const note = (m, ok) => { msg.className = 'banner ' + (ok ? 'ok' : 'bad'); msg.textContent = m; };

    const probe = async () => { try { const r = await API.post('/gateway/probe', { vmId: st.vmId, host: st.host || undefined, port: +st.port }); note(r.open ? `✔ ${T('Đích mở', 'Target open')} (${r.latencyMs} ms)` : `✘ ${T('Đích không mở / không tới được', 'Target closed/unreachable')}`, r.open); } catch (e) { note(e.message, false); } };
    const checkLocal = async () => { if (!st.local) return note(T('Nhập cổng local để kiểm tra', 'Enter a local port'), false); try { const r = await API.get('/ports/check?port=' + st.local); note(r.allowed && r.free ? `✔ ${T('Cổng dùng được', 'Port available')} (${r.kind === 'allocated' ? T('cấp sẵn', 'allocated') : 'private'})` : '✘ ' + r.reason, r.allowed && r.free); } catch (e) { note(e.message, false); } };
    const add = async () => {
      try {
        const body = { toolId: st.toolId, vmId: st.vmId, targetHost: st.host || undefined, targetPort: +st.port || undefined, url: st.url || undefined };
        if (st.local) body.localPort = +st.local;
        const t = await API.post('/gateway/tunnels', body);
        toast(T('Đã thêm port ', 'Added port ') + t.localPort, 'ok'); render(rootEl);
      } catch (e) { note(e.message, false); }
    };

    const rows = S.tunnels.map(t => h('tr', {},
      h('td', { class: 'mono' }, ':' + t.localPort), h('td', {}, h('span', { class: 'chip ' + (t.kind === 'private' ? 'pri' : 'ok') }, t.kind === 'allocated' ? T('Cấp sẵn', 'Allocated') : 'Private')),
      h('td', {}, t.name), h('td', { class: 'mono' }, `${t.vmName} → ${t.targetHost}:${t.targetPort}`),
      h('td', {}, h('span', { class: 'chip ' + (t.running ? 'ok' : '') }, t.running ? T('Đang mở', 'Open') : T('Đóng', 'Closed'))),
      h('td', { class: 'act' }, h('button', { class: 'btn sm', onclick: () => GatewayUI.changePort(t, () => render(rootEl)) }, icon('edit', 14), T('Đổi port', 'Change')), ' ',
        h('button', { class: 'btn sm', onclick: async () => { try { await API.post(`/gateway/tunnels/${t.id}/${t.running ? 'stop' : 'start'}`); } catch (e) { toast(e.message, 'bad'); } render(rootEl); } }, t.running ? T('Đóng', 'Close') : T('Mở', 'Open')), ' ',
        h('button', { class: 'btn sm', onclick: async () => { if (await confirmBox(T('Xoá port này?', 'Delete this port?'))) { await API.del('/gateway/tunnels/' + t.id); render(rootEl); } } }, icon('trash', 14)))));

    root.replaceChildren(
      h('div', { class: 'page-h' }, h('h2', {}, T('Cổng & Port', 'Ports')), h('p', {}, T('Đổi port, thêm port local cấp sẵn hoặc port private để kiểm tra.', 'Change ports, add allocated or private ports for testing.'))),
      h('div', { class: 'grid g2' },
        h('div', { class: 'card' }, h('h3', {}, icon('key'), T('Quyền cổng của bạn', 'Your port policy')),
          h('table', { class: 'tbl', style: { minWidth: 0 } }, h('tbody', {},
            h('tr', {}, h('td', { class: 'mut' }, T('Cổng cấp sẵn', 'Allocated ports')), h('td', {}, (p.allocated || []).map(x => h('span', { class: 'chip ok mono' }, x)))),
            h('tr', {}, h('td', { class: 'mut' }, T('Cổng private', 'Private ports')), h('td', {}, p.privateAllowed ? h('span', { class: 'chip pri mono' }, p.privateRange) : T('Không được phép', 'Not allowed'))),
            h('tr', {}, h('td', { class: 'mut' }, T('Số kết nối tối đa', 'Max connections')), h('td', {}, p.maxTunnels)),
            h('tr', {}, h('td', { class: 'mut' }, T('Đích tuỳ ý', 'Custom targets')), h('td', {}, p.allowCustomTarget ? T('Được phép', 'Allowed') : T('Chỉ VM trong hệ thống', 'Registered VMs only'))),
            h('tr', {}, h('td', { class: 'mut' }, T('Cổng hệ thống (cấm)', 'Reserved')), h('td', {}, pol.reserved.map(x => h('span', { class: 'chip bad mono' }, x))))))),
        h('div', { class: 'card' }, h('h3', {}, icon('plus'), T('Thêm port mới', 'Add a port')),
          h('div', { class: 'form-grid' }, field(T('Chức năng', 'Tool'), toolDd), field(T('Máy ảo trung gian', 'Gateway VM'), vmDd), field(T('Host đích', 'Target host'), hostI), field(T('Cổng đích', 'Target port'), portI),
            h('div', { class: 'full' }, field(T('Cổng local (cấp sẵn hoặc private)', 'Local port (allocated or private)'), localI))),
          msg, h('div', { class: 'row' }, h('button', { class: 'btn', onclick: probe }, icon('activity', 14), T('Kiểm tra đích', 'Test target')), h('button', { class: 'btn', onclick: checkLocal }, T('Kiểm tra cổng local', 'Check local port')), h('button', { class: 'btn primary', onclick: add }, icon('plus', 14), T('Thêm', 'Add'))))),
      h('h3', { style: { margin: '20px 0 10px' } }, T('Danh sách port của bạn', 'Your ports')),
      S.tunnels.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Cổng local|Local', 'Loại|Type', 'Tên|Name', 'Đường đi|Route', 'Trạng thái|State', ''].map(c => h('th', {}, T(...c.split('|')))))), h('tbody', {}, rows))) : empty(T('Chưa có port nào', 'No ports yet')));
  }
  window.Views.ports = { render, onEvent(ev) { if (['tunnel_state', 'tunnel_removed'].includes(ev) && rootEl && document.contains(rootEl) && !document.querySelector('.overlay')) render(rootEl); } };
})();
