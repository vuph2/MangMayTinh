'use strict';
/**
 * Danh muc cong cu (tool) co the mo qua Gateway: Wazuh va cac lua chon mien phi tuong duong.
 * Day la cau hinh mac dinh (khong phai du lieu gia) - admin co the sua/them/xoa trong giao dien.
 */
const store = require('../db/store');
const { HttpError } = require('../http');

const DEFAULTS = [
  { id: 'wazuh-dashboard', name: 'Wazuh Dashboard', category: 'siem', kind: 'web', scheme: 'https', port: 443, path: '/', icon: 'server', description: 'SIEM/XDR mã nguồn mở – giao diện Wazuh (miễn phí)' },
  { id: 'wazuh-api', name: 'Wazuh API', category: 'siem', kind: 'web', scheme: 'https', port: 55000, path: '/', icon: 'bolt', description: 'REST API của Wazuh Manager' },
  { id: 'wazuh-indexer', name: 'Wazuh Indexer (OpenSearch)', category: 'siem', kind: 'web', scheme: 'https', port: 9200, path: '/', icon: 'db', description: 'Truy vấn dữ liệu cảnh báo (OpenSearch)' },
  { id: 'opensearch-dashboards', name: 'OpenSearch Dashboards', category: 'siem', kind: 'web', scheme: 'http', port: 5601, path: '/', icon: 'chart', description: 'Trực quan hoá log, thay thế Kibana (miễn phí)' },
  { id: 'security-onion', name: 'Security Onion', category: 'siem', kind: 'web', scheme: 'https', port: 443, path: '/', icon: 'shield', description: 'Nền tảng IDS/NSM miễn phí (Suricata + Zeek)' },
  { id: 'graylog', name: 'Graylog', category: 'siem', kind: 'web', scheme: 'http', port: 9000, path: '/', icon: 'list', description: 'Quản lý log tập trung (bản miễn phí)' },
  { id: 'evebox', name: 'EveBox (Suricata)', category: 'siem', kind: 'web', scheme: 'http', port: 5636, path: '/', icon: 'bell', description: 'Xem cảnh báo Suricata eve.json' },
  { id: 'grafana', name: 'Grafana', category: 'monitor', kind: 'web', scheme: 'http', port: 3000, path: '/', icon: 'chart', description: 'Dashboard giám sát (miễn phí)' },
  { id: 'zabbix', name: 'Zabbix', category: 'monitor', kind: 'web', scheme: 'http', port: 80, path: '/zabbix', icon: 'server', description: 'Giám sát hạ tầng mạng (miễn phí)' },
  { id: 'netdata', name: 'Netdata', category: 'monitor', kind: 'web', scheme: 'http', port: 19999, path: '/', icon: 'chart', description: 'Giám sát CPU/RAM/mạng thời gian thực' },
  { id: 'cockpit', name: 'Cockpit', category: 'monitor', kind: 'web', scheme: 'https', port: 9090, path: '/', icon: 'server', description: 'Quản trị Linux qua web' },
  { id: 'dvwa', name: 'DVWA (web lab)', category: 'web', kind: 'web', scheme: 'http', port: 80, path: '/', icon: 'globe', description: 'Ứng dụng web cố ý có lỗi – chỉ dùng trong lab' },
  { id: 'ssh', name: 'SSH Terminal', category: 'remote', kind: 'ssh', scheme: 'ssh', port: 22, path: '', icon: 'terminal', description: 'Đăng nhập SSH từ trình duyệt, đi qua VM trung gian' },
  { id: 'tcp', name: 'Cổng TCP tuỳ chọn', category: 'remote', kind: 'tcp', scheme: 'tcp', port: 0, path: '', icon: 'plug', description: 'Mở tunnel TCP tới host:port bất kỳ (RDP, DB…)' },
  { id: 'url', name: 'Website / Link', category: 'web', kind: 'url', scheme: 'http', port: 0, path: '', icon: 'globe', description: 'Mở website/đường link bất kỳ qua VM (đích chỉ thấy IP của VM)' }
];

const col = store.open('tools', null);
if (!col.data) { col.data = DEFAULTS.map(t => ({ ...t, enabled: true, builtin: true })); col.save(true); }

const KINDS = ['web', 'ssh', 'tcp', 'url'];
const CATS = ['siem', 'monitor', 'web', 'remote', 'other'];
const ICONS = ['server', 'globe', 'terminal', 'shield', 'chart', 'db', 'bolt', 'list', 'bell', 'plug', 'cube'];

const list = (all = false) => col.data.filter(t => all || t.enabled);
const byId = id => col.data.find(t => t.id === id);

function normalize(b, cur = {}) {
  const t = { ...cur };
  if (b.name !== undefined) t.name = String(b.name).trim().slice(0, 48);
  if (b.description !== undefined) t.description = String(b.description).slice(0, 200);
  if (b.kind !== undefined) { if (!KINDS.includes(b.kind)) throw new HttpError(400, 'kind khong hop le'); t.kind = b.kind; }
  if (b.category !== undefined) t.category = CATS.includes(b.category) ? b.category : 'other';
  if (b.scheme !== undefined) t.scheme = ['http', 'https', 'ssh', 'tcp'].includes(b.scheme) ? b.scheme : 'http';
  if (b.port !== undefined) { const p = parseInt(b.port, 10); t.port = p >= 0 && p <= 65535 ? p : 0; }
  if (b.path !== undefined) t.path = String(b.path).slice(0, 200);
  if (b.icon !== undefined) t.icon = ICONS.includes(b.icon) ? b.icon : 'globe';
  if (b.enabled !== undefined) t.enabled = !!b.enabled;
  return t;
}
function create(b) {
  const t = normalize(b, { id: 'tool-' + Date.now().toString(36), enabled: true, builtin: false, kind: 'web', scheme: 'http', category: 'other', icon: 'globe', path: '/', port: 80 });
  if (!t.name) throw new HttpError(400, 'Thieu ten tool');
  col.data.push(t); col.save(); return t;
}
function update(id, b) {
  const t = byId(id); if (!t) throw new HttpError(404, 'Khong tim thay tool');
  Object.assign(t, normalize(b, t)); col.save(); return t;
}
function remove(id) {
  const t = byId(id); if (!t) throw new HttpError(404, 'Khong tim thay tool');
  if (t.builtin) throw new HttpError(400, 'Tool co san chi co the an (disable), khong xoa');
  col.data.splice(col.data.indexOf(t), 1); col.save();
}
module.exports = { list, byId, create, update, remove };
