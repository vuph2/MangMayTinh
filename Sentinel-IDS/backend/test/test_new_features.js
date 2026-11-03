'use strict';
/**
 * Test danh rieng cho 6 chuc nang moi:
 * 1. Chay kich ban tan cong & do hieu qua tu dong
 * 2. Gom su co & dong thoi gian theo IP nguon
 * 3. Thong ke top chu ky, IP, loai tan cong, bao cao
 * 4. Anh xa MITRE ATT&CK
 * 5. Danh sach trang (Whitelist IP & SID)
 * 6. Doc log eve.json
 */
const assert = require('assert');
const alerts = require('../src/services/alerts');
const whitelist = require('../src/services/whitelist');
const scenarios = require('../src/services/scenarios');
const sensors = require('../src/services/sensors');
const wazuh = require('../src/services/wazuh');

console.log('--- TEST 6 CHUC NANG MOI ---');

// 1. Whitelist Test
console.log('[1] Whitelist (Danh sach trang)');
whitelist.addIp('192.168.100.99', { reason: 'Test trusted scanner', addedBy: 'admin' });
assert.strictEqual(whitelist.isWhitelistedIp('192.168.100.99'), true);
assert.strictEqual(whitelist.isWhitelistedIp('10.0.0.1'), false);

whitelist.addSid(999999, { reason: 'Test false positive rule', addedBy: 'admin' });
assert.strictEqual(whitelist.isWhitelistedSid(999999), true);
assert.strictEqual(whitelist.isWhitelistedSid(12345), false);

// Alert from whitelisted IP should be ignored (return null)
const ignoredAlert = alerts.add({
  ip: '192.168.100.99',
  dst_ip: '192.168.100.10',
  type: 'Port scan',
  sev: 'High'
});
assert.strictEqual(ignoredAlert, null, 'Canh bao tu IP trong whitelist phai bi bo qua');

// Clean up test entries from whitelist
whitelist.removeIp('192.168.100.99');
whitelist.removeSid(999999);
assert.strictEqual(whitelist.isWhitelistedIp('192.168.100.99'), false);
console.log('  ✔ Whitelist IP & SID hoat dong chinh xac');

// 2. MITRE ATT&CK Mapping Test
console.log('[2] MITRE ATT&CK Mapping');
const testAlert1 = alerts.add({
  ip: '10.99.99.1',
  dst_ip: '10.99.99.2',
  type: 'Port scan',
  signature: 'ET SCAN Potential Nmap Scan',
  sev: 'Low'
});
assert.ok(testAlert1 && testAlert1.mitre, 'Canh bao scan phai co MITRE mapping');
assert.strictEqual(testAlert1.mitre.technique, 'T1046');
assert.strictEqual(testAlert1.mitre.tactic, 'Reconnaissance');

// Test Wazuh hit mapping with rule.mitre
const fakeWazuhHit = {
  _id: 'fake-wazuh-1',
  _source: {
    timestamp: new Date().toISOString(),
    rule: {
      id: 5710,
      description: 'sshd: Attempt to login using a non-existent user',
      level: 5,
      mitre: {
        id: ['T1110'],
        tactic: ['Credential Access'],
        technique: ['Brute Force']
      }
    },
    data: { srcip: '10.88.88.88', dstip: '10.88.88.1' }
  }
};
const mappedWazuh = wazuh.mapHit(fakeWazuhHit);
assert.ok(mappedWazuh.mitre, 'Wazuh alert phai giu truong MITRE tu rule.mitre');
assert.strictEqual(mappedWazuh.mitre.technique, 'T1110');
assert.strictEqual(mappedWazuh.mitre.tactic, 'Credential Access');
console.log('  ✔ Anh xa MITRE ATT&CK cho Suricata & Wazuh thanh cong');

// 3. Incidents & Timeline by IP
console.log('[3] Gom su co & Dong thoi gian theo IP');
// Add multiple alerts for same IP
alerts.add({ ip: '10.77.77.77', dst_ip: '10.0.0.1', type: 'SSH brute force', signature: 'Hydra SSH', sev: 'Medium' });
alerts.add({ ip: '10.77.77.77', dst_ip: '10.0.0.1', type: 'SQL injection', signature: 'sqlmap detected', sev: 'High' });

const inc = alerts.incidents('10.77.77.77');
assert.strictEqual(inc.ip, '10.77.77.77');
assert.ok(inc.total >= 2, 'Tong so canh bao cua IP phai >= 2');
assert.strictEqual(inc.maxSev, 'High');
assert.ok(inc.types.includes('SSH brute force') && inc.types.includes('SQL injection'));
assert.ok(Array.isArray(inc.timeline) && inc.timeline.length >= 2);
console.log('  ✔ Gom su co va dong thoi gian theo IP hoat dong tot');

// 4. Statistics & Top Signatures/IPs
console.log('[4] Thong ke top chu ky, IP, loai tan cong');
const st = alerts.stats();
assert.ok(st.total > 0);
assert.ok(st.byMitreTactic && Object.keys(st.byMitreTactic).length > 0);
assert.ok(st.bySig && Object.keys(st.bySig).length > 0);

const topIps = alerts.topIps(5);
assert.ok(Array.isArray(topIps) && topIps.length > 0);

const topSigs = alerts.topSignatures(5);
assert.ok(Array.isArray(topSigs) && topSigs.length > 0);
console.log('  ✔ Thong ke bao cao & Top IP / Top chu ky thanh cong');

// 5. Scenarios (Kich ban tan cong & Do hieu qua tu dong)
console.log('[5] Kich ban tan cong');
const scList = scenarios.listScenarios();
assert.ok(scList.length >= 5, 'Phai co it nhat 5 kich ban an toan');
assert.ok(scList.some(s => s.id === 'nmap_scan'));
assert.ok(scList.some(s => s.id === 'ssh_bruteforce'));
assert.ok(scList.some(s => s.id === 'sqli_test'));
assert.ok(scList.some(s => s.id === 'syn_flood'));
assert.ok(scList.some(s => s.id === 'curl_sensitive'));

// Test automated metrics calculation
const testRec = {
  id: 'test-run-1',
  scenario: 'nmap_scan',
  vmId: 'fake-vm',
  target: '10.99.99.2',
  startAt: Date.now() - 5000,
  endAt: Date.now(),
  done: true
};
const metrics = scenarios.computeMetrics(testRec);
assert.strictEqual(typeof metrics.detected, 'boolean');
assert.strictEqual(typeof metrics.alertCount, 'number');
console.log('  ✔ Danh sach kich ban & do luong hieu qua tu dong OK');

// 6. eve.json Parser Test
console.log('[6] Parser eve.json');
const fakeEveAlert = JSON.stringify({
  timestamp: '2026-11-03T04:20:00.123456+0000',
  flow_id: 1234567890,
  event_type: 'alert',
  src_ip: '192.168.56.105',
  src_port: 54321,
  dest_ip: '192.168.56.102',
  dest_port: 80,
  proto: 'TCP',
  app_proto: 'http',
  alert: {
    action: 'allowed',
    gid: 1,
    signature_id: 2010935,
    rev: 3,
    signature: 'ET SCAN Potential Nmap User-Agent Observed',
    category: 'Web Application Attack',
    severity: 1,
    metadata: {
      mitre_tactic_id: ['TA0007'],
      mitre_tactic_name: ['Discovery'],
      mitre_technique_id: ['T1046'],
      mitre_technique_name: ['Network Service Scanning']
    }
  }
});

const parsedEve = sensors.parseEveLine(fakeEveAlert, { id: 'vm-sensor', name: 'Sensor-Victim' });
assert.ok(parsedEve, 'parseEveLine phai parse thanh cong su kien eve.json alert');
assert.strictEqual(parsedEve.ip, '192.168.56.105');
assert.strictEqual(parsedEve.dst_ip, '192.168.56.102');
assert.strictEqual(parsedEve.dst_port, 80);
assert.strictEqual(parsedEve.sev, 'High');
assert.strictEqual(parsedEve.sid, 2010935);
assert.strictEqual(parsedEve.source, 'suricata');
assert.ok(parsedEve.mitre && parsedEve.mitre.technique === 'T1046');

// Non-alert event in eve.json should return null
const fakeEveFlow = JSON.stringify({
  timestamp: '2026-11-03T04:20:00.123456+0000',
  event_type: 'flow',
  src_ip: '1.2.3.4'
});
assert.strictEqual(sensors.parseEveLine(fakeEveFlow, { id: 'vm-sensor' }), null, 'Event khong phai alert phai bi bo qua');

console.log('  ✔ Parser eve.json cho Suricata hoat dong chinh xac');

console.log('\n========================================');
console.log('TAT CA 6 CHUC NANG KIEM THU DAT 100%!');
console.log('========================================');

