/**
 * Script mô phỏng traffic tấn công gửi về Sentinel IDS Server
 * Dành cho kiểm thử API và demo trong bài thuyết trình đồ án MMT
 *
 * Cách chạy: node scripts/test_traffic.js
 */
const http = require('http');

const SERVER_HOST = 'localhost';
const SERVER_PORT = 3000;

const attacks = [
  {
    type: "SSH brute force",
    tool: "Hydra",
    sev: "High",
    ip: "192.168.56.101",
    dst_port: 22,
    sid: 1000001,
    signature: "ET SCAN Potential SSH Brute Force Attempt (5 failed logins in 60s)",
    payload: "SSH-2.0-OpenSSH_8.9p1 Ubuntu Invalid password for user root from 192.168.56.101"
  },
  {
    type: "SQL injection",
    tool: "sqlmap",
    sev: "High",
    ip: "192.168.56.101",
    dst_port: 80,
    sid: 1000002,
    signature: "ET WEB_SPECIFIC_APPS DVWA SQL Injection Attempt",
    payload: "GET /vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- HTTP/1.1"
  },
  {
    type: "SYN flood",
    tool: "hping3",
    sev: "Medium",
    ip: "192.168.56.110",
    dst_port: 80,
    sid: 1000003,
    signature: "ET DOS Possible TCP SYN Flood (rate > 100 pps)",
    payload: "TCP SYN flood burst on port 80"
  },
  {
    type: "Port scan",
    tool: "nmap",
    sev: "Low",
    ip: "192.168.56.101",
    dst_port: 80,
    sid: 1000004,
    signature: "ET SCAN Nmap TCP SYN Port Scan",
    payload: "TCP SYN probe to multiple closed and open ports"
  }
];

function sendAlert(alert) {
  const data = JSON.stringify(alert);
  const options = {
    hostname: SERVER_HOST,
    port: SERVER_PORT,
    path: '/api/alerts',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    }
  };

  const req = http.request(options, res => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      console.log(`[SENT] ${alert.type} from ${alert.ip} -> Status: ${res.statusCode}`);
    });
  });

  req.on('error', err => {
    console.error('[ERROR] Không thể kết nối tới server (Đảm bảo server đang chạy node server.js):', err.message);
  });

  req.write(data);
  req.end();
}

console.log("=== BẮT ĐẦU BẮN TRAFFIC MÔ PHỎNG TỚI SENTINEL IDS ===");
let count = 0;
const interval = setInterval(() => {
  const atk = attacks[Math.floor(Math.random() * attacks.length)];
  sendAlert(atk);
  count++;
  if (count >= 10) {
    clearInterval(interval);
    console.log("=== ĐÃ HOÀN TẤT 10 CẢNH BÁO MÔ PHỎNG ===");
  }
}, 1500);