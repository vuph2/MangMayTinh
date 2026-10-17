/**
 * Sentinel IDS - Backend Server (Zero External Dependencies)
 * Computer Networks Lab (MMT) - Suricata & Wazuh Simulation & Ingestion
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Ensure data files exist
function loadJson(file, defaultVal) {
  try {
    const p = path.join(DATA_DIR, file);
    if (!fs.existsSync(p)) {
      fs.writeFileSync(p, JSON.stringify(defaultVal, null, 2), 'utf-8');
      return defaultVal;
    }
    return JSON.parse(fs.readFileSync(p, 'utf-8').replace(/^\\uFEFF/, ''));
  } catch (e) {
    console.error(`Error loading ${file}:`, e);
    return defaultVal;
  }
}

function saveJson(file, data) {
  try {
    const p = path.join(DATA_DIR, file);
    fs.writeFileSync(p, JSON.stringify(data, null, 2), 'utf-8');
  } catch (e) {
    console.error(`Error saving ${file}:`, e);
  }
}

let alerts = loadJson('alerts.json', []);
let agents = loadJson('agents.json', []);
let rules = loadJson('rules.json', []);
let blocklist = loadJson('blocklist.json', {});

// Active SSE client connections
const sseClients = new Set();

function broadcastSSE(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(msg);
    } catch (err) {
      sseClients.delete(client);
    }
  }
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};


const net = require('net');

function checkTcpPort(ip, port, timeout = 1000) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, ip);
  });
}

const { exec } = require('child_process');

function pingHost(ip) {
  return new Promise(resolve => {
    const cmd = process.platform === 'win32' ? `ping -n 1 -w 800 ${ip}` : `ping -c 1 -W 1 ${ip}`;
    exec(cmd, (err, stdout) => {
      if (err) return resolve(false);
      resolve(stdout.includes('TTL=') || stdout.includes('ttl='));
    });
  });
}

async function checkAllAgentsHealth() {
  let changed = false;
  for (const agent of agents) {
    let isUp = false;
    if (agent.name === 'victim') {
      isUp = await checkTcpPort(agent.ip, 80);
    } else if (agent.name === 'Ubuntu1') {
      isUp = await checkTcpPort(agent.ip, 443);
    }
    // If TCP failed or for Kali/other agents, fallback to ICMP ping
    if (!isUp) {
      isUp = await pingHost(agent.ip);
    }
    const newOn = isUp ? 1 : 0;
    if (agent.on !== newOn) {
      agent.on = newOn;
      agent.status = isUp ? 'active' : 'disconnected';
      changed = true;
    }
  }
  if (changed) {
    saveJson('agents.json', agents);
    broadcastSSE('agents_updated', agents);
  }
}

setInterval(checkAllAgentsHealth, 5000);
setTimeout(checkAllAgentsHealth, 1000);

const server = http.createServer(async (req, res) => {
  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // --- Real-time SSE Endpoint ---
  if (pathname === '/api/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    res.write('retry: 5000\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // --- REST API Endpoints ---
  if (pathname.startsWith('/api/')) {
    // 1. ALERTS API
    if (pathname === '/api/alerts' && req.method === 'GET') {
      const { ip, type, sev, limit } = parsedUrl.query;
      let filtered = alerts;
      if (ip) filtered = filtered.filter(a => a.ip.includes(ip));
      if (type) filtered = filtered.filter(a => a.type === type);
      if (sev) filtered = filtered.filter(a => a.sev === sev);
      const l = parseInt(limit, 10) || 100;
      return sendJson(res, 200, { total: alerts.length, data: filtered.slice(0, l) });
    }

    if (pathname === '/api/alerts' && req.method === 'POST') {
      const data = await parseBody(req);
      const newAlert = {
        id: data.id || 'ALT-' + (Date.now() % 1000000),
        ts: data.ts || Date.now(),
        ip: data.ip || '192.168.56.101',
        src_port: data.src_port || Math.floor(30000 + Math.random() * 30000),
        dst_ip: data.dst_ip || '192.168.56.103',
        dst_port: data.dst_port || 80,
        proto: data.proto || 'TCP',
        type: data.type || 'Custom Ingestion',
        tool: data.tool || 'Suricata',
        sev: data.sev || 'Medium',
        sid: data.sid || 1000000,
        signature: data.signature || (data.type + ' detected by Suricata'),
        payload: data.payload || '',
        status: 'active',
        agent: data.agent || 'victim'
      };
      alerts.unshift(newAlert);
      if (alerts.length > 500) alerts = alerts.slice(0, 500);
      saveJson('alerts.json', alerts);
      broadcastSSE('new_alert', newAlert);
      return sendJson(res, 201, { success: true, alert: newAlert });
    }

    if (pathname.startsWith('/api/alerts/') && req.method === 'PATCH') {
      const alertId = pathname.replace('/api/alerts/', '');
      const body = await parseBody(req);
      const alert = alerts.find(a => a.id === alertId);
      if (!alert) return sendJson(res, 404, { error: 'Alert not found' });
      if (body.status) alert.status = body.status;
      saveJson('alerts.json', alerts);
      return sendJson(res, 200, { success: true, alert });
    }

    if (pathname === '/api/alerts' && req.method === 'DELETE') {
      alerts = [];
      saveJson('alerts.json', alerts);
      broadcastSSE('cleared', {});
      return sendJson(res, 200, { success: true, message: 'All alerts cleared' });
    }

    // 2. AGENTS API
    if (pathname === '/api/agents' && req.method === 'GET') {
      return sendJson(res, 200, agents);
    }
    if (pathname === '/api/agents' && req.method === 'POST') {
      const data = await parseBody(req);
      if (data.id) {
        const idx = agents.findIndex(a => a.id === data.id);
        if (idx >= 0) agents[idx] = { ...agents[idx], ...data };
        else agents.push(data);
      } else {
        data.id = 'ag-' + (agents.length + 1);
        agents.push(data);
      }
      saveJson('agents.json', agents);
      broadcastSSE('agents_updated', agents);
      return sendJson(res, 200, agents);
    }

    // 3. BLOCKLIST & ACTIVE RESPONSE API
    if (pathname === '/api/blocklist' && req.method === 'GET') {
      return sendJson(res, 200, blocklist);
    }
    if (pathname === '/api/blocklist' && req.method === 'POST') {
      const data = await parseBody(req);
      if (!data.ip) return sendJson(res, 400, { error: 'IP is required' });
      blocklist[data.ip] = {
        ip: data.ip,
        reason: data.reason || 'Manually blocked via Sentinel IDS UI',
        blockedAt: Date.now(),
        duration: data.duration || 3600,
        source: data.source || 'Sentinel UI / Wazuh Active Response',
        ruleSid: data.ruleSid || null
      };
      saveJson('blocklist.json', blocklist);
      broadcastSSE('ip_blocked', blocklist[data.ip]);
      return sendJson(res, 200, { success: true, blocklist });
    }
    if (pathname.startsWith('/api/blocklist/') && req.method === 'DELETE') {
      const ip = pathname.replace('/api/blocklist/', '');
      if (blocklist[ip]) {
        delete blocklist[ip];
        saveJson('blocklist.json', blocklist);
        broadcastSSE('ip_unblocked', { ip });
      }
      return sendJson(res, 200, { success: true, blocklist });
    }

    // 4. RULES API
    if (pathname === '/api/rules' && req.method === 'GET') {
      return sendJson(res, 200, rules);
    }
    if (pathname === '/api/rules' && req.method === 'POST') {
      const data = await parseBody(req);
      const newRule = {
        id: rules.length ? Math.max(...rules.map(r => r.id)) + 1 : 1,
        sid: data.sid || 1000000 + rules.length + 1,
        rev: 1,
        name: data.name || 'Custom Rule',
        proto: data.proto || 'tcp',
        src: data.src || 'any any',
        dst: data.dst || '$HOME_NET any',
        action: data.action || 'alert',
        raw: data.raw || `alert tcp any any -> $HOME_NET any (msg:"Custom Rule"; sid:1000099; rev:1;)`,
        enabled: data.enabled !== undefined ? data.enabled : true,
        desc: data.desc || 'Custom user rule'
      };
      rules.push(newRule);
      saveJson('rules.json', rules);
      broadcastSSE('rules_updated', rules);
      return sendJson(res, 201, newRule);
    }
    if (pathname.startsWith('/api/rules/') && req.method === 'PUT') {
      const ruleId = parseInt(pathname.replace('/api/rules/', ''), 10);
      const body = await parseBody(req);
      const idx = rules.findIndex(r => r.id === ruleId);
      if (idx === -1) return sendJson(res, 404, { error: 'Rule not found' });
      rules[idx] = { ...rules[idx], ...body };
      saveJson('rules.json', rules);
      broadcastSSE('rules_updated', rules);
      return sendJson(res, 200, rules[idx]);
    }
    if (pathname.startsWith('/api/rules/') && req.method === 'DELETE') {
      const ruleId = parseInt(pathname.replace('/api/rules/', ''), 10);
      rules = rules.filter(r => r.id !== ruleId);
      saveJson('rules.json', rules);
      broadcastSSE('rules_updated', rules);
      return sendJson(res, 200, { success: true });
    }

    // 5. ATTACK SIMULATION API
    if (pathname === '/api/simulate' && req.method === 'POST') {
      const data = await parseBody(req);
      const scenario = data.scenario || 'SSH brute force';
      const SIM_TYPES = {
        'Port scan': { tool: 'nmap', sev: 'Low', sid: 1000004, port: 80, proto: 'TCP', sig: 'ET SCAN Nmap TCP SYN Port Scan', payload: 'TCP SYN Seq=29103 Win=1024' },
        'SSH brute force': { tool: 'Hydra', sev: 'High', sid: 1000001, port: 22, proto: 'TCP', sig: 'ET SCAN Potential SSH Brute Force Attempt', payload: 'SSH-2.0-OpenSSH_8.9p1 user=admin password=incorrect' },
        'SQL injection': { tool: 'sqlmap', sev: 'High', sid: 1000002, port: 80, proto: 'TCP', sig: 'ET WEB_SPECIFIC_APPS DVWA SQL Injection Attempt', payload: "GET /vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--" },
        'SYN flood': { tool: 'hping3', sev: 'Medium', sid: 1000003, port: 80, proto: 'TCP', sig: 'ET DOS Possible TCP SYN Flood', payload: 'TCP SYN flood 200+ pps' },
        'Sensitive File Access': { tool: 'curl', sev: 'High', sid: 1000005, port: 80, proto: 'TCP', sig: 'ET WEB_SERVER Access to /etc/passwd Attempt', payload: 'GET /vulnerabilities/fi/?page=../../../../etc/passwd' }
      };
      const def = SIM_TYPES[scenario] || SIM_TYPES['SSH brute force'];
      const simAlert = {
        id: 'SIM-' + Date.now().toString().slice(-6),
        ts: Date.now(),
        ip: data.attackerIp || '192.168.56.101',
        src_port: Math.floor(35000 + Math.random() * 20000),
        dst_ip: data.targetIp || '192.168.56.103',
        dst_port: def.port,
        proto: def.proto,
        type: scenario,
        tool: def.tool,
        sev: def.sev,
        sid: def.sid,
        signature: def.sig,
        payload: def.payload,
        status: 'active',
        agent: 'victim'
      };
      alerts.unshift(simAlert);
      if (alerts.length > 500) alerts = alerts.slice(0, 500);
      saveJson('alerts.json', alerts);
      broadcastSSE('new_alert', simAlert);
      return sendJson(res, 201, { success: true, alert: simAlert });
    }

    // 6. STATS API
    if (pathname === '/api/stats' && req.method === 'GET') {
      const now = Date.now();
      const last1h = alerts.filter(a => now - a.ts < 3600000).length;
      const byType = {};
      const byIp = {};
      const bySev = { High: 0, Medium: 0, Low: 0 };
      for (const a of alerts) {
        byType[a.type] = (byType[a.type] || 0) + 1;
        byIp[a.ip] = (byIp[a.ip] || 0) + 1;
        if (bySev[a.sev] !== undefined) bySev[a.sev]++;
      }
      return sendJson(res, 200, {
        totalAlerts: alerts.length,
        last1h,
        blockedIpsCount: Object.keys(blocklist).length,
        activeAgents: agents.filter(a => a.status === 'active').length,
        byType,
        byIp,
        bySev
      });
    }

    // 7. TELEGRAM WEBHOOK TEST
    if (pathname === '/api/webhook/telegram-test' && req.method === 'POST') {
      const body = await parseBody(req);
      const token = body.token || '';
      const chatId = body.chatId || '';
      return sendJson(res, 200, {
        success: true,
        message: `Simulated Telegram alert sent to Chat ID ${chatId || 'Group'}: [HIGH ALERT] Potential SSH Brute Force from 192.168.56.101`
      });
    }

    return sendJson(res, 404, { error: 'API route not found' });
  }

  // --- Static File Serving ---
  let reqPath = pathname === '/' ? '/index.html' : pathname;
  let filePath = path.join(PUBLIC_DIR, reqPath);

  // Security check: stay inside public dir
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Access Denied');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`   Sentinel IDS Dashboard - Mạng Máy Tính (MMT)     `);
  console.log(`   Server running at: http://localhost:${PORT}        `);
  console.log(`   API Endpoint:      http://localhost:${PORT}/api/alerts`);
  console.log(`====================================================`);
});
