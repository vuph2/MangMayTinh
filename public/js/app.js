/**
 * Sentinel IDS - Core Frontend Application
 * Fully interactive IDS Dashboard for Computer Networks (MMT) Lab Project
 */
(function() {
  const $ = id => document.getElementById(id);
  const Q = sel => document.querySelectorAll(sel);

  // SVG Icon definitions
  const ICONS = {
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    bell: '<path d="M6 16v-5a6 6 0 0112 0v5l2 2H4z"/><path d="M10 21h4"/>',
    chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    file: '<path d="M6 3h8l5 5v13H6z"/><path d="M14 3v5h5"/>',
    gear: '<circle cx="12" cy="3" r="1"/><circle cx="12" cy="21" r="1"/><circle cx="3" cy="12" r="1"/><circle cx="21" cy="12" r="1"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    dots: '<circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/>',
    shield: '<path d="M12 2.4L19.6 5.2V11.4C19.6 16.2 16.4 19.8 12 21.6C7.6 19.8 4.4 16.2 4.4 11.4V5.2Z" fill="currentColor" fill-opacity=".2"/><path d="M12 2.4L19.6 5.2V11.4C19.6 16.2 16.4 19.8 12 21.6C7.6 19.8 4.4 16.2 4.4 11.4V5.2Z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="1.8"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/>',
    moon: '<path d="M20 14A8 8 0 1110 4a7 7 0 0010 10z"/>',
    srv: '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/>',
    bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
    back: '<path d="M15 5l-7 7 7 7"/>',
    term: '<path d="M4 6h16v12H4z"/><path d="M7 10l3 2-3 2M12 15h4"/>',
    net: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-6 5M12 12l6 5"/>',
    bug: '<rect x="8" y="8" width="8" height="12" rx="4"/><path d="M8 13H4M16 13h4M9 5l2 3M15 5l-2 3"/>',
    list: '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
    tune: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 114 2c-1 .7-1.5 1.1-1.5 2.2M12 17h.01"/>',
    cmp: '<path d="M8 4v16M16 4v16M4 8l4-4 4 4M12 16l4 4 4-4"/>',
    volume: '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>',
    volumeMute: '<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'
  };

  const ic = name => '<svg class="i" viewBox="0 0 24 24">' + (ICONS[name] || '') + '</svg>';

  // State
    let AGENTS = [
    { id: "ag-1", name: "victim", ip: "192.168.56.102", on: 1, status: "active", role: "DVWA Web (Port 8080) & Suricata Sensor", cpu: 18, mem: 42 },
    { id: "ag-2", name: "Ubuntu1", ip: "192.168.56.103", on: 1, status: "active", role: "Wazuh Manager & Indexer (Port 8443)", cpu: 35, mem: 68 },
    { id: "ag-3", name: "kali", ip: "192.168.56.101", on: 1, status: "active", role: "Kali Attacker (nmap, hydra)", cpu: 45, mem: 52 }
  ];
  let DUMMY_PREV = [
    { id: "ag-1", name: "victim", ip: "192.168.56.102", on: 1, role: "DVWA Web (Port 8080) & Suricata Sensor", cpu: 18, mem: 42 },
    { id: "ag-2", name: "Ubuntu1", ip: "192.168.56.103", on: 1, role: "Wazuh Manager & Indexer (Port 8443)", cpu: 35, mem: 68 },
    { id: "ag-3", name: "kali", ip: "192.168.56.101", on: 1, role: "Kali Attacker (nmap, hydra)", cpu: 45, mem: 52 }
  ];

  let ALERTS = [];
  let BLOCKED = {};
  let RULES = [];
  let CHECKLIST = [
    { text: "Wazuh server running (wazuh-indexer, wazuh-manager)", done: 1 },
    { text: "Victim and DVWA running on Ubuntu Server", done: 1 },
    { text: "Add Host-only adapter to all VMs and test ping", done: 1 },
    { text: "Install Wazuh agent on Victim (Active status)", done: 1 },
    { text: "Install Suricata on Victim and stream eve.json", done: 1 },
    { text: "Import Kali Linux on drive with free space", done: 1 },
    { text: "Run nmap stealth scan and verify alerts", done: 1 },
    { text: "Write custom Suricata rules for SSH & SQLi", done: 1 },
    { text: "Configure active response / iptables blocklist", done: 1 },
    { text: "Benchmark Suricata vs Snort performance", done: 0 },
    { text: "Connect Sentinel IDS dashboard to API", done: 1 },
    { text: "Prepare presentation slides and report", done: 0 }
  ];

  let selectedAgentIdx = 0;
  let activeTab = "ag";
  let subFilter = "all";
  let searchQuery = "";
  let isPaused = false;
  let isLive = true;
  let unreadCount = 0;
  let activePop = null;
  let currentTheme = localStorage.getItem("th") || "dark";
  let currentLang = localStorage.getItem("sentinel_lang") || "vi";
  let alertFilters = { ip: "", type: "", sev: "", status: "" };
  let selectedAlertForModal = null;
  let isServerConnected = false;

  const t0 = Date.now() - 3600 * 1000;

  function tr(key) {
    const dict = window.I18N ? window.I18N[currentLang] : null;
    return (dict && dict[key]) || key;
  }

  function showToast(msg, duration = 2500) {
    const el = $("toast");
    if (!el) return;
    el.textContent = msg;
    el.style.display = "block";
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => {
      el.style.display = "none";
    }, duration);
  }

  function timeAgo(ts) {
    const mins = Math.round((Date.now() - ts) / 60000);
    if (mins < 1) return currentLang === "vi" ? "vừa xong" : "just now";
    if (mins < 60) return mins + " " + (currentLang === "vi" ? "phút trước" : "min ago");
    const h = Math.floor(mins / 60);
    return h + " " + (currentLang === "vi" ? "giờ trước" : "h ago");
  }

  function countBy(fn) {
    const counts = {};
    ALERTS.forEach(a => {
      const k = fn(a);
      counts[k] = (counts[k] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }

  function renderBars(list) {
    if (!list.length) return '<p class="mut">' + tr("all") + '</p>';
    const max = list[0][1] || 1;
    return list.map(([k, v]) => `
      <div class="br">
        <span class="n" title="${k}">${k}</span>
        <span class="t"><i style="width:${(v / max * 100).toFixed(0)}%"></i></span>
        <span class="c">${v}</span>
      </div>
    `).join("");
  }

  function setTheme(theme) {
    currentTheme = theme;
    const root = document.documentElement;
    if (theme === "system") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", theme);
    }
    localStorage.setItem("th", theme);
    const isDark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme:dark)").matches);
    $("tbT").innerHTML = ic(isDark ? "sun" : "moon");
  }

  function updateSoundIcon() {
    const btn = $("soundToggleBtn");
    if (btn && window.sounds) {
      btn.innerHTML = ic(window.sounds.enabled ? "volume" : "volumeMute");
      btn.title = window.sounds.enabled ? tr("soundOn") : tr("soundOff");
    }
  }

  function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem("sentinel_lang", lang);
    renderAll();
    showToast(lang === "vi" ? "Đã chuyển ngôn ngữ: Tiếng Việt" : "Language switched to English");
  }

  function renderLeft() {
    const subContainer = $("sub");
    const SUBS = {
      ag: [["all", tr("all")], ["on", tr("active")], ["off", tr("disconnected")]],
      at: [["all", tr("all")], ["bl", tr("blocked")]]
    };
    subContainer.innerHTML = (SUBS[activeTab] || []).map(([k, label]) => `
      <span data-s="${k}" class="${k === subFilter ? 'on' : ''}">${label}</span>
    `).join("");

    let html = "";
    if (activeTab === "ag") {
      AGENTS.forEach((agent, i) => {
        if (searchQuery && !(agent.name + agent.ip).toLowerCase().includes(searchQuery.toLowerCase())) return;
        const isOnline = (agent.on === 1 || agent.on === true || agent.status === 'active');
        if (subFilter === "on" && !isOnline) return;
        if (subFilter === "off" && isOnline) return;
        html += `
          <div class="li ${i === selectedAgentIdx ? 'on' : ''}" data-a="${i}">
            <span class="av">${ic("srv")}</span>
            <div>
              <b>${agent.name}</b>
              <small>${agent.ip} · CPU ${agent.cpu}%</small>
            </div>
            <span class="dot ${(agent.on === 1 || agent.on === true || agent.status === 'active') ? '' : 'off'}"></span>
          </div>
        `;
      });
    } else {
      const attackers = countBy(a => a.ip);
      const filtered = attackers.filter(([ip]) => {
        if (searchQuery && !ip.includes(searchQuery)) return false;
        if (subFilter === "bl" && !BLOCKED[ip]) return false;
        return true;
      });
      html = filtered.map(([ip, count]) => {
        const topTool = (ALERTS.find(a => a.ip === ip) || {}).tool || "nmap";
        const isBl = !!BLOCKED[ip];
        return `
          <div class="li">
            <span class="av" style="color:${isBl ? 'var(--bad)' : 'var(--warn)'}">${ic("bolt")}</span>
            <div>
              <b>${ip}</b>
              <small>${count} ${tr("alerts")} · ${topTool}</small>
            </div>
            ${isBl 
              ? '<button class="btn s d" style="color:var(--bad)">' + tr("blocked") + '</button>'
              : '<button class="btn s" data-b="' + ip + '">' + tr("blockIp") + '</button>'}
          </div>
        `;
      }).join("");
    }
    $("list").innerHTML = html || ('<p class="mut" style="padding:16px">' + tr("all") + ' (0)</p>');
  }

  function renderHero() {
    const agent = AGENTS[selectedAgentIdx] || AGENTS[0];
    const isOnline = agent.on === 1 || agent.on === true || agent.status === 'active';
    const isOk = isOnline && !isPaused;
    $("hN").textContent = agent.name;
    $("hI").textContent = agent.ip + " · " + (agent.role || ('Wazuh Agent 00' + (selectedAgentIdx + 1)));
    $("pz").textContent = isPaused ? tr("resumeMonitoring") : tr("pauseMonitoring");
    $("va").textContent = tr("viewAlerts");

    const prot = $("prot");
    prot.className = "prot" + (isOk ? "" : " bad");
    $("pT").textContent = !isOnline ? tr("notProtected") : (isPaused ? tr("paused") : tr("protected"));
    $("sIp").textContent = agent.ip;

    // Real-time visual topology adjustment
    const mapEl = document.querySelector(".map svg");
    if (mapEl) {
      const rg = mapEl.querySelector(".rg");
      const atkLine = mapEl.querySelector(".atk");
      const lkLine = mapEl.querySelector(".lk");
      if (rg) rg.style.display = isOnline ? "block" : "none";
      if (atkLine) atkLine.style.opacity = isOnline ? "1" : "0.15";
      if (lkLine) lkLine.style.opacity = isOnline ? "1" : "0.15";
    }

    tickTimer();
  }

  function renderBottom() {
    const now = Date.now();
    const lastHourCount = ALERTS.filter(a => now - a.ts < 3600000).length;
    const loadPct = Math.min(100, lastHourCount * 2);
    $("sLd").innerHTML = loadPct + '% <span class="ld"><i style="width:' + loadPct + '%"></i></span>';
    $("sTot").textContent = ALERTS.length;

    const BUCKETS = 36;
    const allCounts = Array(BUCKETS).fill(0);
    const hiCounts = Array(BUCKETS).fill(0);

    ALERTS.forEach(a => {
      const bucketIdx = Math.floor((now - a.ts) / (5 * 60 * 1000));
      if (bucketIdx < BUCKETS) {
        allCounts[BUCKETS - 1 - bucketIdx]++;
        if (a.sev === "High") hiCounts[BUCKETS - 1 - bucketIdx]++;
      }
    });

    const maxVal = Math.max(4, ...allCounts);
    const toPoints = arr => arr.map((n, i) => {
      const x = (i * 400 / (BUCKETS - 1)).toFixed(1);
      const y = (80 - (n / maxVal * 72)).toFixed(1);
      return x + "," + y;
    }).join(" ");

    $("ch").innerHTML = `
      <line class="gl" x1="0" x2="400" y1="80" y2="80"/>
      <line class="gl" x1="0" x2="400" y1="44" y2="44" stroke-dasharray="2 4"/>
      <line class="gl" x1="0" x2="400" y1="10" x2="400" stroke-dasharray="2 4" stroke-opacity="0.5"/>
      <polyline class="l1" vector-effect="non-scaling-stroke" points="${toPoints(allCounts)}"/>
      <polyline class="l2" vector-effect="non-scaling-stroke" points="${toPoints(hiCounts)}"/>
    `;

    $("cN").innerHTML = `
      <span class="g">▼ ${allCounts[BUCKETS - 1]} ${tr("all")}</span> &nbsp;
      <span class="r">▲ ${hiCounts[BUCKETS - 1]} ${tr("high")}</span> &nbsp;
      max ${maxVal}
    `;
  }

  function renderPop() {
    const pop = $("pop");
    Q(".tl").forEach(el => el.classList.toggle("on", el.dataset.k === activePop));
    if (!activePop) {
      pop.classList.remove("show");
      return;
    }
    pop.classList.add("show");

    if (activePop === "st") {
      pop.innerHTML = `
        <h3>${tr("statistics")}</h3>
        <div class="sec2">${tr("topAttackers")}</div>
        ${renderBars(countBy(a => a.ip).slice(0, 5))}
        <div class="sec2">${tr("attackTypes")}</div>
        ${renderBars(countBy(a => a.type))}
      `;
    } else if (activePop === "bl") {
      const blockedIps = Object.keys(BLOCKED);
      const itemsHtml = blockedIps.length ? blockedIps.map(ip => `
        <div class="row2">
          <span><b>${ip}</b> <small style="display:block;color:var(--mut)">${BLOCKED[ip].reason || 'Active Response'}</small></span>
          <button class="btn s" data-ub="${ip}">${tr("unblock")}</button>
        </div>
      `).join("") : ('<p class="mut">' + tr("noBlockedIps") + '</p>');

      pop.innerHTML = `
        <h3>${tr("blocklist")} (${blockedIps.length})</h3>
        <div style="max-height:220px;overflow:auto">${itemsHtml}</div>
        <button class="btn s p" id="copyIptablesBtn" style="width:100%;margin-top:10px">
          ${ic("copy")} Copy Linux iptables drop rules
        </button>
      `;
    } else if (activePop === "rp") {
      pop.innerHTML = `
        <h3>${tr("report")}</h3>
        <p class="mut">${tr("exportPromo")}</p>
        <div class="btns" style="flex-direction:column;gap:8px">
          <button class="btn p" id="btnExportPdf" style="width:100%">${ic("file")} ${tr("exportPdf")}</button>
          <button class="btn" id="btnExportCsv" style="width:100%">${ic("download")} ${tr("exportCsv")}</button>
        </div>
      `;
    }
  }

  function renderAlertRows() {
    const container = $("alList");
    if (!container) return;

    let list = ALERTS.filter(a => {
      if (alertFilters.ip && !a.ip.includes(alertFilters.ip)) return false;
      if (alertFilters.type && a.type !== alertFilters.type) return false;
      if (alertFilters.sev && a.sev !== alertFilters.sev) return false;
      if (alertFilters.status && a.status !== alertFilters.status) return false;
      return true;
    });

    $("alCount").textContent = list.length + " " + tr("alerts");
    if (!list.length) {
      container.innerHTML = '<p class="mut" style="padding:20px 0">' + tr("all") + ' (0)</p>';
      return;
    }

    container.innerHTML = list.slice(0, 100).map(a => `
      <div class="row cl" data-alert-id="${a.id}">
        <span class="pill ${a.sev}">${a.sev}</span>
        <div>
          <b>${a.type}</b>
          <small>${a.ip}:${a.src_port || 'any'} → ${a.dst_ip || '192.168.56.103'}:${a.dst_port || 80} · ${a.tool} · ${timeAgo(a.ts)}</small>
        </div>
        ${BLOCKED[a.ip] 
          ? '<button class="btn s d" style="color:var(--bad)">' + tr("blocked") + '</button>' 
          : '<button class="btn s" data-b="' + a.ip + '">' + tr("blockIp") + '</button>'}
      </div>
    `).join("");
  }

  function showModalAlert(alert) {
    selectedAlertForModal = alert;
    let modal = $("alertDetailModal");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "alertDetailModal";
      modal.className = "modal-overlay";
      document.body.appendChild(modal);
    }
    modal.innerHTML = `
      <div class="modal-box">
        <div class="ph">
          <h2>${tr("alertDetails")} - <span class="pill ${alert.sev}">${alert.sev}</span></h2>
          <button class="ib" id="closeAlertModal">${ic("x")}</button>
        </div>
        <div class="modal-body">
          <div class="meta-grid">
            <div><label>Attack Type</label><b>${alert.type}</b></div>
            <div><label>Detection Tool</label><b>${alert.tool}</b></div>
            <div><label>Source Address</label><b>${alert.ip}:${alert.src_port || 'N/A'}</b></div>
            <div><label>Destination Target</label><b>${alert.dst_ip || '192.168.56.103'}:${alert.dst_port || 80}</b></div>
            <div><label>Protocol</label><b>${alert.proto || 'TCP'}</b></div>
            <div><label>Timestamp</label><b>${new Date(alert.ts).toLocaleString()}</b></div>
            <div><label>Rule SID</label><b>${alert.sid || 1000001}</b></div>
            <div><label>Status</label><b>${alert.status || 'active'}</b></div>
          </div>
          <div class="sec">${tr("signature")}</div>
          <code class="cm">${alert.signature || alert.type}</code>
          <div class="sec">${tr("payload")}</div>
          <textarea class="f" readonly style="width:100%;height:80px;font-family:ui-monospace,monospace;font-size:12px">${alert.payload || 'No raw payload available'}</textarea>
          
          <div class="sec">${tr("actions")}</div>
          <div class="btns" style="justify-content:flex-start">
            ${BLOCKED[alert.ip] 
              ? '<button class="btn s d">' + tr("blocked") + '</button>' 
              : '<button class="btn p s" data-b="' + alert.ip + '">' + tr("blockIp") + ' (' + alert.ip + ')</button>'}
            <button class="btn s" id="btnResolveAlert">${tr("resolve")}</button>
            <button class="btn s" id="btnFpAlert">${tr("markFp")}</button>
            <button class="btn s" id="btnDownloadJson">${ic("download")} JSON</button>
          </div>
        </div>
      </div>
    `;
    modal.style.display = "flex";
  }

  function getIptablesScript() {
    const ips = Object.keys(BLOCKED);
    if (!ips.length) return "# No IPs currently blocked in Sentinel IDS\n";
    let script = "#!/bin/bash\n# Wazuh / Sentinel IDS Active Response Blocklist Script\n";
    ips.forEach(ip => {
      script += `sudo iptables -A INPUT -s ${ip} -j DROP\n`;
      script += `sudo ufw deny from ${ip} to any comment "Sentinel IDS Block"\n`;
    });
    return script;
  }

  function exportCsv() {
    const headers = ["Timestamp", "Source_IP", "Source_Port", "Dest_IP", "Dest_Port", "Protocol", "Attack_Type", "Tool", "Severity", "SID", "Status"];
    const rows = ALERTS.map(a => [
      new Date(a.ts).toISOString(),
      a.ip,
      a.src_port || "",
      a.dst_ip || "",
      a.dst_port || "",
      a.proto || "TCP",
      `"${a.type}"`,
      a.tool,
      a.sev,
      a.sid || "",
      a.status || "active"
    ]);
    const csvContent = "\uFEFF" + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `sentinel_alerts_${Date.now()}.csv`;
    link.click();
    showToast("Đã tải xuống file CSV cảnh báo an ninh");
  }

  function generateReport() {
    const printArea = $("rep");
    const nowStr = new Date().toLocaleString();
    const topAttackers = countBy(a => a.ip).slice(0, 5);
    const blockedCount = Object.keys(BLOCKED).length;

    printArea.innerHTML = `
      <div style="font-family:Inter,system-ui,sans-serif;padding:24px;color:#1c1b23">
        <div style="border-bottom:2px solid #0f9f84;padding-bottom:12px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <h1 style="margin:0;font-size:24px;color:#0f9f84">SENTINEL IDS – INTRUSION DETECTION REPORT</h1>
            <p style="margin:4px 0 0;color:#6b6878">Báo cáo An ninh Mạng Máy Tính (MMT) · Suricata Sensor & Wazuh SIEM</p>
          </div>
          <div style="text-align:right">
            <b>${nowStr}</b><br>
            <small>Agent: ${AGENTS[selectedAgentIdx].name} (${AGENTS[selectedAgentIdx].ip})</small>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px">
          <div style="background:#f4f5f7;padding:12px;border-radius:6px"><small>Tổng cảnh báo</small><h2 style="margin:4px 0">${ALERTS.length}</h2></div>
          <div style="background:#f4f5f7;padding:12px;border-radius:6px"><small>Mức độ Cao (High)</small><h2 style="margin:4px 0;color:#e5384f">${ALERTS.filter(a => a.sev === 'High').length}</h2></div>
          <div style="background:#f4f5f7;padding:12px;border-radius:6px"><small>IP đã bị chặn</small><h2 style="margin:4px 0;color:#e89b2c">${blockedCount}</h2></div>
          <div style="background:#f4f5f7;padding:12px;border-radius:6px"><small>Trạng thái hệ thống</small><h2 style="margin:4px 0;color:#0f9f84">ACTIVE</h2></div>
        </div>

        <h3>1. Top IP Kẻ Tấn Công (Top Attackers)</h3>
        <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
          <tr style="background:#f4f5f7"><th style="padding:6px;border:1px solid #ddd">Source IP</th><th style="padding:6px;border:1px solid #ddd">Alerts</th><th style="padding:6px;border:1px solid #ddd">Trạng thái</th></tr>
          ${topAttackers.map(([ip, cnt]) => `
            <tr>
              <td style="padding:6px;border:1px solid #ddd">${ip}</td>
              <td style="padding:6px;border:1px solid #ddd">${cnt}</td>
              <td style="padding:6px;border:1px solid #ddd">${BLOCKED[ip] ? 'BLOCKED' : 'MONITORED'}</td>
            </tr>
          `).join("")}
        </table>

        <h3>2. Danh Sách 50 Sự Kiện Cảnh Báo Gần Nhất</h3>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead>
            <tr style="background:#f4f5f7">
              <th style="padding:6px;border:1px solid #ddd">Thời gian</th>
              <th style="padding:6px;border:1px solid #ddd">IP Nguồn</th>
              <th style="padding:6px;border:1px solid #ddd">Loại Tấn Công</th>
              <th style="padding:6px;border:1px solid #ddd">Công Cụ</th>
              <th style="padding:6px;border:1px solid #ddd">Mức Độ</th>
              <th style="padding:6px;border:1px solid #ddd">Mã Luật (SID)</th>
            </tr>
          </thead>
          <tbody>
            ${ALERTS.slice(0, 50).map(a => `
              <tr>
                <td style="padding:5px;border:1px solid #ddd">${new Date(a.ts).toLocaleTimeString()}</td>
                <td style="padding:5px;border:1px solid #ddd">${a.ip}</td>
                <td style="padding:5px;border:1px solid #ddd">${a.type}</td>
                <td style="padding:5px;border:1px solid #ddd">${a.tool}</td>
                <td style="padding:5px;border:1px solid #ddd;color:${a.sev === 'High' ? '#e5384f' : a.sev === 'Medium' ? '#e89b2c' : '#0f9f84'};font-weight:bold">${a.sev}</td>
                <td style="padding:5px;border:1px solid #ddd">${a.sid || 1000001}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
    window.print();
  }

  function openPanel(viewKey, subView = "main") {
    activePop = null;
    renderPop();
    const panel = $("panel");
    panel.className = "panel show";

    if (viewKey === "al") {
      panel.innerHTML = `
        <div class="ph">
          <h1>${tr("alerts")} (<span id="alCount">${ALERTS.length}</span>)</h1>
          <button class="ib" id="closePanelBtn">${ic("x")}</button>
        </div>
        <div class="pb">
          <div class="fl">
            <input class="f" id="fIp" placeholder="${tr("filterIp")}" value="${alertFilters.ip}">
            <select class="f" id="fTy">
              <option value="">${tr("allTypes")}</option>
              <option value="Port scan">Port scan (nmap)</option>
              <option value="SSH brute force">SSH brute force (Hydra)</option>
              <option value="SQL injection">SQL injection (sqlmap)</option>
              <option value="SYN flood">SYN flood (hping3)</option>
              <option value="Sensitive File Access">Sensitive File Access (curl)</option>
            </select>
            <select class="f" id="fSv">
              <option value="">${tr("allSeverities")}</option>
              <option value="High">${tr("high")}</option>
              <option value="Medium">${tr("medium")}</option>
              <option value="Low">${tr("low")}</option>
            </select>
            <button class="btn s p" id="btnPanelExport" style="height:40px">${ic("file")} ${tr("exportPdf")}</button>
            <button class="btn s" id="btnClearAlerts" style="height:40px;color:var(--bad)">Xóa tất cả</button>
          </div>
          <div id="alList"></div>
        </div>
      `;
      unreadCount = 0;
      updateBadge();
      renderAlertRows();

      $("fIp").oninput = e => { alertFilters.ip = e.target.value.trim(); renderAlertRows(); };
      $("fTy").onchange = e => { alertFilters.type = e.target.value; renderAlertRows(); };
      $("fSv").onchange = e => { alertFilters.sev = e.target.value; renderAlertRows(); };
      $("btnPanelExport").onclick = generateReport;
      $("btnClearAlerts").onclick = () => {
        if (confirm("Bạn có chắc chắn muốn xóa tất cả lịch sử cảnh báo không?")) {
          ALERTS = [];
          renderAll();
          showToast("Đã xóa sạch cảnh báo.");
          if (isServerConnected) fetch('/api/alerts', { method: 'DELETE' });
        }
      };
      return;
    }

    const VIEWS = {
      lab: () => [
        "Cẩm nang vận hành Lab IDS (Wazuh + Suricata + DVWA + Kali)",
        `
        <div class="wn" style="margin-bottom:14px">
          <b>Mô hình triển khai:</b> Kali (192.168.56.101) → Victim (192.168.56.102) → Ubuntu1 / Wazuh Server (192.168.56.103).<br>
          Chỉ tấn công IP của Victim. RAM tối thiểu 12 GB, ổ cứng trống ~60 GB.
        </div>

        <div class="sec">1. Lối tắt truy cập nhanh (Quick Access)</div>
        <div class="btns" style="justify-content:flex-start;margin-bottom:16px">
          <a href="https://localhost:8443" target="_blank" class="btn p s">Mở Wazuh Dashboard (Port 8443)</a>
          <a href="http://localhost:8080" target="_blank" class="btn s">Mở DVWA (Port 8080)</a>
          <button class="btn s" id="btnCopyWazuhPass">Copy Pass Wazuh</button>
          <button class="btn s" id="btnCopySshVictim">Copy SSH Victim</button>
          <button class="btn s" id="btnCopySshUbuntu">Copy SSH Ubuntu1</button>
        </div>

        <div class="sec">2. Thứ tự bật & tắt máy ảo</div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <b>Thứ tự BẬT:</b>
          <small>1) <b>Ubuntu1</b> (Bật server, đợi 2-3 phút cho indexer & manager khởi động xong)</small>
          <small>2) <b>Victim</b> (Bật server, đợi 1-2 phút cho Suricata và wazuh-agent khởi động)</small>
          <small>3) <b>Kali</b> (Bật sau cùng để chuẩn bị tấn công)</small>
          <b style="margin-top:6px">Thứ tự TẮT:</b>
          <small>Tắt ngược lại: Kali → Victim → Ubuntu1. Trên mỗi máy chạy: <code>sudo shutdown now</code> (Tuyệt đối không tắt đột ngột bằng Power Off để tránh hỏng DB).</small>
        </div>

        <div class="sec">3. Tài khoản & Thông tin đăng nhập</div>
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px">
          <tr style="background:var(--card)"><th style="padding:8px;border:1px solid var(--line);text-align:left">Máy ảo</th><th style="padding:8px;border:1px solid var(--line);text-align:left">Tài khoản SSH</th><th style="padding:8px;border:1px solid var(--line);text-align:left">Giao diện Web / Dịch vụ</th></tr>
          <tr><td style="padding:8px;border:1px solid var(--line)"><b>Ubuntu1</b> (Wazuh Server)</td><td style="padding:8px;border:1px solid var(--line)"><code>ssh vuph@localhost</code><br>Pass: <code>password</code></td><td style="padding:8px;border:1px solid var(--line)"><b>https://localhost:8443</b><br>User: <code>admin</code><br>Pass: <code>3Jl0Lt7Hv.Righz2YZO04*+rkdkbMOCC</code></td></tr>
          <tr><td style="padding:8px;border:1px solid var(--line)"><b>Victim</b> (Nạn nhân)</td><td style="padding:8px;border:1px solid var(--line)"><code>ssh -p 2222 victim@localhost</code><br>Pass: <code>password</code></td><td style="padding:8px;border:1px solid var(--line)"><b>http://localhost:8080</b> (DVWA)<br>Log: <code>/var/log/suricata/fast.log</code></td></tr>
          <tr><td style="padding:8px;border:1px solid var(--line)"><b>Kali</b> (Attacker)</td><td style="padding:8px;border:1px solid var(--line)">Đăng nhập máy ảo:<br>User: <code>kali</code> | Pass: <code>kali</code></td><td style="padding:8px;border:1px solid var(--line)">IP Host-only: <code>192.168.56.x</code> (eth1)</td></tr>
        </table>

        <div class="sec">4. Lệnh kiểm thử & Dấu hiệu thành công</div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <b>Bước 1: Bắn lệnh quét từ Kali</b>
          <code class="cm">nmap -sS -sV 192.168.56.102</code>
          <code class="cm">nmap -sC -p 80 192.168.56.102</code>
          <b>Bước 2: Kiểm tra log thời gian thực trên Victim</b>
          <code class="cm">sudo tail -f /var/log/suricata/fast.log</code>
          <b>Bước 3: Xem kết quả trên Wazuh Dashboard</b>
          <small>Vào menu <b>Threat Intelligence → Threat Hunting → Events</b>, nhập bộ lọc: <code>rule.groups: suricata</code>.</small>
          <small><b>DẤU HIỆU THÀNH CÔNG:</b> Cột Signature xuất hiện cảnh báo <b>"ET SCAN Possible Nmap User-Agent Observed"</b> và máy Victim có trạng thái Active trong Endpoints.</small>
        </div>

        <div class="sec">5. Xử lý sự cố nếu IP DHCP bị đổi</div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <small>Nếu IP Ubuntu1 khác 192.168.56.103:</small>
          <small>1) Trên Ubuntu1 lấy IP mới: <code>ip -br addr show enp0s8</code></small>
          <small>2) Trên Victim trỏ lại agent về IP mới:</small>
          <code class="cm">sudo sed -i 's|<address>.*</address>|<address>IP-UBUNTU1-MOI</address>|' /var/ossec/etc/ossec.conf\nsudo systemctl restart wazuh-agent</code>
          <small>3) Nếu card mạng Victim đổi tên, sửa HOME_NET và interface trong <code>/etc/suricata/suricata.yaml</code> rồi chạy <code>sudo systemctl restart suricata</code>.</small>
        </div>
        `
      ],
      main: () => [
        tr("settings"),
        `
        <div class="row cl" data-v="prof">
          <span class="avt">${ic("user")}</span>
          <div><b>Pikachu-Learner</b><small>Đồ Án Mạng Máy Tính (MMT) · Nhóm 3</small></div>
          <span class="mut">›</span>
        </div>
        <div class="sec">Kết nối Lab & Dịch vụ</div>
        <div class="g3">
          <div class="cd cl" data-v="api"><span class="ci">${ic("srv")}</span><div><b>Wazuh API</b><small>Port 55000 · JWT</small></div></div>
          <div class="cd cl" data-v="idx"><span class="ci">${ic("chart")}</span><div><b>Indexer</b><small>Port 9200</small></div></div>
          <div class="cd cl" data-v="sur"><span class="ci">${ic("shield")}</span><div><b>Suricata</b><small>eve.json · 53,103 rules</small></div></div>
          <div class="cd cl" data-v="net"><span class="ci">${ic("net")}</span><div><b>Lab Network</b><small>Host-only 192.168.56.x</small></div></div>
          <div class="cd cl" data-v="rul"><span class="ci">${ic("term")}</span><div><b>${tr("customRules")}</b><small>${RULES.length} luật tùy chỉnh</small></div></div>
          <div class="cd cl" data-v="cmp"><span class="ci">${ic("cmp")}</span><div><b>So sánh Snort</b><small>Tiêu chí đồ án</small></div></div>
        </div>
        <div class="sec">Tùy chọn chung</div>
        <div class="row"><div>Ngôn ngữ giao diện (Language)</div>
          <select class="f" id="selLang">
            <option value="vi" ${currentLang === 'vi' ? 'selected' : ''}>Tiếng Việt</option>
            <option value="en" ${currentLang === 'en' ? 'selected' : ''}>English</option>
          </select>
        </div>
        <div class="row"><div>Giao diện (Theme)</div>
          <select class="f" id="selTheme">
            <option value="dark" ${currentTheme === 'dark' ? 'selected' : ''}>Dark (Tối)</option>
            <option value="light" ${currentTheme === 'light' ? 'selected' : ''}>Light (Sáng)</option>
            <option value="system" ${currentTheme === 'system' ? 'selected' : ''}>System (Hệ thống)</option>
          </select>
        </div>
        <div class="row"><div>Âm thanh cảnh báo (Audio Alarms)</div>
          <input type="checkbox" class="tg" id="tgSound" ${window.sounds && window.sounds.enabled ? 'checked' : ''}>
        </div>
        <div class="row"><div>Tự động tạo traffic giả lập (Auto Live Demo)</div>
          <input type="checkbox" class="tg" id="tgLive" ${isLive ? 'checked' : ''}>
        </div>
        <div class="sec">Công cụ kiểm thử & Đồ án</div>
        <div class="row cl" data-v="lab"><span class="ci">${ic("shield")}</span><div><b>Cẩm nang chạy Lab IDS (Wazuh + Suricata)</b><small>Tài khoản, mật khẩu, thứ tự bật tắt, lệnh test</small></div><span class="mut">›</span></div>
        <div class="row cl" data-v="atk"><span class="ci">${ic("bug")}</span><div><b>${tr("attackScenarios")}</b><small>nmap, Hydra, sqlmap, hping3</small></div><span class="mut">›</span></div>
        <div class="row cl" data-v="rul"><span class="ci">${ic("term")}</span><div><b>${tr("customRules")}</b><small>Trình soạn thảo & kiểm tra cú pháp luật</small></div><span class="mut">›</span></div>
        <div class="row cl" data-v="chk"><span class="ci">${ic("list")}</span><div><b>${tr("checklist")}</b><small>Theo dõi tiến độ đồ án</small></div><span class="mut">›</span></div>
        <div class="row cl" data-v="help"><span class="ci">${ic("help")}</span><div><b>${tr("help")}</b><small>Sửa lỗi VirtualBox, Wazuh và Suricata</small></div><span class="mut">›</span></div>
        <div class="row cl" data-v="about"><span class="ci">${ic("shield")}</span><div><b>${tr("about")}</b><small>Phiên bản & hướng dẫn sử dụng</small></div><span class="mut">›</span></div>
        `
      ],
      atk: () => [
        tr("attackScenarios"),
        `
        <div class="wn" style="margin-bottom:16px">
          <b>Lưu ý quan trọng:</b> Chỉ thực hiện kiểm thử an ninh trong dải mạng nội bộ máy ảo Host-only (192.168.56.x). Tuyệt đối không tấn công mạng trường hoặc máy tính ngoài phạm vi cho phép.
        </div>
        ${window.attackSimulator ? window.attackSimulator.scenarios.map(sc => `
          <div class="row" style="flex-direction:column;align-items:stretch;gap:8px;padding:14px">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div><b>${sc.name}</b> <span class="pill ${sc.sev}">${sc.sev}</span> · <code>${sc.tool}</code></div>
              <button class="btn s p" data-run-sim="${sc.name}">${tr("runDemo")}</button>
            </div>
            <small style="color:var(--mut)">${sc.desc}</small>
            <code class="cm">${sc.command}</code>
          </div>
        `).join("") : ''}
        `
      ],
      rul: () => [
        tr("customRules"),
        `
        <div class="fl" style="margin-bottom:14px">
          <button class="btn p s" id="btnOpenNewRuleModal">+ ${tr("addRule")}</button>
          <button class="btn s" id="btnValidateAllRules">${tr("validateRule")}</button>
        </div>
        <div id="rulesList">
          ${RULES.map(r => `
            <div class="row" style="flex-direction:column;align-items:stretch;gap:8px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div>
                  <b>SID ${r.sid}: ${r.name}</b>
                  <small style="display:block;color:var(--mut)">${r.desc || ''}</small>
                </div>
                <div style="display:flex;gap:8px;align-items:center">
                  <input type="checkbox" class="tg" data-rule-toggle="${r.id}" ${r.enabled ? 'checked' : ''}>
                  <button class="btn s" data-rule-del="${r.id}" style="color:var(--bad)">Xóa</button>
                </div>
              </div>
              <code class="cm" style="user-select:all">${r.raw}</code>
            </div>
          `).join("")}
        </div>
        `
      ],
      chk: () => {
        const completed = CHECKLIST.filter(c => c.done).length;
        const pct = Math.round(completed / CHECKLIST.length * 100);
        return [
          tr("checklist"),
          `
          <div class="br" style="margin-bottom:16px">
            <span class="t"><i style="width:${pct}%"></i></span>
            <span class="c" style="width:auto;margin-left:12px;font-weight:bold">${completed}/${CHECKLIST.length} (${pct}%)</span>
          </div>
          ${CHECKLIST.map((item, idx) => `
            <div class="row">
              <div>${item.text}</div>
              <input type="checkbox" class="tg" data-ck-idx="${idx}" ${item.done ? 'checked' : ''}>
            </div>
          `).join("")}
          `
        ];
      },
      help: () => [
        tr("help"),
        `
        <div class="row" style="flex-direction:column;align-items:stretch">
          <b>1. Ubuntu 24.04 / Wazuh Server không khởi động được API?</b>
          <small>Kiểm tra trạng thái dịch vụ:</small>
          <code class="cm">sudo systemctl status wazuh-manager wazuh-indexer</code>
          <small>Nếu indexer chết do RAM, khởi động lại theo thứ tự: indexer -> chờ 30s -> manager.</small>
        </div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <b>2. Suricata không ghi nhận cảnh báo vào eve.json?</b>
          <small>Đảm bảo interface card mạng đúng với card Host-only:</small>
          <code class="cm">sudo suricata -i enp0s8 -c /etc/suricata/suricata.yaml -D</code>
          <small>Theo dõi log thời gian thực: <code>sudo tail -f /var/log/suricata/eve.json</code></small>
        </div>
        <div class="row" style="flex-direction:column;align-items:stretch">
          <b>3. Các máy ảo không ping thấy nhau trong VirtualBox?</b>
          <small>Vào VirtualBox -> Settings của từng máy ảo -> Network -> Adapter 2 -> Chọn 'Host-only Adapter' (VirtualBox Host-Only Ethernet Adapter), Promiscuous Mode: Allow All.</small>
        </div>
        `
      ],
      about: () => [
        tr("about"),
        `
        <div class="row">
          <div>
            <b>Sentinel IDS - Phiên Bản Đồ Án MMT</b>
            <small>Được xây dựng cho đồ án môn Mạng Máy Tính & An Ninh Mạng</small>
          </div>
        </div>
        <div class="sec">Công nghệ & Kiến trúc</div>
        <div class="row"><div>Hệ điều hành máy ảo</div><b>Ubuntu 24.04 LTS & Kali Linux 2026</b></div>
        <div class="row"><div>Công cụ phát hiện xâm nhập</div><b>Suricata 7.x & Wazuh SIEM 4.x</b></div>
        <div class="row"><div>Cơ chế ngăn chặn chủ động</div><b>Linux iptables & Wazuh Active Response</b></div>
        <div class="row"><div>Web Dashboard</div><b>HTML5, Vanilla CSS Glassmorphism, Web Audio</b></div>
        `
      ]
    };

    const viewFn = VIEWS[subView] || VIEWS.main;
    const [title, contentHtml] = viewFn();

    panel.innerHTML = `
      <div class="ph">
        <div class="pt">
          ${subView === "main" ? "" : '<button class="ib" data-v="main">' + ic("back") + '</button>'}
          <h1>${title}</h1>
        </div>
        <button class="ib" id="closePanelBtn">${ic("x")}</button>
      </div>
      <div class="pb">${contentHtml}</div>
    `;

    const selLang = $("selLang");
    if (selLang) selLang.onchange = e => setLanguage(e.target.value);

    const selTheme = $("selTheme");
    if (selTheme) selTheme.onchange = e => setTheme(e.target.value);

    const tgSound = $("tgSound");
    if (tgSound && window.sounds) {
      tgSound.onchange = e => {
        window.sounds.enabled = e.target.checked;
        localStorage.setItem("sentinel_sound", e.target.checked ? "1" : "0");
        updateSoundIcon();
      };
    }

    const tgLive = $("tgLive");
    if (tgLive) tgLive.onchange = e => { isLive = e.target.checked; };

    const btnNewRule = $("btnOpenNewRuleModal");
    if (btnNewRule) {
      btnNewRule.onclick = () => {
        const raw = prompt("Nhập luật Suricata mới (Ví dụ: alert tcp any any -> $HOME_NET 80 (msg:\"Custom\"; sid:1000099; rev:1;)):");
        if (raw && raw.trim()) {
          const newRule = {
            id: Date.now(),
            sid: 1000000 + RULES.length + 1,
            name: "Custom Rule " + (RULES.length + 1),
            raw: raw.trim(),
            enabled: true,
            desc: "Luật tự định nghĩa bởi người dùng"
          };
          RULES.push(newRule);
          localStorage.setItem("sentinel_rules", JSON.stringify(RULES));
          openPanel("se", "rul");
          showToast("Đã lưu luật Suricata mới!");
        }
      };
    }
  }

  function tickTimer() {
    const agent = AGENTS[selectedAgentIdx];
    const isOnline = agent && (agent.on === 1 || agent.on === true || agent.status === 'active');
    if (!agent || !isOnline || isPaused) {
      $("pS").textContent = "";
      return;
    }
    const secs = Math.floor((Date.now() - t0) / 1000);
    const m = Math.floor(secs / 60);
    const s = String(secs % 60).padStart(2, "0");
    $("pS").textContent = "• " + m + " min " + s + " sec";
  }

  function updateBadge() {
    const el = $("bd");
    if (unreadCount > 0) {
      el.style.display = "block";
      el.textContent = unreadCount > 99 ? "99+" : unreadCount;
    } else {
      el.style.display = "none";
    }
  }

  function pushAlert(newAlert) {
    ALERTS.unshift(newAlert);
    if (ALERTS.length > 500) ALERTS.pop();
    unreadCount++;
    updateBadge();
    renderBottom();

    if (activeTab === "at") renderLeft();
    if (activePop) renderPop();
    if ($("alList")) renderAlertRows();

    if (window.sounds) window.sounds.playAlert(newAlert.sev);
    if (window.attackSimulator) window.attackSimulator.animateMapAttack();
  }

  function blockIp(ip, reason = "Cảnh báo an ninh từ Sentinel IDS") {
    BLOCKED[ip] = {
      ip,
      reason,
      blockedAt: Date.now(),
      duration: 3600
    };
    localStorage.setItem("sentinel_blocked", JSON.stringify(BLOCKED));
    renderAll();
    showToast("Đã chặn IP " + ip + " (Kích hoạt Active Response iptables)");
    if (window.sounds) window.sounds.playSuccess();
    if (isServerConnected) {
      fetch('/api/blocklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason })
      }).catch(() => {});
    }
  }

  function unblockIp(ip) {
    if (BLOCKED[ip]) {
      delete BLOCKED[ip];
      localStorage.setItem("sentinel_blocked", JSON.stringify(BLOCKED));
      renderAll();
      showToast("Đã gỡ chặn IP " + ip);
      if (isServerConnected) {
        fetch('/api/blocklist/' + ip, { method: 'DELETE' }).catch(() => {});
      }
    }
  }

  function seedMockData() {
    const savedAlerts = localStorage.getItem("sentinel_alerts");
    if (savedAlerts) {
      try { ALERTS = JSON.parse(savedAlerts); } catch (e) {}
    }
    if (!ALERTS.length) {
      const types = [
        { type: "Port scan", tool: "nmap", sev: "Low", sid: 1000004, sig: "ET SCAN Nmap TCP SYN Port Scan", payload: "TCP SYN port probe" },
        { type: "SSH brute force", tool: "Hydra", sev: "High", sid: 1000001, sig: "ET SCAN Potential SSH Brute Force Attempt", payload: "Failed password for root" },
        { type: "SQL injection", tool: "sqlmap", sev: "High", sid: 1000002, sig: "ET WEB_SPECIFIC_APPS DVWA SQL Injection Attempt", payload: "1' UNION SELECT user,password FROM users--" },
        { type: "SYN flood", tool: "hping3", sev: "Medium", sid: 1000003, sig: "ET DOS Possible TCP SYN Flood", payload: "SYN flood 100+ pps" }
      ];
      const ips = ["192.168.56.101", "192.168.56.102", "192.168.56.110", "100.64.0.7"];
      const now = Date.now();
      for (let i = 0; i < 60; i++) {
        const t = types[Math.floor(Math.random() * types.length)];
        const ip = ips[Math.floor(Math.random() * ips.length)];
        ALERTS.push({
          id: 'ALT-' + (1000 + i),
          ts: now - Math.floor(Math.pow(Math.random(), 2) * 86400000),
          ip: ip,
          src_port: Math.floor(30000 + Math.random() * 30000),
          dst_ip: '192.168.56.103',
          dst_port: t.type === 'SSH brute force' ? 22 : 80,
          proto: 'TCP',
          type: t.type,
          tool: t.tool,
          sev: t.sev,
          sid: t.sid,
          signature: t.sig,
          payload: t.payload,
          status: 'active'
        });
      }
      ALERTS.sort((a, b) => b.ts - a.ts);
    }

    const savedRules = localStorage.getItem("sentinel_rules");
    if (savedRules) {
      try { RULES = JSON.parse(savedRules); } catch (e) {}
    }
    if (!RULES.length) {
      RULES = [
        { id: 1, sid: 1000001, name: "SSH Brute Force", raw: 'alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; threshold:type both, count 5, seconds 60; sid:1000001; rev:1;)', enabled: true, desc: "Phát hiện vét cạn SSH" },
        { id: 2, sid: 1000002, name: "SQL Injection DVWA", raw: 'alert tcp any any -> $HOME_NET 80 (msg:"DVWA SQLi Attempt"; content:"UNION"; nocase; sid:1000002; rev:1;)', enabled: true, desc: "Phát hiện SQLi" },
        { id: 3, sid: 1000003, name: "SYN Flood DoS", raw: 'alert tcp any any -> $HOME_NET any (msg:"SYN Flood"; flags:S; threshold:count 100, seconds 1; sid:1000003; rev:1;)', enabled: true, desc: "Phát hiện DoS" }
      ];
    }

    const savedBlocked = localStorage.getItem("sentinel_blocked");
    if (savedBlocked) {
      try { BLOCKED = JSON.parse(savedBlocked); } catch (e) {}
    } else {
      BLOCKED = { "192.168.56.110": { ip: "192.168.56.110", reason: "SYN flood DoS", blockedAt: Date.now() - 3600000 } };
    }
  }

  async function syncWithServer() {
    try {
      const res = await fetch('/api/alerts?limit=100');
      if (res.ok) {
        const json = await res.json();
        if (json.data && json.data.length) {
          ALERTS = json.data;
          isServerConnected = true;
        }
      }
      const blRes = await fetch('/api/blocklist');
      if (blRes.ok) {
        BLOCKED = await blRes.json();
      }
      const rulRes = await fetch('/api/rules');
      if (rulRes.ok) {
        RULES = await rulRes.json();
      }
      const agRes = await fetch('/api/agents');
      if (agRes.ok) {
        const list = await agRes.json();
        if (list.length) {
          AGENTS = list.map(a => ({
            ...a,
            on: (a.on === 1 || a.on === true || a.status === 'active') ? 1 : 0
          }));
        }
      }
      renderAll();
      initSSE();
    } catch (e) {
      isServerConnected = false;
    }
  }

  function initSSE() {
    if (!window.EventSource) return;
    try {
      const evtSource = new EventSource('/api/events');
      evtSource.addEventListener('new_alert', e => {
        const alert = JSON.parse(e.data);
        pushAlert(alert);
      });
      evtSource.addEventListener('ip_blocked', e => {
        const item = JSON.parse(e.data);
        BLOCKED[item.ip] = item;
        renderAll();
      });
      evtSource.addEventListener('ip_unblocked', e => {
        const { ip } = JSON.parse(e.data);
        delete BLOCKED[ip];
        renderAll();
      });
      evtSource.addEventListener('agents_updated', e => {
        try {
          const list = JSON.parse(e.data);
          if (list && list.length) {
            AGENTS = list.map(a => ({
              ...a,
              on: (a.on === 1 || a.status === 'active') ? 1 : 0
            }));
            renderAll();
          }
        } catch (err) {}
      });
    } catch (err) {}
  }

  function renderAll() {
    renderLeft();
    renderHero();
    renderBottom();
    updateBadge();
    updateSoundIcon();
    if (activePop) renderPop();
    if ($("alList")) renderAlertRows();
  }

  document.addEventListener("click", e => {
    const target = e.target;
    const match = selector => target.closest(selector);
    let el;

    if ((el = match("[data-v]"))) {
      openPanel("se", el.dataset.v);
      return;
    }

    if ((el = match("[data-b]"))) {
      e.stopPropagation();
      blockIp(el.dataset.b);
      return;
    }

    if ((el = match("[data-ub]"))) {
      e.stopPropagation();
      unblockIp(el.dataset.ub);
      return;
    }

    if ((el = match("[data-a]"))) {
      selectedAgentIdx = parseInt(el.dataset.a, 10);
      renderAll();
      return;
    }

    if ((el = match("[data-t]"))) {
      activeTab = el.dataset.t;
      subFilter = "all";
      Q(".tab").forEach(t => t.classList.toggle("on", t.dataset.t === activeTab));
      renderLeft();
      return;
    }

    if ((el = match("[data-s]"))) {
      subFilter = el.dataset.s;
      renderLeft();
      return;
    }

    if ((el = match("[data-k]"))) {
      const key = el.dataset.k;
      if (key === "al" || key === "se") {
        openPanel(key);
      } else {
        activePop = activePop === key ? null : key;
        renderPop();
      }
      return;
    }

    if ((el = match("[data-m]"))) {
      $("menu").classList.remove("show");
      const [m, v] = el.dataset.m.split(":");
      if (m === "rp") generateReport();
      else if (m === "al") openPanel("al");
      else openPanel(m, v || "main");
      return;
    }

    if (match("#closePanelBtn")) {
      const panel = $("panel");
      panel.className = "panel";
      panel.innerHTML = "";
      return;
    }

    if (match("#closeAlertModal") || match(".modal-overlay") === target) {
      const m = $("alertDetailModal");
      if (m) m.style.display = "none";
      return;
    }

    if ((el = match("[data-alert-id]"))) {
      if (match("[data-b]")) return;
      const alertId = el.dataset.alertId;
      const found = ALERTS.find(a => a.id === alertId);
      if (found) showModalAlert(found);
      return;
    }

    if (match("#btnResolveAlert")) {
      if (selectedAlertForModal) {
        selectedAlertForModal.status = "resolved";
        showToast("Đã đánh dấu xử lý thành công");
        $("alertDetailModal").style.display = "none";
        renderAll();
      }
      return;
    }
    if (match("#btnFpAlert")) {
      if (selectedAlertForModal) {
        selectedAlertForModal.status = "false_positive";
        showToast("Đã ghi nhận báo cáo False Positive");
        $("alertDetailModal").style.display = "none";
        renderAll();
      }
      return;
    }
    if (match("#btnDownloadJson")) {
      if (selectedAlertForModal) {
        const blob = new Blob([JSON.stringify(selectedAlertForModal, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = 'alert_' + selectedAlertForModal.id + '.json';
        a.click();
      }
      return;
    }

    if ((el = match("[data-run-sim]"))) {
      const simName = el.dataset.runSim;
      const scenario = window.attackSimulator ? window.attackSimulator.getScenario(simName) : null;
      if (scenario) {
        const simAlert = {
          id: 'SIM-' + Date.now().toString().slice(-6),
          ts: Date.now(),
          ip: "192.168.56.101",
          src_port: Math.floor(35000 + Math.random() * 20000),
          dst_ip: "192.168.56.103",
          dst_port: scenario.dstPort,
          proto: scenario.proto,
          type: scenario.name,
          tool: scenario.tool,
          sev: scenario.sev,
          sid: scenario.sid,
          signature: scenario.sig,
          payload: scenario.payload,
          status: "active"
        };
        pushAlert(simAlert);
        showToast("Đã mô phỏng: " + scenario.name + " (" + scenario.tool + ")");
      }
      return;
    }

    if ((el = match("[data-rule-toggle]"))) {
      const ruleId = parseInt(el.dataset.ruleToggle, 10);
      const rule = RULES.find(r => r.id === ruleId);
      if (rule) {
        rule.enabled = el.checked;
        localStorage.setItem("sentinel_rules", JSON.stringify(RULES));
        showToast("Luật SID " + rule.sid + " đã " + (rule.enabled ? 'kích hoạt' : 'tắt'));
      }
      return;
    }
    if ((el = match("[data-rule-del]"))) {
      const ruleId = parseInt(el.dataset.ruleDel, 10);
      if (confirm("Bạn có chắc muốn xóa luật này không?")) {
        RULES = RULES.filter(r => r.id !== ruleId);
        localStorage.setItem("sentinel_rules", JSON.stringify(RULES));
        openPanel("se", "rul");
        showToast("Đã xóa luật Suricata.");
      }
      return;
    }

    if ((el = match("[data-ck-idx]"))) {
      const idx = parseInt(el.dataset.ckIdx, 10);
      if (CHECKLIST[idx]) {
        CHECKLIST[idx].done = el.checked ? 1 : 0;
        localStorage.setItem("sentinel_checklist", JSON.stringify(CHECKLIST));
      }
      return;
    }

    
    if (match("#btnCopyWazuhPass")) {
      navigator.clipboard.writeText("3Jl0Lt7Hv.Righz2YZO04*+rkdkbMOCC").then(() => {
        showToast("Đã copy mật khẩu Wazuh: 3Jl0Lt7Hv.Righz2YZO04*+rkdkbMOCC");
      });
      return;
    }
    if (match("#btnCopySshVictim")) {
      navigator.clipboard.writeText("ssh -p 2222 victim@localhost").then(() => {
        showToast("Đã copy lệnh SSH Victim: ssh -p 2222 victim@localhost");
      });
      return;
    }
    if (match("#btnCopySshUbuntu")) {
      navigator.clipboard.writeText("ssh vuph@localhost").then(() => {
        showToast("Đã copy lệnh SSH Ubuntu1: ssh vuph@localhost");
      });
      return;
    }

    if (match("#copyIptablesBtn")) {
      const script = getIptablesScript();
      navigator.clipboard.writeText(script).then(() => {
        showToast("Đã copy lệnh iptables vào Clipboard!");
      }).catch(() => {
        prompt("Lệnh iptables của bạn:", script);
      });
      return;
    }

    if (match("#pr") || match("#btnExportPdf")) {
      generateReport();
      return;
    }
    if (match("#btnExportCsv")) {
      exportCsv();
      return;
    }

    if (match("#va")) {
      openPanel("al");
      return;
    }
    if (match("#pz")) {
      isPaused = !isPaused;
      renderHero();
      showToast(isPaused ? "Đã tạm dừng giám sát" : "Tiếp tục giám sát");
      return;
    }

    if (match("#tbT")) {
      setTheme(currentTheme === "dark" ? "light" : "dark");
      return;
    }
    if (match("#soundToggleBtn")) {
      if (window.sounds) {
        const on = window.sounds.toggle();
        updateSoundIcon();
        showToast(on ? tr("soundOn") : tr("soundOff"));
      }
      return;
    }
    if (match("#mn")) {
      $("menu").classList.toggle("show");
      return;
    }

    if (!match("#mn") && !match("#menu")) {
      $("menu").classList.remove("show");
    }
    if (activePop && !match(".pop") && !match(".tl")) {
      activePop = null;
      renderPop();
    }
  });

  $("q").oninput = e => {
    searchQuery = e.target.value.trim();
    renderLeft();
  };

  setInterval(tickTimer, 1000);

  // Real-time synchronization of VM agent status every 3 seconds
  setInterval(async () => {
    try {
      const res = await fetch('/api/agents');
      if (res.ok) {
        const list = await res.json();
        if (list && list.length) {
          AGENTS = list.map(a => ({
            ...a,
            on: (a.on === 1 || a.status === 'active') ? 1 : 0
          }));
          renderLeft();
          renderHero();
        }
      }
    } catch (e) {}
  }, 3000);

  // Normalize on-state
  AGENTS.forEach(a => { a.on = 1; a.status = 'active'; });
  seedMockData();
  setTheme(currentTheme);
  renderAll();
  syncWithServer();
})();