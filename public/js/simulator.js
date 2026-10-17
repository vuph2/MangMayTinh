/**
 * Sentinel IDS - Attack Simulation Engine & Topology Animator
 * Cấu hình chuẩn theo mô hình Lab IDS:
 * Kali (192.168.56.101) -> Victim (192.168.56.102) -> Ubuntu1 / Wazuh Server (192.168.56.103)
 */
class AttackSimulator {
  constructor() {
    this.scenarios = [
      {
        id: "nmap_syn",
        name: "Port scan (SYN scan)",
        tool: "nmap",
        command: "nmap -sS -sV 192.168.56.102",
        sev: "Low",
        dstPort: 80,
        proto: "TCP",
        sid: 1000004,
        sig: "ET SCAN Possible Nmap User-Agent Observed",
        payload: "TCP SYN probe from 192.168.56.101 to 192.168.56.102 on ports 22, 80",
        desc: "Lệnh kiểm thử chính thức của bài Lab: nmap -sS -sV 192.168.56.102"
      },
      {
        id: "nmap_scripts",
        name: "Nmap HTTP Script Scan",
        tool: "nmap",
        command: "nmap -sC -p 80 192.168.56.102",
        sev: "Medium",
        dstPort: 80,
        proto: "TCP",
        sid: 1000004,
        sig: "ET SCAN Nmap Scripting Engine Probe",
        payload: "GET / HTTP/1.1\r\nHost: 192.168.56.102\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        desc: "Quét lỗ hổng HTTP DVWA bằng Nmap Scripting Engine."
      },
      {
        id: "ssh_brute",
        name: "SSH brute force",
        tool: "Hydra",
        command: "hydra -l victim -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.102",
        sev: "High",
        dstPort: 22,
        proto: "TCP",
        sid: 1000001,
        sig: "ET SCAN Potential SSH Brute Force Attempt",
        payload: "SSH-2.0-OpenSSH_8.9p1 Failed password for user victim from 192.168.56.101",
        desc: "Thử đăng nhập vét cạn mật khẩu tài khoản SSH trên máy Victim."
      },
      {
        id: "sqli",
        name: "SQL injection",
        tool: "sqlmap",
        command: 'sqlmap -u "http://192.168.56.102/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="..."',
        sev: "High",
        dstPort: 80,
        proto: "TCP",
        sid: 1000002,
        sig: "ET WEB_SPECIFIC_APPS DVWA SQL Injection Attempt",
        payload: "GET /vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM dvwa.users-- - HTTP/1.1",
        desc: "Tấn công trích xuất dữ liệu web DVWA thông qua lỗ hổng SQLi."
      },
      {
        id: "syn_flood",
        name: "SYN flood",
        tool: "hping3",
        command: "hping3 -S --flood -p 80 192.168.56.102",
        sev: "Medium",
        dstPort: 80,
        proto: "TCP",
        sid: 1000003,
        sig: "ET DOS Possible TCP SYN Flood",
        payload: "TCP SYN flood from 192.168.56.101 to 192.168.56.102:80 > 50,000 pps",
        desc: "Bắn dồn dập gói SYN gây nghẽn hàng đợi kết nối web server."
      }
    ];
  }

  getScenario(name) {
    return this.scenarios.find(s => s.name === name || s.id === name || s.tool === name) || this.scenarios[0];
  }

  animateMapAttack() {
    const mapSvg = document.querySelector(".map svg");
    if (!mapSvg) return;

    // Trigger visual pulse on victim node
    const victimRing = mapSvg.querySelector(".rg");
    if (victimRing) {
      victimRing.style.fill = "var(--bad)";
      victimRing.style.opacity = "0.7";
      setTimeout(() => {
        victimRing.style.fill = "var(--acc)";
        victimRing.style.opacity = "0.25";
      }, 1500);
    }

    // Spawn an attack laser particle from Kali (70, 55) to Victim (200, 120)
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", "70");
    circle.setAttribute("cy", "55");
    circle.setAttribute("r", "5");
    circle.setAttribute("fill", "var(--bad)");
    circle.setAttribute("filter", "drop-shadow(0 0 6px #e5384f)");
    mapSvg.appendChild(circle);

    const startTime = performance.now();
    const duration = 550;

    function step(now) {
      const p = Math.min((now - startTime) / duration, 1);
      const curX = 70 + (200 - 70) * p;
      const curY = 55 + (120 - 55) * p;
      circle.setAttribute("cx", curX);
      circle.setAttribute("cy", curY);
      if (p < 1) {
        requestAnimationFrame(step);
      } else {
        circle.remove();
      }
    }
    requestAnimationFrame(step);
  }
}

window.attackSimulator = new AttackSimulator();