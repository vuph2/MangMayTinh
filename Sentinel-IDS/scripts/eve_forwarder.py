#!/usr/bin/env python3
"""
Suricata eve.json -> Sentinel IDS (Backend) forwarder.
Chay tren may Victim/sensor khi KHONG muon Backend SSH vao doc log (phuong an day thay cho keo).
Chi doc cac su kien that event_type == "alert" trong eve.json, khong sinh du lieu gia.

Dung:
  python3 eve_forwarder.py --server http://192.168.56.1:3000 --key <INGEST_KEY> [--file /var/log/suricata/eve.json]
INGEST_KEY lay trong giao dien: Quan tri -> Cai dat he thong -> "Khoa day log".
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from datetime import datetime

def tail_f(path):
    while not os.path.exists(path):
        print(f"[-] Cho Suricata tao file {path} ...")
        time.sleep(2)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.4)
                continue
            yield line

def to_ms(ts):
    try:
        return int(datetime.strptime(ts[:26], "%Y-%m-%dT%H:%M:%S.%f").timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)

def classify(sig):
    s = sig.lower()
    if "nmap" in s or "scan" in s: return "Port scan", "nmap"
    if "ssh" in s or "brute" in s: return "SSH brute force", "Hydra"
    if "sql" in s: return "SQL injection", "sqlmap"
    if "flood" in s or "dos" in s: return "SYN flood", "hping3"
    if "passwd" in s or "/etc/" in s: return "Sensitive File Access", "curl"
    return "Intrusion Attempt", "Suricata"

def convert(ev):
    a = ev.get("alert", {})
    sig = a.get("signature", "")
    typ, tool = classify(sig)
    pri = a.get("severity", 3)
    return {
        "ts": to_ms(ev.get("timestamp", "")), "ip": ev.get("src_ip", ""), "src_port": ev.get("src_port", 0),
        "dst_ip": ev.get("dest_ip", ""), "dst_port": ev.get("dest_port", 0), "proto": ev.get("proto", "TCP"),
        "type": typ, "tool": tool, "sev": "High" if pri == 1 else "Medium" if pri == 2 else "Low",
        "sid": a.get("signature_id", 0), "signature": sig,
        "payload": (ev.get("payload_printable") or json.dumps(ev.get("http", ""), ensure_ascii=False))[:1500],
        "agent": os.uname().nodename,
    }

def post(server, key, data):
    req = urllib.request.Request(f"{server}/api/alerts", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json", "X-Ingest-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=4):
            print(f"[+] {data['type']} {data['ip']} -> {data['dst_ip']}:{data['dst_port']}")
    except urllib.error.HTTPError as e:
        print(f"[!] Backend tu choi: HTTP {e.code} (kiem tra --key)")
    except Exception as e:
        print(f"[!] Khong gui duoc: {e}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--file", default="/var/log/suricata/eve.json")
    a = ap.parse_args()
    print(f"[*] Dang theo doi {a.file} -> {a.server}")
    for line in tail_f(a.file):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("event_type") == "alert":
            post(a.server.rstrip("/"), a.key, convert(ev))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
