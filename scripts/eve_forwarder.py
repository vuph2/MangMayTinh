#!/usr/bin/env python3
"""
Suricata EVE.JSON Log Forwarder to Sentinel IDS Dashboard
Chạy trực tiếp trên máy ảo Victim (Ubuntu Server) để forward log Suricata sang Sentinel IDS.

Cách dùng:
  python3 eve_forwarder.py --server http://192.168.56.1:3000 --file /var/log/suricata/eve.json
"""
import time
import json
import urllib.request
import argparse
import sys
import os

def tail_f(file_path):
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} không tồn tại. Đang chờ Suricata tạo file...")
        while not os.path.exists(file_path):
            time.sleep(2)
    
    with open(file_path, "r", encoding="utf-8") as f:
        f.seek(0, 2) # Go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def forward_alert(server_url, alert_data):
    try:
        req = urllib.request.Request(
            f"{server_url}/api/alerts",
            data=json.dumps(alert_data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"[+] Forwarded: {alert_data.get('type')} from {alert_data.get('ip')}")
    except Exception as e:
        print(f"[-] Lỗi gửi cảnh báo tới server: {e}")

def main():
    parser = argparse.ArgumentParser(description="Suricata eve.json Forwarder")
    parser.add_argument("--server", default="http://192.168.56.1:3000", help="URL Sentinel IDS Server")
    parser.add_argument("--file", default="/var/log/suricata/eve.json", help="Path tới eve.json")
    args = parser.parse_args()

    print(f"[*] Theo dõi tệp: {args.file}")
    print(f"[*] Gửi log về server: {args.server}")

    for line in tail_f(args.file):
        try:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                alert_info = event.get("alert", {})
                sev_map = {1: "High", 2: "Medium", 3: "Low"}
                alert_payload = {
                    "ip": event.get("src_ip", "0.0.0.0"),
                    "src_port": event.get("src_port", 0),
                    "dst_ip": event.get("dest_ip", "192.168.56.103"),
                    "dst_port": event.get("dest_port", 80),
                    "proto": event.get("proto", "TCP"),
                    "type": alert_info.get("category", "Intrusion Attempt"),
                    "tool": "Suricata Live",
                    "sev": sev_map.get(alert_info.get("severity", 2), "Medium"),
                    "sid": alert_info.get("signature_id", 1000000),
                    "signature": alert_info.get("signature", "Suricata Alert"),
                    "payload": event.get("payload_printable", "")
                }
                forward_alert(args.server, alert_payload)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()