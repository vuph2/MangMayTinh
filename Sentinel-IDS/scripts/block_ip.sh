#!/bin/bash
# Wazuh Active Response & Sentinel IDS Blocking Script
# Sử dụng: sudo ./block_ip.sh <IP_CAN_CHAN>

TARGET_IP=$1

if [ -z "$TARGET_IP" ]; then
    echo "Sử dụng: sudo $0 <IP_CAN_CHAN>"
    exit 1
fi

echo "[*] Kích hoạt Active Response chặn IP: $TARGET_IP"

# Thêm quy tắc iptables DROP
sudo iptables -I INPUT -s "$TARGET_IP" -j DROP

# Cấu hình ufw nếu ufw đang bật
if command -v ufw &> /dev/null; then
    sudo ufw deny from "$TARGET_IP" to any comment "Sentinel IDS Block"
fi

echo "[+] Đã chặn thành công IP $TARGET_IP trên card mạng."
echo "[+] Xem danh sách đang chặn: sudo iptables -L INPUT -v -n"