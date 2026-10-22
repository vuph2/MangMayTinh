# Chuẩn bị máy ảo cho Sentinel IDS

Mô hình mẫu (VirtualBox, card 2 Host-only `192.168.56.0/24`):

| Máy | IP ví dụ | Vai trò trong Sentinel |
|---|---|---|
| Victim (DVWA + Suricata + Wazuh agent) | 192.168.56.102 | `gateway`, `sensor`, `victim` |
| Ubuntu1 (Wazuh Manager/Indexer/Dashboard) | 192.168.56.103 | `siem` (đích của chức năng Wazuh) |
| Kali | 192.168.56.101 | `attacker` (chỉ nhãn quản lý) |
| Máy chạy Backend/Frontend | 192.168.56.1 (host) | – |

IP có thể khác — hãy nhập đúng IP thực của bạn trong giao diện.

## 1. SSH trên máy `gateway`
```bash
sudo apt install -y openssh-server
# /etc/ssh/sshd_config  (đảm bảo)
AllowTcpForwarding yes
PasswordAuthentication yes      # hoặc dùng private key
sudo systemctl restart ssh
```
Khuyến nghị tạo user riêng cho Sentinel thay vì dùng tài khoản cá nhân, và dùng key thay mật khẩu.

## 2. Quyền đọc log Suricata (vai trò `sensor`)
```bash
sudo usermod -aG adm <user_ssh>        # đọc được /var/log/suricata/fast.log
```
Nếu không đọc được, Backend tự thử lại bằng `sudo` (cần mật khẩu sudo hoặc NOPASSWD).

## 3. Chặn IP bằng iptables (vai trò `victim`)
User SSH phải chạy được `sudo iptables`. Cách gọn: `/etc/sudoers.d/sentinel`
```
<user_ssh> ALL=(root) NOPASSWD: ALL
```
rồi chọn *sudo không cần mật khẩu* trong cấu hình VM (hoặc điền mật khẩu sudo).
> Lưu ý: Backend chạy lệnh dạng `sudo bash -c '…'`, nên quyền này tương đương root. Chỉ dùng cho VM lab, dùng user riêng và đặt Backend sau tường lửa.

## 4. Đồng bộ luật Suricata
Trong `/etc/suricata/suricata.yaml` cần có:
```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
```
Sentinel sẽ ghi `local.rules`, chạy `suricata -T -c /etc/suricata/suricata.yaml`, rồi `systemctl restart suricata`. Nếu kiểm tra lỗi thì tự khôi phục bản cũ.

## 5. Wazuh
Trong **Cài đặt hệ thống → Wazuh** nhập IP máy Wazuh, user/mật khẩu API (cổng 55000) và Indexer (cổng 9200). Wazuh dùng chứng chỉ tự ký nên để *Kiểm tra TLS* tắt.
Tạo VM `siem` cho máy Wazuh; chức năng **Wazuh Dashboard** sẽ đi qua VM `gateway` tới `192.168.56.103:443`.

## 6. Lệnh kiểm thử trong lab (trên Kali, chỉ nhằm máy Victim của bạn)
```bash
nmap -sS -sV 192.168.56.102
nmap -sC -p 80 192.168.56.102
```
Cảnh báo thật sẽ xuất hiện ở trang **Cảnh báo** trong vài giây (sensor đọc `fast.log`). Không quét ra ngoài mạng lab.

## 7. Đẩy log kiểu push (tuỳ chọn)
Nếu không muốn Backend SSH vào sensor:
```bash
python3 scripts/eve_forwarder.py --server http://192.168.56.1:3000 --key <INGEST_KEY>
```
`INGEST_KEY` ở **Quản trị → Cài đặt hệ thống**.
