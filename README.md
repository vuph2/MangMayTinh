# HƯỚNG DẪN DỰ ÁN MÔN MẠNG MÁY TÍNH (MMT)
## HỆ THỐNG GIÁM SÁT & PHÁT HIỆN XÂM NHẬP (SENTINEL IDS)
**Tích hợp Suricata Sensor, Wazuh SIEM & Active Response**

---

### 1. Cấu trúc thư mục tại `D:\MMT`
```text
D:\MMT\
├── public/                 # Giao diện Web Dashboard (Frontend)
│   ├── index.html          # Trang chính Sentinel IDS
│   ├── css/
│   │   └── style.css       # Giao diện hiện đại (Dark/Light mode, Glassmorphism)
│   └── js/
│       ├── app.js          # Xử lý tương tác, bảng cảnh báo, modal, bộ lọc
│       ├── simulator.js    # Trình giả lập 5 kịch bản tấn công (nmap, hydra, sqlmap, DoS, LFI)
│       ├── sound.js        # Âm thanh cảnh báo an ninh (Web Audio API không cần file ngoài)
│       └── i18n.js         # Hỗ trợ song ngữ Tiếng Việt & English
│
├── server/                 # Web Server & REST API Backend (Node.js)
│   ├── server.js           # Server HTTP + Server-Sent Events (SSE) theo dõi log thời gian thực
│   ├── package.json        # Thông tin ứng dụng
│   └── data/               # Lưu trữ dữ liệu JSON
│       ├── alerts.json     # Lịch sử cảnh báo an ninh
│       ├── agents.json     # Danh sách máy giám sát (Victim, Wazuh, Kali, Gateway)
│       ├── rules.json      # Danh mục các luật Suricata tùy chỉnh
│       └── blocklist.json  # Danh sách các IP bị chặn (Active Response)
│
├── scripts/                # Kịch bản hỗ trợ kiểm thử đồ án
│   ├── test_traffic.js     # Script bắn traffic mô phỏng vào server
│   ├── eve_forwarder.py    # Script đẩy log thật từ /var/log/suricata/eve.json về web
│   └── block_ip.sh         # Script lệnh iptables chặn IP trên máy ảo Linux
│
├── start.bat               # 1 Click: Khởi động server Node.js & mở Dashboard
├── open_browser.bat        # 1 Click: Mở trực tiếp giao diện (chế độ độc lập Offline)
└── README.md               # Tài liệu hướng dẫn chi tiết
```

---

### 2. Các chức năng cơ bản đã xây dựng đầy đủ
1. **Trung tâm Quản lý Cảnh báo (Alerts Center):**
   - Lọc đa tiêu chí: Theo IP nguồn, loại hình tấn công, độ nghiêm trọng (High, Medium, Low), trạng thái.
   - Bảng xem chi tiết sự kiện: Timestamp, Source/Dest IP & Port, Protocol, Rule SID, Raw Payload gói tin.
   - Thao tác xử lý: **Chặn IP ngay lập tức**, Đánh dấu đã giải quyết (Resolve), Báo cáo cảnh báo giả (False Positive), Tải tệp JSON của cảnh báo.
2. **Kịch bản Tấn công Thực nghiệm (Attack Simulation Engine):**
   - **Port scan (Nmap):** Quét cổng TCP SYN Stealth scan.
   - **SSH brute force (Hydra):** Vét cạn mật khẩu SSH port 22.
   - **SQL injection (sqlmap):** Tấn công khai thác lỗ hổng DVWA web.
   - **SYN flood (hping3):** Tấn công từ chối dịch vụ DoS làm nghẽn hàng đợi TCP.
   - **Sensitive File Access (curl):** Đọc trộm file nhạy cảm `/etc/passwd`.
   - Có hiệu ứng tia laser và vòng phòng thủ nhấp nháy động trên sơ đồ mạng (Topology Map).
3. **Quản lý Luật Suricata (Custom Rules Editor):**
   - Danh sách các luật với mã định danh SID (1000001 - 1000005).
   - Bật/tắt luật bằng công tắc, thêm luật mới, kiểm tra cú pháp luật hợp lệ.
4. **Cơ chế Ngăn chặn Chủ động (Blocklist & Active Response):**
   - Quản lý danh sách IP đang bị cô lập.
   - Nút **"Copy Linux iptables drop rules"** tự động tạo chuỗi lệnh `iptables -A INPUT -s <IP> -j DROP` để chạy ngay trên máy ảo Linux.
5. **Biểu đồ Thời gian thực (Real-time Timeline Analytics):**
   - Biểu đồ đường SVG trực quan hóa lưu lượng cảnh báo theo chu kỳ 5 phút trong 3 giờ qua.
   - Đo lường % tải hệ thống (Alert Load) và thời gian duy trì phòng thủ (Uptime).
6. **Báo cáo Chuyên nghiệp (Reporting & Export):**
   - **Xuất PDF / In báo cáo:** Định dạng trang in chuẩn báo cáo đồ án với bảng tổng kết rủi ro, top kẻ tấn công và danh sách sự kiện.
   - **Xuất CSV:** Tải file `.csv` tương thích Microsoft Excel.
7. **Âm thanh Cảnh báo An ninh (Cyber Sound Effects):**
   - Sử dụng Web Audio API tổng hợp âm báo động tần số cao khi có tấn công High severity, có nút bật/tắt âm thanh nhanh trên thanh công cụ.
8. **Hỗ trợ Song ngữ (Tiếng Việt & English):**
   - Dễ dàng chuyển đổi trực tiếp trong phần Cài đặt (Settings).

---

### 3. Cách khởi chạy

#### Cách 1: Chạy đầy đủ Server Backend + Giao diện (Khuyên dùng khi demo đồ án)
1. Double-click vào tệp `D:\MMT\start.bat`
2. Cửa sổ dòng lệnh sẽ chạy Node.js server tại `http://localhost:3000` và tự động bật trình duyệt.

#### Cách 2: Mở nhanh không cần server (Offline mode)
1. Double-click vào tệp `D:\MMT\open_browser.bat` hoặc mở trực tiếp `D:\MMT\public\index.html`.
2. Ứng dụng sẽ tự động chạy ở chế độ Client-side lưu trữ qua LocalStorage.

#### Cách 3: Bắn traffic kiểm thử vào Dashboard
Mở PowerShell tại `D:\MMT` và chạy:
```powershell
node scripts/test_traffic.js
```

---

### 4. Cấu hình mạng Lab trong VirtualBox (Nhóm MMT)
- **Card mạng 1:** NAT (Dùng để máy ảo ra Internet tải package `suricata`, `wazuh-agent`, `dvwa`).
- **Card mạng 2:** Host-only Adapter (VirtualBox Host-Only Ethernet Adapter)
  - Wazuh Server: `192.168.56.100`
  - Kali Linux (Attacker): `192.168.56.101`
  - Victim VM (Web DVWA + Suricata): `192.168.56.103`
  - Windows Host (Máy chạy giao diện Dashboard này): `192.168.56.1` (hoặc `localhost:3000`)
---

### 5. CẨM NANG HƯỚNG DẪN CHẠY LAB IDS THỰC TẾ
*(Wazuh Server + Suricata + DVWA Web + Kali Linux)*

#### 5.1 Mô hình Lab
- **Kali (Kẻ tấn công):** `192.168.56.101`
- **Victim (Nạn nhân):** `192.168.56.102` (Chạy Web DVWA, Suricata Sensor, Wazuh Agent)
- **Ubuntu1 (Wazuh Server):** `192.168.56.103` (Chạy Wazuh Manager, Indexer, Dashboard)
- **Windows Host (Máy của bạn):** `192.168.56.1` (Chạy Sentinel IDS Dashboard tại `http://localhost:3000`)

> **Quy tắc an toàn:** Chỉ tấn công IP của máy Victim (`192.168.56.102`). Tuyệt đối không quét IP ra ngoài mạng trường/nhà.

---

#### 5.2 Thứ tự Bật & Tắt máy ảo
- **THỨ TỰ BẬT:**
  1. **Ubuntu1:** Bật server, đợi **2-3 phút** để wazuh-indexer và manager sẵn sàng.
  2. **Victim:** Bật server, đợi **1-2 phút** để Docker DVWA và Suricata chạy.
  3. **Kali:** Bật sau cùng.
- **THỨ TỰ TẮT:**
  - Tắt ngược lại: Kali → Victim → Ubuntu1.
  - Trên terminal mỗi máy chạy lệnh: `sudo shutdown now` (không tắt đột ngột bằng nút Power Off).

---

#### 5.3 Thông tin tài khoản & Port Forwarding
1. **Ubuntu1 (Wazuh Server):**
   - SSH: `ssh vuph@localhost` (Mật khẩu: `password`)
   - Wazuh Dashboard: `https://localhost:8443` *(Port Forwarding 8443 -> 443)*
   - Tài khoản web: `admin` | Mật khẩu: `3Jl0Lt7Hv.Righz2YZO04*+rkdkbMOCC`
2. **Victim (Nạn nhân):**
   - SSH: `ssh -p 2222 victim@localhost` (Mật khẩu: `password`) *(Port Forwarding 2222 -> 22)*
   - Web DVWA: `http://localhost:8080` *(Port Forwarding 8080 -> 80)*
   - Kiểm tra dịch vụ:
     ```bash
     sudo systemctl status suricata wazuh-agent --no-pager | grep -E "●|Active"
     sudo docker ps
     ```
   - Xem log cảnh báo trực tiếp: `sudo tail -f /var/log/suricata/fast.log`
3. **Kali Linux:**
   - Tài khoản: `kali` / `kali`
   - Kiểm tra IP: `ip -4 a` (Card `eth1` nhận dải Host-only `192.168.56.x`)
   - Test kết nối: `ping -c 3 192.168.56.102`

---

#### 5.4 Lệnh kiểm thử & Dấu hiệu thành công
1. Trên Kali bắn lệnh quét Nmap:
   ```bash
   nmap -sS -sV 192.168.56.102
   nmap -sC -p 80 192.168.56.102
   ```
2. Trên Victim kiểm tra: Log xuất hiện trong `fast.log`.
3. Trên Wazuh Dashboard (`https://localhost:8443`):
   - Vào menu: **Threat Intelligence → Threat Hunting → Events**
   - Nhập bộ lọc: `rule.groups: suricata`
   - **KẾT QUẢ THÀNH CÔNG:** Xuất hiện cảnh báo **"ET SCAN Possible Nmap User-Agent Observed"** và máy Victim có trạng thái **Active** trong mục Endpoints.
