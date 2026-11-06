# Sentinel IDS v2 – Đồ án Mạng Máy Tính

Hệ thống **giám sát & phát hiện xâm nhập** (Suricata + Wazuh) có **đăng nhập/phân quyền**, **Gateway qua máy ảo** (ẩn IP người dùng, ngắt tại VM khi có sự cố), **quản lý port**, và một bộ **công cụ phòng thủ (blue-team)**: chạy kịch bản tấn công để kiểm tra IDS, đo hiệu quả phát hiện, gom sự cố theo dòng thời gian, thống kê, báo cáo theo khoảng thời gian (CSV/PDF), chống tràn cảnh báo, và thông báo qua **Telegram + Email**.

Dự án tách làm 2 phần chạy riêng:

| Phần | Thư mục | Vai trò | Công nghệ | Cổng mặc định |
|---|---|---|---|---|
| **FrontEnd (UI)** | `frontend/` | Giao diện web | HTML + CSS + JavaScript thuần (không build) | `5173` |
| **BackEnd (Data access + Server)** | `backend/` | API, xác thực, SSH, tunnel, lưu dữ liệu | Node.js (JavaScript) + thư viện `ssh2` | `3000` |
| Scripts hỗ trợ | `scripts/` | Đẩy log từ máy ảo, chặn IP thủ công | Python 3, Bash | – |

```
Sentinel-IDS/
├─ frontend/            # UI  (npm start -> http://localhost:5173)
│  ├─ index.html, serve.js, css/style.css
│  └─ js/
│     ├─ config.js api.js ui.js app.js sound.js      # nền tảng: gọi API, helper giao diện, router + SSE
│     └─ views/        # mỗi trang 1 file:
│        dashboard.js alerts.js gateway.js ports.js   #   tổng quan, cảnh báo, gateway, port
│        security.js scenarios.js reports.js          #   bảo mật, kịch bản tấn công, báo cáo
│        account.js admin.js                          #   tài khoản, quản trị (có Cài đặt hệ thống)
├─ backend/             # Server (npm start -> http://localhost:3000/api)
│  ├─ server.js         # HTTP server + SSE + xác thực
│  ├─ src/db/store.js   # Data access layer (JSON, ghi nguyên tử: ghi file tạm rồi đổi tên)
│  ├─ src/security/     # crypto.js: scrypt (băm mật khẩu), AES-256-GCM (mã hoá), JWT
│  ├─ src/routes/       # index.js: toàn bộ REST API (bản đồ /api/...)
│  ├─ src/services/     # logic thật: users, vms, tunnels, terminals, alerts, blocklist, rules,
│  │                    #   monitor, sensors, wazuh, telegram, email, whitelist, scenarios…
│  ├─ test/selftest.js            # 70 kiểm thử end-to-end (npm test)
│  ├─ test/test_new_features.js   # 8 kiểm thử cho các chức năng mới
│  └─ data/             # dữ liệu chạy thật (tự tạo, đã .gitignore)
├─ scripts/ eve_forwarder.py  block_ip.sh
├─ docs/LAB_SETUP.md    # chuẩn bị các máy ảo
├─ start.bat / start.sh # chạy cả 2 bằng 1 lệnh
└─ README.md            # tài liệu này
```

> **Mẹo đọc code cho người mới:** mỗi file đều có **đoạn chú thích đầu file** nói *file này làm gì*, và các dòng khó đều có `// giải thích` bằng tiếng Việt. Muốn hiểu "hệ thống có những API gì" → đọc `backend/src/routes/index.js`. Muốn hiểu "một trang giao diện" → đọc file tương ứng trong `frontend/js/views/`.

---

## 1. Hướng dẫn chạy (VS Code)

**Yêu cầu:** Node.js ≥ 18 (khuyên dùng 20/22). Python 3 chỉ cần nếu dùng `eve_forwarder.py`.

### Cách A – 1 click
- **Windows:** double-click `start.bat` (tự `npm install`, mở 2 cửa sổ Backend/Frontend và trình duyệt).
- **Linux/macOS:** `./start.sh`

### Cách B – Từng phần trong VS Code (khuyên dùng khi code/debug)
1. `File → Open Folder…` chọn thư mục `Sentinel-IDS`.
2. Mở Terminal 1 (`Ctrl + ` `) → **BackEnd**:
   ```bash
   cd backend
   npm install        # chỉ lần đầu (cài thư viện ssh2)
   npm start          # hoặc: npm run dev (tự restart khi sửa code)
   ```
   Tài khoản admin mặc định: **`admin` / `admin1234`** (backend tự tạo; mỗi lần khởi động sẽ ép admin về đúng thông tin này; đặt `ADMIN_FORCE=false` trong `backend/.env` nếu muốn tự đổi mật khẩu và giữ nguyên).
   Muốn đặt mật khẩu khác ngay: `npm run reset-admin -- MatKhauMoi123` (dừng backend trước, không mất dữ liệu).
3. Mở Terminal 2 (`+` trên panel Terminal) → **FrontEnd**:
   ```bash
   cd frontend
   npm start          # (không cần npm install, không có thư viện ngoài)
   ```
4. Mở <http://localhost:5173>, đăng nhập `admin` / `admin1234`.

> Đổi tài khoản admin mặc định: copy `backend/.env.example` → `backend/.env`, sửa `ADMIN_USERNAME` / `ADMIN_PASSWORD`. **`admin1234` là mật khẩu yếu, chỉ dùng trong mạng lab.**

### Chạy kiểm thử (tự động)
```bash
cd backend
npm test                         # 70 kiểm thử end-to-end (dùng SSH server giả, chỉ trong bài test)
node test/test_new_features.js   # 8 kiểm thử cho các chức năng mới (whitelist, MITRE, incidents,
                                 #   thống kê, kịch bản, eve.json, chống tràn, email)
```

### Cấu hình hay dùng
| Việc cần làm | Cách làm |
|---|---|
| Frontend ở máy khác / đổi địa chỉ API | sửa `frontend/js/config.js` (`API_BASE`) hoặc chạy `API_BASE=http://IP:3000/api npm start` |
| Cho người dùng ở máy khác trong mạng truy cập | Backend `.env`: `BIND_HOST=0.0.0.0`, `TUNNEL_BIND_HOST=0.0.0.0`, `FRONTEND_ORIGIN=http://IP-frontend:5173`; Frontend: `HOST=0.0.0.0 npm start` |
| Đổi cổng | `PORT` (backend), `PORT` (frontend); nhớ khớp `FRONTEND_ORIGIN` / `API_BASE` |

---

## 2. Thiết lập lần đầu (làm trong giao diện, không sửa code)

1. **Quản trị → Máy ảo → Thêm VM**: khai báo từng VM của lab (IP, cổng SSH, user/mật khẩu hoặc private key) và **vai trò**:
   - `gateway` – máy trung gian để user đi qua (bắt buộc cho Gateway/Terminal/Port).
   - `sensor` – chạy Suricata; Backend tự SSH đọc log (`fast.log` **hoặc** `eve.json`) lấy cảnh báo thật.
   - `victim` – máy được bảo vệ; nút **Chặn IP** sẽ chạy `iptables` thật trên các máy này.
   - `attacker` – máy chạy **kịch bản tấn công** (Kali…); chỉ VM có vai trò này mới chạy được kịch bản.
   - `siem` – nhãn quản lý (Wazuh).

   Bấm **Thử SSH** để kiểm tra. Mật khẩu VM được mã hoá AES-256-GCM, không bao giờ gửi về trình duyệt. Host key SSH được ghi nhớ ở lần kết nối đầu (TOFU) và cảnh báo nếu đổi (chống MITM).
2. **Quản trị → Cài đặt hệ thống**: cấu hình thông báo & phản ứng:
   - **Telegram**: Bot Token + Chat ID.
   - **Email (SMTP)**: máy chủ SMTP, port, user/mật khẩu, người gửi/nhận — xem mục 3.5.
   - **Wazuh**: host, API 55000, Indexer 9200.
   - **Xử lý sự cố**: tự động ngắt Gateway, tự động chặn IP, và **chống tràn cảnh báo**.
3. **Quản trị → Quản lý User**: tạo tài khoản, đặt quyền, **cấp dải cổng local** cho từng user.
4. Chi tiết chuẩn bị máy ảo (sshd, sudo, Suricata `local.rules`…): xem `docs/LAB_SETUP.md`.

---

## 3. Chức năng (cũ)

### 3.1 Tài khoản & phân quyền (Admin / User)
- Trang **Đăng nhập / Đăng ký / Quên mật khẩu** đều có nút con mắt xem mật khẩu. Đăng ký tự do → tài khoản **chờ admin duyệt**. Quên mật khẩu → gửi yêu cầu tới admin, admin bấm 🔑 để cấp mật khẩu tạm.
- **Tự động đăng nhập:** ô tick dưới ô mật khẩu. *Có tick* → nhớ 30 ngày. *Không tick* → mất phiên khi đóng tab / chạy lại backend. Đừng tick trên máy dùng chung.
- Đăng nhập **JWT**, mật khẩu băm **scrypt**, khoá tạm 5 phút sau 5 lần sai, giới hạn tốc độ, thu hồi token khi đăng xuất/đổi mật khẩu.
- **Admin** quản lý tất cả; **User** dùng Gateway/Terminal/port của mình. Mọi thao tác nhạy cảm ghi vào **Audit log**.

### 3.2 Gateway: Bạn → chức năng → máy ảo → website/link
```
 Bạn (IP ẩn) ──► :cổng local ──► [Chức năng: Wazuh/SSH/…] ──SSH──► [Máy ảo gateway] ──► Website / dịch vụ
                                                                       ▲ đích chỉ thấy IP của VM
```
- Mỗi kết nối dùng **một phiên SSH riêng** tới VM; lưu lượng đi qua `forwardOut`, **đích không bao giờ nhận IP của bạn**.
- **Ngắt tại VM + thông báo:** khi có cảnh báo (mặc định mức High) liên quan, hết hạn, quá thời gian rảnh, hoặc bấm **Ngắt ngay** → Backend đóng phiên SSH tại VM và báo cho người dùng (toast + âm báo realtime qua SSE + Telegram/Email).
- **SSH Terminal** trên web đi qua VM: nhập tài khoản **của máy đích** (không lộ mật khẩu VM của admin).

### 3.3 Cổng & Port
- **Đổi port / Thêm port**: kiểm tra cổng trống/được phép trước khi lưu; tunnel tự khởi động lại trên cổng mới.
- Hai loại cổng local: **cổng cấp sẵn** (admin cấp) và **cổng private** (user tự nhập trong dải cho phép). Cổng hệ thống (3000, 5173) và cổng < 1024 bị cấm.
- **Kiểm tra đích qua VM** (probe): thử mở `host:port` từ VM trước khi tạo kết nối.

### 3.4 Dữ liệu thật – không còn mock
Cảnh báo, CPU/RAM, Telegram, luật Suricata, Wazuh… đều là dữ liệu/thao tác thật. Chưa cấu hình thì hiển thị **trống**, không điền số liệu giả.

---

## 3.5 Chức năng MỚI (blue-team) — cách dùng & nguyên lý

> Tất cả đều đã có **kiểm thử tự động** trong `backend/test/test_new_features.js`.

### (1) Chạy kịch bản tấn công từ web + Đo hiệu quả phát hiện
**Trang:** *Kịch bản tấn công* (chỉ admin). **File:** `backend/src/services/scenarios.js`, `frontend/js/views/scenarios.js`.
- Chọn 1 kịch bản có sẵn — **Nmap scan, Nmap OS detect, SSH brute-force (Hydra), SQL injection (sqlmap), SYN flood (hping3), đọc file nhạy cảm (curl)** — chạy **từ VM vai trò `attacker`** nhắm vào máy `victim` trong lab.
- **Nguyên lý an toàn:** danh sách lệnh là **cố định** (người dùng không tự nhập lệnh), chỉ chạy được trên VM `attacker`, mỗi VM chỉ 1 kịch bản một lúc, có giới hạn thời gian.
- **Đo hiệu quả tự động:** sau khi chạy, hệ thống đối chiếu các cảnh báo IDS phát sinh để tính: **có phát hiện không, số cảnh báo, độ trễ (latency)** từ lúc tấn công đến cảnh báo đầu tiên, loại & chữ ký phát hiện. Mục đích: kiểm tra xem luật IDS của bạn có bắt được tấn công không.

### (2) Gom cảnh báo thành sự cố + dòng thời gian theo IP
**Trang:** *Cảnh báo* → bấm vào một IP. **Hàm:** `alerts.incidents(ip)`.
- Gom **tất cả cảnh báo của một IP nguồn** lại thành 1 "sự cố", sắp xếp theo thời gian (dòng thời gian tấn công), kèm: lần đầu/cuối thấy, mức độ cao nhất, các loại tấn công. Giúp nhìn ra "kẻ này đã làm gì, theo trình tự nào".

### (3) Thống kê chi tiết + ánh xạ MITRE ATT&CK
**Trang:** *Báo cáo*. **Hàm:** `alerts.stats/topIps/topSignatures`.
- **Top IP tấn công, Top chữ ký, phân loại tấn công, theo mức độ/trạng thái, theo giờ**, và **MITRE ATT&CK** (tự đoán chiến thuật/kỹ thuật từ chữ ký, hoặc lấy sẵn từ Wazuh `rule.mitre`).

### (4) Đọc `eve.json` (nhiều thông tin hơn `fast.log`)
**File:** `backend/src/services/sensors.js` (`parseEveLine`).
- Nếu `logPath` của VM sensor kết thúc bằng `.json` hoặc chứa chữ `eve`, Backend tự chuyển sang đọc **`eve.json`** (JSON đầy đủ: cổng, giao thức, app_proto, flow_id, và **MITRE** từ `metadata`). Vẫn tương thích ngược với `fast.log`.

### (5) Chống tràn cảnh báo (gộp theo tần suất)
**Cấu hình:** *Cài đặt hệ thống → Xử lý sự cố → "Gộp cảnh báo lặp lại"*. **Hàm:** `alerts.add` + `settings.floodControl`.
- Khi **cùng một IP + cùng loại** tấn công lặp lại vượt **ngưỡng** trong **cửa sổ thời gian**, hệ thống **gộp** chúng thành **một cảnh báo đại diện có bộ đếm** thay vì làm ngập danh sách. Mặc định: bật, 30 giây, ngưỡng 5. Khác với *chống trùng* (loại bản sao y hệt) — cái này gộp theo **tần suất**.

### (6) Báo cáo theo khoảng thời gian + biểu đồ + xuất PDF/CSV
**Trang:** *Báo cáo*. **File:** `frontend/js/views/reports.js`, backend `/stats?from=&to=`.
- Chọn **Từ / Đến** hoặc nút nhanh **1h / 6h / 24h / 7 ngày / Tất cả** → toàn bộ số liệu & biểu đồ tính lại đúng trong khoảng đó.
- **Xuất CSV** (mở bằng Excel) và **Xuất PDF** (dùng chức năng in của trình duyệt → chọn "Save as PDF"; chỉ in phần báo cáo nhờ CSS `@media print`).

### (7) Gửi Email cảnh báo (song song Telegram)
**Cấu hình:** *Cài đặt hệ thống → Email (SMTP)*. **File:** `backend/src/services/email.js`.
- Gửi cảnh báo qua **SMTP** (không dùng thư viện ngoài — tự nói chuyện SMTP qua `net`/`tls`). Hỗ trợ **STARTTLS (cổng 587)** và **TLS ngay (cổng 465)**, đăng nhập `AUTH LOGIN`, tiêu đề tiếng Việt (RFC 2047).
- Nhập **máy chủ SMTP, port, user, mật khẩu, From, To** (nhiều người nhận cách nhau dấu phẩy), chọn **mức tối thiểu** để gửi, rồi bấm **"Gửi email thử (thật)"** để kiểm tra.
- *Gmail:* bật 2FA rồi tạo **App Password**, dùng host `smtp.gmail.com`, port `587`, secure = tắt.

### (8) Danh sách trắng (Whitelist) + MITRE
**Trang:** *Bảo mật → Danh sách trắng*. **File:** `backend/src/services/whitelist.js`.
- **IP tin cậy** hoặc **SID luật** trong danh sách trắng → cảnh báo bị **bỏ qua tự động**, giúp giảm **báo động giả (false positive)**.

---

## 4. API tóm tắt (`/api`)
`POST /auth/login · GET /auth/me · POST /auth/change-password` ·
`GET|POST|PATCH|DELETE /users` (admin) · `GET|POST|PATCH|DELETE /vms` · `GET|POST|PATCH|DELETE /tools` ·
`GET|POST /gateway/tunnels · PATCH|DELETE /gateway/tunnels/:id · POST /gateway/tunnels/:id/start|stop · POST /gateway/cut-all · POST /gateway/probe` ·
`GET /ports/policy · GET /ports/check?port=` · `POST /terminal …` ·
`GET /alerts · POST /alerts` (cần `X-Ingest-Key`) · `GET /stats?from=&to=` ·
`GET /incidents?ip= · GET /top-ips · GET /top-signatures` *(thống kê/sự cố)* ·
`GET /scenarios · GET /scenarios/history · POST /scenarios/run` *(kịch bản tấn công)* ·
`GET|POST|DELETE /whitelist/ips · GET|POST|DELETE /whitelist/sids` *(danh sách trắng)* ·
`GET|POST|DELETE /blocklist` · `GET|POST|PUT|DELETE /rules · POST /rules/deploy` ·
`GET /wazuh/status|agents|alerts` · `GET|PUT /settings · POST /settings/telegram-test · POST /settings/email-test` · `GET /audit` · `GET /events` (SSE).

## 5. Bảo mật – lưu ý khi dùng
- Chỉ dùng trong **mạng lab/được phép**. Kịch bản tấn công **chỉ nhắm vào máy của chính bạn** trong lab.
- Backend mặc định chỉ lắng nghe `127.0.0.1`. Nếu mở `0.0.0.0`, hãy giới hạn bằng firewall + HTTPS/reverse proxy.
- Mật khẩu **không nằm trong mã nguồn**; bí mật (token/mật khẩu) được mã hoá bằng khoá trong `backend/data/secret.key`.
- Sao lưu `backend/data/` (đặc biệt `secret.key` – mất file này là không giải mã được mật khẩu VM).

## 6. Xử lý sự cố nhanh
| Triệu chứng | Cách xử lý |
|---|---|
| Trang báo "Không kết nối được Backend" | Backend chưa chạy hoặc sai `API_BASE`/CORS (`FRONTEND_ORIGIN`) |
| VM luôn "mất kết nối" | Kiểm tra IP/cổng SSH, card Host-only; thử nút *Thử SSH* |
| "Host key của VM đã thay đổi" | VM cài lại → Sửa VM → tick *Reset host key* |
| Tunnel lỗi "administratively prohibited" | bật `AllowTcpForwarding yes` trong `/etc/ssh/sshd_config` của VM gateway |
| Chặn IP báo `failed` | tài khoản SSH cần sudo; điền *Mật khẩu sudo* hoặc `NOPASSWD` |
| Không có cảnh báo Suricata | VM cần vai trò `sensor`, đúng `logPath`, user SSH đọc được `fast.log`/`eve.json` |
| Kịch bản tấn công báo lỗi | VM phải có vai trò `attacker` và cài sẵn công cụ (nmap/hydra/sqlmap/hping3) |
| Gửi email lỗi | kiểm tra host/port/secure; Gmail phải dùng **App Password**; thử nút *Gửi email thử* để xem lỗi thật |
