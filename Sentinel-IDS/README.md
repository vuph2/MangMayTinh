# Sentinel IDS v2 – Đồ án Mạng Máy Tính

Hệ thống giám sát & phát hiện xâm nhập (Suricata + Wazuh) có **đăng nhập/phân quyền**, **Gateway qua máy ảo** (ẩn IP người dùng, ngắt tại VM khi có sự cố) và **quản lý port**. Dự án tách làm 2 phần chạy riêng:

| Phần | Thư mục | Vai trò | Công nghệ | Cổng mặc định |
|---|---|---|---|---|
| **FrontEnd (UI)** | `frontend/` | Giao diện web | HTML + CSS + JavaScript thuần (không build) | `5173` |
| **BackEnd (Data access + Server)** | `backend/` | API, xác thực, SSH, tunnel, lưu dữ liệu | Node.js (JavaScript) + thư viện `ssh2` | `3000` |
| Scripts hỗ trợ | `scripts/` | Đẩy log từ máy ảo, chặn IP thủ công | Python 3, Bash | – |

```
Sentinel-IDS/
├─ frontend/            # UI  (npm start -> http://localhost:5173)
│  ├─ index.html, serve.js, css/style.css
│  └─ js/ config.js  api.js  ui.js  app.js  sound.js  views/*.js
├─ backend/             # Server (npm start -> http://localhost:3000/api)
│  ├─ server.js         # HTTP server + SSE + xác thực
│  ├─ src/db/store.js   # Data access layer (JSON, ghi nguyên tử)
│  ├─ src/security/     # scrypt, AES-256-GCM, JWT
│  ├─ src/routes/       # toàn bộ REST API
│  ├─ src/services/     # users, vms, tunnels, terminals, alerts, blocklist, rules, monitor, sensors, wazuh, telegram…
│  ├─ test/selftest.js  # kiểm thử end-to-end (npm test)
│  └─ data/             # dữ liệu chạy thật (tự tạo, đã .gitignore)
├─ scripts/ eve_forwarder.py  block_ip.sh
├─ docs/LAB_SETUP.md    # chuẩn bị các máy ảo
├─ start.bat / start.sh # chạy cả 2 bằng 1 lệnh
└─ README.md
```

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
   npm install        # chỉ lần đầu
   npm start          # hoặc: npm run dev (tự restart khi sửa code)
   ```
   Lần chạy đầu, console in **tài khoản admin + mật khẩu ngẫu nhiên (chỉ 1 lần)**. Hãy ghi lại.
3. Mở Terminal 2 (`+` trên panel Terminal) → **FrontEnd**:
   ```bash
   cd frontend
   npm start          # (không cần npm install, không có thư viện ngoài)
   ```
4. Mở <http://localhost:5173>, đăng nhập `admin` + mật khẩu ở bước 2 → hệ thống bắt **đổi mật khẩu** ở lần đầu.

> Có thể đặt trước mật khẩu admin: copy `backend/.env.example` → `backend/.env`, điền `ADMIN_PASSWORD=...`.

### Cấu hình hay dùng
| Việc cần làm | Cách làm |
|---|---|
| Frontend ở máy khác / đổi địa chỉ API | sửa `frontend/js/config.js` (`API_BASE`) hoặc chạy `API_BASE=http://IP:3000/api npm start` |
| Cho người dùng ở máy khác trong mạng truy cập | Backend `.env`: `BIND_HOST=0.0.0.0`, `TUNNEL_BIND_HOST=0.0.0.0`, `FRONTEND_ORIGIN=http://IP-frontend:5173`; Frontend: `HOST=0.0.0.0 npm start` |
| Đổi cổng | `PORT` (backend), `PORT` (frontend); nhớ khớp `FRONTEND_ORIGIN` / `API_BASE` |
| Kiểm thử tự động | `cd backend && npm test` (58 kiểm tra, dùng SSH server giả chỉ trong bài test) |

---

## 2. Thiết lập lần đầu (làm trong giao diện, không sửa code)

1. **Quản trị → Máy ảo → Thêm VM**: khai báo từng VM của lab (IP, cổng SSH, user/mật khẩu hoặc private key) và **vai trò**:
   - `gateway` – máy trung gian để user đi qua (bắt buộc cho Gateway/Terminal/Port).
   - `sensor` – chạy Suricata; Backend tự SSH `tail -F fast.log` lấy cảnh báo thật.
   - `victim` – máy được bảo vệ; nút **Chặn IP** sẽ chạy `iptables` thật trên các máy này.
   - `attacker`, `siem` – nhãn quản lý (Kali, Wazuh).
   
   Bấm **Thử SSH** để kiểm tra. Mật khẩu VM được mã hoá AES-256-GCM, không bao giờ gửi về trình duyệt. Host key SSH được ghi nhớ ở lần kết nối đầu (TOFU) và cảnh báo nếu đổi (chống MITM).
2. **Quản trị → Cài đặt hệ thống**: nhập Telegram Bot Token + Chat ID, thông tin Wazuh (host, API 55000, Indexer 9200), bật tự động ngắt/tự động chặn.
3. **Quản trị → Quản lý User**: tạo tài khoản, đặt quyền, **cấp dải cổng local** cho từng user.
4. Chi tiết chuẩn bị máy ảo (sshd, sudo, Suricata `local.rules`…): xem `docs/LAB_SETUP.md`.

---

## 3. Chức năng

### 3.1 Tài khoản & phân quyền (Admin / User)
- Đăng nhập JWT, mật khẩu băm **scrypt**, khoá tạm 5 phút sau 5 lần sai, giới hạn tốc độ đăng nhập, thu hồi token khi đăng xuất/đổi mật khẩu/khoá tài khoản.
- **Admin**: quản lý user (tạo/sửa/khoá/mở khoá/đặt lại mật khẩu/xoá, chính sách cổng), VM, công cụ Gateway, luật Suricata, chặn IP, đánh dấu cảnh báo, cài đặt hệ thống, xem Audit log.
- **User**: xem tổng quan/cảnh báo/Wazuh, dùng Gateway & Terminal, quản lý port của mình, hồ sơ, đổi mật khẩu.
- Mọi thao tác nhạy cảm được ghi vào **Audit log**.

### 3.2 Gateway: Bạn → chức năng → máy ảo → website/link
```
 Bạn (IP ẩn) ──► :cổng local ──► [Chức năng: Wazuh/SSH/…] ──SSH──► [Máy ảo gateway] ──► Website / đường link / dịch vụ
                                                                       ▲ đích chỉ thấy IP của VM
```
- Nút xổ **“Chức năng”** (có icon): *Wazuh Dashboard, Wazuh API, Wazuh Indexer* và các lựa chọn **miễn phí** tương đương: *OpenSearch Dashboards, Security Onion, Graylog, EveBox, Grafana, Zabbix, Netdata, Cockpit*, cùng *DVWA, SSH Terminal, Cổng TCP tuỳ chọn, Website/Link bất kỳ*. Admin thêm/sửa/ẩn công cụ trong **Quản trị → Công cụ Gateway**.
- Icon: thùng server (máy ảo/dịch vụ), quả cầu (website/link), terminal, … Sơ đồ đường đi hiển thị trực quan.
- Mỗi kết nối dùng **một phiên SSH riêng** tới VM; lưu lượng đi qua `forwardOut` của VM, nên **đích không bao giờ nhận IP của bạn** (nó chỉ thấy IP VM).
- **Ngắt tại VM + thông báo:** khi có cảnh báo (mặc định mức High) liên quan tới VM/đích, VM mất kết nối, hết thời hạn, quá thời gian rảnh, hoặc bạn bấm **Ngắt ngay** → Backend đóng phiên SSH tại VM, huỷ mọi socket và thông báo cho chủ kết nối (toast + âm báo realtime qua SSE, và Telegram cá nhân nếu đã nhập Chat ID).
- **SSH Terminal** trên web đi qua VM: bạn nhập tài khoản **của máy đích** (Backend không bao giờ đưa mật khẩu VM của admin cho user).

### 3.3 Cổng & Port
- **Đổi port**: nút *Đổi port* trên mỗi kết nối; kiểm tra cổng trống/được phép trước khi lưu, tunnel đang chạy tự khởi động lại trên cổng mới.
- **Thêm port**: chọn công cụ + VM + đích + cổng local.
- Hai loại cổng local: **cổng cấp sẵn** (admin cấp theo user, ví dụ `8080-8089`) và **cổng private** (user tự nhập trong dải `privateRange`, ví dụ `20000-20999`) để kiểm tra riêng.
- **Kiểm tra đích qua VM** (probe): thử mở `host:port` từ VM trước khi tạo kết nối.
- Cổng hệ thống (3000, 5173) và cổng < 1024 bị cấm.

### 3.4 Dữ liệu thật – không còn mock
Đã xoá hoàn toàn: `alerts.json/agents.json` mẫu, bộ giả lập tấn công, cảnh báo sinh ngẫu nhiên, số CPU/RAM cố định, tin nhắn Telegram “giả lập”, `localStorage` mẫu.

| Mục (theo file `Danh_sach.docx`) | Trạng thái |
|---|---|
| 1. Tự động chặn IP (iptables qua SSH) | ✅ `blocklist.js` – SSH vào VM `victim` chạy `iptables -I INPUT -s IP -j DROP`, bỏ chặn `-D`, hẹn giờ tự gỡ, chống chèn lệnh, không cho chặn IP của chính hệ thống |
| 2. Telegram thật | ✅ gọi `api.telegram.org/bot<TOKEN>/sendMessage`; nút “Gửi tin thử” báo lỗi thật nếu token sai |
| 3. CPU/RAM thời gian thực | ✅ SSH đọc `/proc/stat`, `free -m`, `loadavg`, `uptime` mỗi chu kỳ health-check |
| 4. Đồng bộ luật Suricata | ✅ ghi `/etc/suricata/rules/local.rules`, chạy `suricata -T`, `systemctl restart suricata`, lỗi cú pháp thì khôi phục bản cũ |
| 5. Wazuh API & Indexer | ✅ JWT `POST /security/user/authenticate`, `/agents`, truy vấn `wazuh-alerts-*/_search`, đồng bộ cảnh báo định kỳ |
| 6. Đăng nhập & phân quyền | ✅ xem 3.1 |
| Live log Suricata, health check, SSE | ✅ giữ & nâng cấp (nhiều sensor, tự kết nối lại, chống trùng) |

> Nếu chưa có VM/Wazuh/Telegram được cấu hình, giao diện hiển thị trạng thái **trống/chưa cấu hình** (không điền số liệu giả).

---

## 4. API tóm tắt (`/api`)
`POST /auth/login · GET /auth/me · POST /auth/change-password` ·
`GET|POST|PATCH|DELETE /users` (admin) · `GET|POST|PATCH|DELETE /vms` · `GET|POST|PATCH|DELETE /tools` ·
`GET|POST /gateway/tunnels · PATCH|DELETE /gateway/tunnels/:id · POST /gateway/tunnels/:id/start|stop · POST /gateway/cut-all · POST /gateway/probe` ·
`GET /ports/policy · GET /ports/check?port=` · `POST /terminal …` ·
`GET /alerts · POST /alerts` (cần `X-Ingest-Key`) `· GET /stats` ·
`GET|POST|DELETE /blocklist` · `GET|POST|PUT|DELETE /rules · POST /rules/deploy` ·
`GET /wazuh/status|agents|alerts` · `GET|PUT /settings · POST /settings/telegram-test` · `GET /audit` · `GET /events` (SSE).

## 5. Bảo mật – lưu ý khi dùng
- Chỉ dùng trong **mạng lab/được phép**. Đừng mở Backend ra Internet khi chưa có HTTPS + tường lửa/reverse proxy.
- Backend mặc định chỉ lắng nghe `127.0.0.1`. Nếu mở `0.0.0.0`, hãy giới hạn bằng firewall.
- Tunnel là TCP thuần: HTTPS vẫn mã hoá đầu-cuối tới đích (trình duyệt sẽ báo chứng chỉ tự ký của Wazuh như bình thường).
- Mật khẩu **không còn nằm trong mã nguồn**; xoá/đổi mật khẩu cũ đã từng ghi trong tài liệu lab (`password`, mật khẩu admin Wazuh) vì đã lộ.
- Sao lưu `backend/data/` (đặc biệt `secret.key` – mất file này là không giải mã được mật khẩu VM).

## 6. Xử lý sự cố nhanh
| Triệu chứng | Cách xử lý |
|---|---|
| Trang báo “Không kết nối được Backend” | Backend chưa chạy hoặc sai `API_BASE`/CORS (`FRONTEND_ORIGIN`) |
| VM luôn “mất kết nối” | Kiểm tra IP/cổng SSH, card Host-only; thử nút *Thử SSH* |
| “Host key của VM đã thay đổi” | VM cài lại → Sửa VM → tick *Reset host key* |
| Tunnel lỗi “administratively prohibited” | bật `AllowTcpForwarding yes` trong `/etc/ssh/sshd_config` của VM gateway |
| Chặn IP báo `failed` | tài khoản SSH cần sudo; điền *Mật khẩu sudo* hoặc `NOPASSWD` |
| Không có cảnh báo Suricata | VM cần vai trò `sensor`, đúng `logPath`, user SSH đọc được `fast.log` (nhóm `adm` hoặc sudo) |
