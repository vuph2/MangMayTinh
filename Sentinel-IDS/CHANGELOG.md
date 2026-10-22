# Changelog – Sentinel IDS

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [V1.3] – 2026-10-22

### Merged
- Pulled teammate's **V1.2** refactor (`feat: Update the whole code [ V1.2 ]`, commit `9ac4e82`) into the local `main` branch via a clean fast-forward merge.
- No merge conflicts – working tree was clean after discarding stale runtime data files (`server/data/agents.json`, `server/data/alerts.json`) that are no longer part of the V1.2 project structure.

### Changed
- Bumped backend `package.json` version from `2.0.0` → `2.1.0` to track this integration point.

### Project structure after V1.3
```
Sentinel-IDS/
├─ backend/             # Node.js API server (port 3000)
│  ├─ server.js
│  ├─ src/auth.js · config.js · http.js
│  ├─ src/db/store.js
│  ├─ src/routes/index.js
│  ├─ src/security/crypto.js
│  ├─ src/services/   alerts · audit · blocklist · events · monitor
│  │                  portpolicy · rules · sensors · settings · ssh
│  │                  telegram · terminals · tools · tunnels · users · vms · wazuh
│  ├─ test/selftest.js
│  └─ data/            (runtime – gitignored)
├─ frontend/            # Vanilla HTML/CSS/JS UI (port 5173)
│  ├─ index.html · serve.js · css/style.css
│  └─ js/  api · app · config · sound · ui
│         views/  account · admin · alerts · dashboard · gateway · ports · security
├─ scripts/
│  ├─ eve_forwarder.py  # Streams Suricata fast.log via SSH → backend /api/alerts
│  └─ block_ip.sh       # Manual IP block helper
├─ docs/LAB_SETUP.md
├─ start.bat / start.sh
├─ CHANGELOG.md         ← this file (added in V1.3)
└─ README.md
```

---

## [V1.2] – 2026-10-22

### Added (teammate's contribution)
- Full project restructure under `Sentinel-IDS/` (52 new files, 4 011 insertions).
- Modular backend: auth (JWT + scrypt), AES-256-GCM VM password encryption, SSH host-key TOFU.
- Gateway with SSH tunnelling, multi-tool dropdown (Wazuh, OpenSearch, DVWA, SSH Terminal, custom TCP, etc.).
- Real-time Suricata log streaming (SSH `tail -F fast.log`), Wazuh API/Indexer integration.
- Telegram bot notifications (real API calls).
- Admin panel: user management, VM management, Suricata rule deployment, IP blocklist (iptables via SSH), audit log, system settings.
- Port management with per-user port ranges and probe feature.
- `start.bat` / `start.sh` one-click launcher.
- Self-test suite (`backend/test/selftest.js`, 58 checks).
- `docs/LAB_SETUP.md` for VM preparation guide.

### Removed
- All mock data, random alert generators, hard-coded credentials, localStorage stubs.

---

## [V1.1] – Earlier

- Automatic live SSH Suricata log streamer from Victim VM.
- Removed all mock alerts / generators for 100 % real-world data.
- Real-time agent status sync via SSE/polling.

---

## [V1.0] – Initial

- Complete Sentinel IDS dashboard, attack simulator, and lab setup for the MMT project.
