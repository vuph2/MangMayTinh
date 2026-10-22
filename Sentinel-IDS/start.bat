@echo off
chcp 65001 >nul
title Sentinel IDS - Backend + Frontend
echo ====================================================
echo   SENTINEL IDS v2  -  Do an Mang May Tinh
echo ====================================================
cd /d "%~dp0backend"
if not exist node_modules (
  echo [1/3] Cai dat thu vien Backend...
  call npm install
)
echo [2/3] Khoi dong BACKEND (cong 3000) trong cua so moi...
start "Sentinel Backend" cmd /k "cd /d %~dp0backend && node server.js"
timeout /t 2 >nul
echo [3/3] Khoi dong FRONTEND (cong 5173) trong cua so moi...
start "Sentinel Frontend" cmd /k "cd /d %~dp0frontend && node serve.js"
timeout /t 2 >nul
start "" http://localhost:5173
echo Da khoi dong. Xem mat khau admin lan dau trong cua so "Sentinel Backend".
