@echo off
title Sentinel IDS Server - Do An MMT
echo ====================================================
echo        SENTINEL IDS - HE THONG GIAM SAT AN NINH MANG
echo               Do An Mon Mang May Tinh (MMT)
echo ====================================================
echo.
cd /d "D:\MMT\server"
echo [1/2] Dang khoi dong Web Server tai http://localhost:3000 ...
start "" "http://localhost:3000"
node server.js
pause
