#!/usr/bin/env bash
# Chay Backend + Frontend (Linux/macOS). Ctrl+C de dung ca hai.
set -e
cd "$(dirname "$0")"
[ -d backend/node_modules ] || (cd backend && npm install)
(cd backend && node server.js) & BE=$!
(cd frontend && node serve.js) & FE=$!
trap 'kill $BE $FE 2>/dev/null' INT TERM EXIT
echo "Backend: http://localhost:3000/api   Frontend: http://localhost:5173"
wait
