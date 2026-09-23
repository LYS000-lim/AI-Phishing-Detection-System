@echo off
REM Starts the PhishGuard backend (project .venv, IPv4 127.0.0.1:8000) and
REM the frontend dev server in two windows. Open http://localhost:5173
cd /d "%~dp0"
start "PhishGuard backend" cmd /k ".venv\Scripts\python -m uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8000"
start "PhishGuard frontend" cmd /k "npm --prefix frontend run dev"
