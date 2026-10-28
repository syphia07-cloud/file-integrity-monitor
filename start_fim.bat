@echo off
cd /d "%~dp0"
start "FIM Watcher" cmd /k python watcher.py
start "FIM Dashboard" cmd /k python dashboard.py
ping -n 4 127.0.0.1 >nul
start http://localhost:5000