@echo off
cd /d "%~dp0"
python scripts\start_host.py
if errorlevel 1 pause
