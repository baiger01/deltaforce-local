@echo off
setlocal
cd /d "%~dp0"
python -m dfserver.entrance %*
if errorlevel 1 pause
