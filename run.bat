@echo off
REM ==== Flutter Interceptor - launch (GUI + console log window) ====
setlocal
set HERE=%~dp0

REM pick a Python: existing platform-tools venv first, else local .venv
set PY=C:\platform-tools\frida17\Scripts\python.exe
if not exist "%PY%" set PY=%HERE%.venv\Scripts\python.exe
if not exist "%PY%" (
  echo [!] No Python environment found. Run setup.bat first.
  pause & exit /b 1
)

REM keep this console open -> it shows the live engine log
chcp 65001 >nul
title Flutter Interceptor - engine log
"%PY%" "%HERE%flutter_interceptor.py"
echo(
echo [tool closed] press a key to exit...
pause >nul
