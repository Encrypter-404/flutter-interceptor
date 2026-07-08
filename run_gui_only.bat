@echo off
REM ==== Flutter Interceptor - launch GUI only (no console window) ====
setlocal
set HERE=%~dp0
set PYW=C:\platform-tools\frida17\Scripts\pythonw.exe
if not exist "%PYW%" set PYW=%HERE%.venv\Scripts\pythonw.exe
if not exist "%PYW%" (
  echo [!] No Python environment found. Run setup.bat first.
  pause & exit /b 1
)
start "" "%PYW%" "%HERE%flutter_interceptor.py"
