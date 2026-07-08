@echo off
REM ==== Flutter Interceptor - one-time setup (creates a local Python venv) ====
setlocal
set HERE=%~dp0

echo(
echo === Flutter Interceptor setup ===
echo(

REM 1) reuse the existing platform-tools venv if present (fastest)
if exist "C:\platform-tools\frida17\Scripts\python.exe" (
  echo Found existing frida17 venv - nothing to install. Just run run.bat
  pause & exit /b 0
)

REM 2) otherwise build a local .venv here
where python >nul 2>&1
if errorlevel 1 (
  echo [!] Python not found. Install Python 3.10+ x64 from https://python.org  ^(tick "Add to PATH"^) then re-run setup.bat
  pause & exit /b 1
)

echo Creating virtual environment (.venv)...
python -m venv "%HERE%.venv" || ( echo [!] venv creation failed & pause & exit /b 1 )
echo Installing dependencies (frida + pywebview)...
"%HERE%.venv\Scripts\python.exe" -m pip install --upgrade pip
"%HERE%.venv\Scripts\python.exe" -m pip install -r "%HERE%requirements.txt" || ( echo [!] pip install failed & pause & exit /b 1 )

echo(
echo === Done. Double-click run.bat to launch. ===
pause
