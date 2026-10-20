@echo off
setlocal
cd /d "%~dp0"
if not exist .env copy .env.example .env >nul
if not exist .env (
  echo Failed to create .env
  exit /b 1
)
node --version >nul 2>nul
if errorlevel 1 (
  echo Node.js 22 or newer is required.
  exit /b 1
)
npm install --no-audit --no-fund
if errorlevel 1 exit /b 1
echo Setup complete. Review .env, then run start.bat.
