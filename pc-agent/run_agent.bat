@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ==================================================
REM  SysPulse Agent - Run Script (Windows)
REM  - Writes config.json from env vars
REM  - Starts agent
REM ==================================================

cd /d C:\pc-agent

REM ---------- CONFIG (EDIT HERE) ----------
set "MONITOR_SERVER=http://PC-DATECSA-USC:8000"
set "AGENT_TOKEN=token_servidor_001"
set "REPORT_INTERVAL=10"
set "TOP_N=5"
set "TIMEOUT=5"
set "VERIFY_TLS=true"
set "DISK_PATH="
set "REGEN_DEVICE_ID=false"
set "DEVICE_ID_FILE=C:\pc-agent\device_id.txt"
REM ---------------------------------------

REM Make sure logs folder exists
if not exist "logs" mkdir "logs"

REM ---------- Write config.json ----------
REM Note: agent.py reads:
REM   - token from env var AGENT_TOKEN (priority)
REM   - server/interval/top_n from config.json
REM This script ensures everything is consistent.

(
  echo {
  echo   "server": "%MONITOR_SERVER%",
  echo   "token": "%AGENT_TOKEN%",
  echo   "interval": %REPORT_INTERVAL%,
  echo   "top_n": %TOP_N%,
  echo   "timeout": %TIMEOUT%,
  echo   "verify_tls": %VERIFY_TLS%,
  echo   "disk_path": "%DISK_PATH%",
  echo   "regen_device_id": %REGEN_DEVICE_ID%
  echo }
) > "config.json"

REM ---------- Optional: force device_id file path ----------
REM Your agent uses DEVICE_ID_PATH inside its folder (device_id.txt).
REM If you want to force a custom location, keep the file here:
REM C:\pc-agent\device_id.txt  (recommended)
REM We'll copy if you defined DEVICE_ID_FILE elsewhere.

if not "%DEVICE_ID_FILE%"=="C:\pc-agent\device_id.txt" (
  if exist "%DEVICE_ID_FILE%" (
    copy /Y "%DEVICE_ID_FILE%" "C:\pc-agent\device_id.txt" >nul
  )
)

REM ---------- Export env vars (agent reads AGENT_TOKEN) ----------
set "AGENT_TOKEN=%AGENT_TOKEN%"

echo.
echo ==========================================
echo  Starting SysPulse Agent...
echo  Folder: %CD%
echo  Server: %MONITOR_SERVER%
echo  Interval: %REPORT_INTERVAL%s
echo  Top N: %TOP_N%
echo  Token: (set)
echo ==========================================
echo.

REM ---------- Run agent ----------
"C:\pc-agent\venv\Scripts\python.exe" "C:\pc-agent\agent.py"

echo.
echo Agent stopped. Check logs: C:\pc-agent\logs\agent.log
pause
endlocal