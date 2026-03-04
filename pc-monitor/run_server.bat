@echo off

REM ======================================
REM PC MONITOR SERVER START SCRIPT
REM ======================================

cd /d %~dp0

REM Activar entorno virtual
call venv\Scripts\activate

REM --------------------------
REM CONFIGURACION DASHBOARD
REM --------------------------

REM Usuario del login
set DASH_USER=admin

REM Cambia esta clave por una segura
set DASH_PASS=admin123

REM --------------------------
REM CONFIGURACION AGENTE
REM --------------------------

REM 🔐 TOKEN que deben usar TODOS los agentes
set AGENT_TOKEN=MI_TOKEN_SUPER_SEGURO

REM --------------------------
REM CONFIGURACION SISTEMA
REM --------------------------

REM Dias de retencion de datos
set RETENTION_DAYS=7

REM Segundos para marcar offline
set OFFLINE_AFTER_SECONDS=60

REM Limpieza cada 6 horas
set CLEANUP_EVERY_SECONDS=21600

REM --------------------------
REM INICIAR SERVIDOR
REM --------------------------

echo.
echo ======================================
echo Iniciando PC Monitor Server...
echo ======================================
echo.

uvicorn server:app --host 0.0.0.0 --port 8000

pause