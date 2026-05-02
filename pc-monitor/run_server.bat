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

REM Usuario admin
set DASH_USER=admin

REM ⚠️ CAMBIA ESTA CONTRASEÑA
set DASH_PASS=Admin_2025_Segura!

REM --------------------------
REM CONFIGURACION AGENTE
REM --------------------------

REM TOKEN para los agentes
set AGENT_TOKEN=MI_TOKEN_SUPER_SEGURO

REM --------------------------
REM CONFIGURACION SISTEMA
REM --------------------------

REM Días de retención
set RETENTION_DAYS=7

REM Tiempo para marcar offline
set OFFLINE_AFTER_SECONDS=60

REM Limpieza cada 6 horas
set CLEANUP_EVERY_SECONDS=21600

REM --------------------------
REM CONFIGURACION EMAIL (MUY IMPORTANTE)
REM --------------------------

REM 🔴 CONFIGURA ESTO CON TU CORREO REAL

set SMTP_HOST=smtp.gmail.com
set SMTP_PORT=587

set SMTP_USER=syspulseweb@gmail.com
set SMTP_PASS=tainefwxmlnqxjzr

set SMTP_FROM=syspulseweb@gmail.com
set SMTP_USE_TLS=1

REM Tiempo de expiración códigos
set VERIFY_CODE_TTL_MIN=10
set RESET_CODE_TTL_MIN=10

REM --------------------------
REM INICIAR SERVIDOR
REM --------------------------

echo.
echo ======================================
echo Iniciando SysPulse Server...
echo ======================================
echo.

uvicorn server:app --host 0.0.0.0 --port 8000 --reload

pause