@echo off
cd /d "%~dp0"
echo === BAT START === > "%~dp0deploy.log"
echo Working dir: %CD% >> "%~dp0deploy.log"
echo Time: %DATE% %TIME% >> "%~dp0deploy.log"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy-fq.ps1" >> "%~dp0deploy.log" 2>&1
echo === BAT EXIT %ERRORLEVEL% === >> "%~dp0deploy.log"
echo Time: %DATE% %TIME% >> "%~dp0deploy.log"
echo.
echo ===== KONIEC (ERRORLEVEL=%ERRORLEVEL%). Log: deploy.log =====
timeout /t 30
