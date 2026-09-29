@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-OroResea.ps1"
if errorlevel 1 (
  echo.
  echo OroResea installation failed.
  pause
  exit /b 1
)
echo.
echo OroResea installation completed.
pause
