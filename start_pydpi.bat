@echo off
REM Double-click this file to run PyDPI. Everything is set up automatically.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_pydpi.ps1" %*
if errorlevel 9009 (
    echo.
    echo PowerShell was not found on this computer.
    pause
)
