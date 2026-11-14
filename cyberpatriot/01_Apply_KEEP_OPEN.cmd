@echo off
setlocal EnableExtensions DisableDelayedExpansion
title CyberPatriot Win11 v3 - Apply
cd /d "%~dp0"
echo ================================================================
echo CyberPatriot Windows 11 Fixed v3
echo MODE: Apply  (Apply=changes system; Audit=read only)
echo ================================================================
echo This window will stay open even if PowerShell fails to start.
echo.
if not exist "%~dp0CyberPatriot_Win11_Fixed_v3.ps1" (
  echo ERROR: Extract ALL the ZIP files to ONE folder first.
  goto :end
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0CyberPatriot_Win11_Fixed_v3.ps1" -Mode Apply
echo.
echo PowerShell returned; exit code=%errorlevel%
echo See any errors displayed above.
:end
echo.
echo This CMD window stays open. Press any key only when done reading.
pause >nul
endlocal