@echo off
setlocal

REM === Description ===
REM This batch script unblocks and executes the Windows Hardening Audit tool
REM with remediation and high-finding fail handling enabled.

echo ============================================================
echo   Windows Hardening Audit - Automated Execution
echo ============================================================
echo.

REM Move to the directory of this script (useful if run from another location)
cd /d "%~dp0"

REM Target PowerShell script name (you can edit version name here)
set SCRIPT_NAME=Win_Hardening_Audit.ps1

REM Step 1: Unblock the script
echo [*] Unblocking %SCRIPT_NAME% ...
powershell -Command "Unblock-File .\%SCRIPT_NAME%"

REM Step 2: Run PowerShell with ExecutionPolicy Bypass
echo [*] Running Hardening Audit with remediation and strict mode ...
powershell -ExecutionPolicy Bypass -NoProfile -Command ^
    ".\%SCRIPT_NAME% -WithRemediation -FailOnHighFindings"

echo.
echo ============================================================
echo   Audit Execution Completed
echo ============================================================

pause
endlocal
