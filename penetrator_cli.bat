@echo off
rem Launcher for PENETRATOR on Windows
chcp 65001 >nul
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 penetrator.py %*
) else (
    python penetrator.py %*
)
endlocal
