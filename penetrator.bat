@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 "%~dp0penetrator.py" %*
) else (
    python "%~dp0penetrator.py" %*
)

endlocal
