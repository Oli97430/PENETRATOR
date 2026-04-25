@echo off
rem ============================================================
rem   PENETRATOR - Auto-installer for Windows
rem ============================================================
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ============================================================
echo    PENETRATOR - Installation automatique
echo  ============================================================
echo.

rem --- 1. Check Python ---------------------------------------------------
set "PYTHON_CMD="
where py >nul 2>nul && set "PYTHON_CMD=py -3"
if "!PYTHON_CMD!"=="" (
    where python >nul 2>nul && set "PYTHON_CMD=python"
)
if "!PYTHON_CMD!"=="" (
    echo  [X] Python 3 est introuvable.
    echo      Telecharge-le ici : https://www.python.org/downloads/windows/
    echo      Pense a cocher "Add Python to PATH" pendant l'installation.
    start https://www.python.org/downloads/windows/
    pause
    exit /b 1
)
echo  [*] Python detecte :
!PYTHON_CMD! --version

rem --- 2. Upgrade pip ----------------------------------------------------
echo.
echo  [*] Mise a jour de pip...
!PYTHON_CMD! -m pip install --upgrade pip --disable-pip-version-check >nul 2>nul
if errorlevel 1 echo  [!] pip upgrade a echoue (pas critique).

rem --- 3. Install requirements ------------------------------------------
echo.
echo  [*] Installation des dependances Python (ceci peut prendre 1-2 min)...
!PYTHON_CMD! -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo  [X] L'installation des dependances a echoue.
    pause
    exit /b 1
)

rem --- 4. Install sqlmap (pure Python, tres utile) ----------------------
echo.
echo  [*] Installation de sqlmap...
!PYTHON_CMD! -m pip install --disable-pip-version-check sqlmap >nul 2>nul
if errorlevel 1 echo  [!] sqlmap non installe via pip (optionnel).

rem --- 5. Create desktop shortcut (optional) ---------------------------
echo.
echo  [*] Creation d'un raccourci sur le Bureau (optionnel)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop') + '\PENETRATOR.lnk'); ^
   $s.TargetPath = '%~dp0penetrator.bat'; ^
   $s.WorkingDirectory = '%~dp0'; ^
   $s.IconLocation = 'cmd.exe'; ^
   $s.Save()" 2>nul

rem --- 6. Summary --------------------------------------------------------
echo.
echo  ============================================================
echo    Installation terminee !
echo  ============================================================
echo.
echo    Pour lancer :
echo      [GUI moderne]  penetrator.bat        ou   double-clic sur le raccourci Bureau
echo      [Mode console] penetrator_cli.bat
echo.
echo    Outils externes optionnels :
echo      * nmap   - https://nmap.org/download.html
echo      * msfvenom (Metasploit) - https://www.metasploit.com/download
echo.
pause
