# ============================================================
#   PENETRATOR - Auto-installer for Windows (PowerShell)
# ============================================================
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location -LiteralPath $PSScriptRoot

function Write-Step([string]$msg) { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "  [X] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "    PENETRATOR - Installation automatique" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host ""

# --- 1. Python ---------------------------------------------------------
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $python = @('py','-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $python = @('python')
}
if (-not $python) {
    Write-Err "Python 3 est introuvable."
    Write-Host "    Telecharge : https://www.python.org/downloads/windows/"
    Start-Process "https://www.python.org/downloads/windows/"
    Read-Host "Appuie sur Entree pour quitter"
    exit 1
}
Write-Step "Python detecte :"
& $python[0] $python[1..($python.Count-1)] '--version'

# --- 2. pip upgrade ----------------------------------------------------
Write-Step "Mise a jour de pip..."
try { & $python[0] $python[1..($python.Count-1)] -m pip install --upgrade pip --disable-pip-version-check | Out-Null } catch {}

# --- 3. Requirements --------------------------------------------------
Write-Step "Installation des dependances Python (cela peut prendre 1 a 2 min)..."
& $python[0] $python[1..($python.Count-1)] -m pip install --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Err "Echec de l'installation des dependances."
    Read-Host "Appuie sur Entree pour quitter"
    exit 1
}
Write-Ok "Dependances installees."

# --- 4. sqlmap --------------------------------------------------------
Write-Step "Installation de sqlmap (optionnel)..."
try { & $python[0] $python[1..($python.Count-1)] -m pip install --disable-pip-version-check sqlmap | Out-Null; Write-Ok "sqlmap installe." }
catch { Write-Warn "sqlmap non installe (optionnel)." }

# --- 5. Desktop shortcut ---------------------------------------------
Write-Step "Creation du raccourci Bureau..."
try {
    $desk = [Environment]::GetFolderPath('Desktop')
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut("$desk\PENETRATOR.lnk")
    $sc.TargetPath = "$PSScriptRoot\penetrator.bat"
    $sc.WorkingDirectory = $PSScriptRoot
    $sc.Save()
    Write-Ok "Raccourci cree sur le Bureau."
} catch {
    Write-Warn "Raccourci non cree (optionnel)."
}

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host "    Installation terminee !" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "    Lancer l'UI moderne : .\penetrator.bat"
Write-Host "    Mode console      : .\penetrator_cli.bat"
Write-Host ""
Write-Host "    Outils externes optionnels :"
Write-Host "      nmap     https://nmap.org/download.html"
Write-Host "      msfvenom https://www.metasploit.com/download"
Write-Host ""
Read-Host "Appuie sur Entree pour fermer"
