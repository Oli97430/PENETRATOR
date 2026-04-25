# PENETRATOR GUI launcher (PowerShell)
Set-Location -LiteralPath $PSScriptRoot

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 (Join-Path $PSScriptRoot 'penetrator.py') @args
} else {
    & python (Join-Path $PSScriptRoot 'penetrator.py') @args
}
