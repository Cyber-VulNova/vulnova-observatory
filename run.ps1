# One-command launcher for VulNova Observatory (Windows / PowerShell).
# Creates an isolated virtual env, installs the app, and starts the dashboard.
# Usage:  .\run.ps1            (starts on http://127.0.0.1:5000)
#         .\run.ps1 --port 8080 --refresh-hours 6
$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating virtual environment (.venv)..."
    python -m venv .venv
}

$venvPy = Join-Path ".venv" "Scripts\python.exe"
Write-Host "[*] Installing VulNova Observatory..."
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install . | Out-Null

Write-Host "[*] Starting the dashboard..."
& $venvPy -m vulnova.cli web @args
