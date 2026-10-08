# Starts DomainCheck on http://127.0.0.1:8000 for local use (Windows PowerShell).
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File scripts\run_local.ps1
# Stop with Ctrl+C.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path ".venv")) {
    Write-Host "First run: creating the virtual environment and installing dependencies..."
    python -m venv .venv
    & .\.venv\Scripts\python -m pip install -e .
}

# Plain HTTP on localhost, so the browser must be allowed to send the CSRF cookie back.
$env:DOMAINCHECK_SECURE_COOKIES = "false"
$env:DOMAINCHECK_HSTS = "false"
# Generous limits for your own testing (the defaults are 10 per IP and 3 per domain per hour).
$env:DOMAINCHECK_LIMIT_IP_PER_HOUR = "100"
$env:DOMAINCHECK_LIMIT_DOMAIN_PER_HOUR = "20"

Write-Host "DomainCheck is starting on http://127.0.0.1:8000  (Ctrl+C to stop)"
& .\.venv\Scripts\python -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
