Set-Location $PSScriptRoot

$pythonBin = if (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe") {
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
} else {
    "python"
}

Write-Host "ScamShield Launcher (PowerShell)" -ForegroundColor Cyan
Write-Host "Using Python: $pythonBin" -ForegroundColor Gray

& $pythonBin check_backend.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Running pip install..." -ForegroundColor Yellow
    & $pythonBin -m pip install -r requirements.txt
}

Write-Host "Starting ScamShield on http://127.0.0.1:5000 ..." -ForegroundColor Green
& $pythonBin app.py
Read-Host "Press Enter to close"
