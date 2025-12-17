# Run Replay Attack Tests from PowerShell
# Make sure backend is running on localhost:5000 first

Write-Host "Replay Attack Test Suite" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend URL: http://localhost:5000" -ForegroundColor Yellow
Write-Host ""

# Activate venv
Write-Host "Activating Python environment..." -ForegroundColor Green
& ".\backend\venv\Scripts\Activate.ps1"

# Run tests
Write-Host ""
Write-Host "Starting tests..." -ForegroundColor Green
Write-Host ""

python tests/test_replay_attacks.py

Write-Host ""
Write-Host "Tests completed!" -ForegroundColor Green
