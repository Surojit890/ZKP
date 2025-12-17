# PowerShell script to run all ZKP tests
# Usage: .\tests\run_all_tests.ps1

Write-Host "`n" -NoNewline
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "     ZKP Authentication System - Complete Test Suite (PowerShell)              " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date
$projectRoot = Split-Path -Parent $PSScriptRoot
$testsDir = $PSScriptRoot

# Track results
$results = @{}

# 1. Run pytest unit tests
Write-Host "`n1. Unit Tests (pytest)" -ForegroundColor Blue
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Blue
python -m pytest "$testsDir\test_backend.py" -v
$results['unit_tests'] = $LASTEXITCODE -eq 0

# 2. Check if server is running
Write-Host "`n2. Checking Backend Server Status" -ForegroundColor Blue
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Blue

try {
    $response = Invoke-WebRequest -Uri "http://localhost:5000/health" -TimeoutSec 2 -UseBasicParsing
    $serverRunning = $response.StatusCode -eq 200
    Write-Host "✓ Backend server is running on http://localhost:5000" -ForegroundColor Green
} catch {
    $serverRunning = $false
    Write-Host "⚠ Backend server is NOT running" -ForegroundColor Yellow
    Write-Host "  Security tests require the backend server to be running." -ForegroundColor Yellow
    Write-Host "  Start it with: python backend\app_final.py" -ForegroundColor Yellow
    
    $continue = Read-Host "`nContinue with security tests anyway? (y/n)"
    if ($continue -ne 'y') {
        Write-Host "`nSkipping security tests." -ForegroundColor Yellow
        # Print summary and exit
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Write-Host "`n" -NoNewline
        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host "                              Test Summary                                      " -ForegroundColor Cyan
        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host "Duration: $([math]::Round($duration, 2)) seconds"
        Write-Host "Unit Tests: " -NoNewline
        if ($results['unit_tests']) {
            Write-Host "PASSED" -ForegroundColor Green
        } else {
            Write-Host "FAILED" -ForegroundColor Red
        }
        Write-Host "Security Tests: SKIPPED (server not running)" -ForegroundColor Yellow
        exit 0
    }
}

# 3. Run MITM attack tests
Write-Host "`n3. MITM Attack Simulation Tests" -ForegroundColor Blue
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Blue
python "$testsDir\test_mitm_vectors.py"
$results['mitm_tests'] = $LASTEXITCODE -eq 0

# 4. Run replay attack tests
Write-Host "`n4. Replay Attack Tests" -ForegroundColor Blue
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Blue
python "$testsDir\test_replay_attacks.py"
$results['replay_tests'] = $LASTEXITCODE -eq 0

# 5. Run XSS security tests
Write-Host "`n5. XSS Security Tests" -ForegroundColor Blue
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Blue
python "$testsDir\test_xss_vectors.py"
$results['xss_tests'] = $LASTEXITCODE -eq 0

# Print summary
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host "`n" -NoNewline
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                              Test Summary                                      " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$totalSuites = $results.Count
$passedSuites = ($results.Values | Where-Object { $_ -eq $true }).Count
$failedSuites = $totalSuites - $passedSuites

Write-Host "`nTotal Test Suites: $totalSuites"
Write-Host "Passed: $passedSuites" -ForegroundColor Green
if ($failedSuites -gt 0) {
    Write-Host "Failed: $failedSuites" -ForegroundColor Red
}

Write-Host "`nDuration: $([math]::Round($duration, 2)) seconds"
Write-Host "Completed: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"

Write-Host "`nDetailed Results:" -ForegroundColor White
Write-Host "--------------------------------------------------------------------------------"

$testNames = @{
    'unit_tests' = 'Backend Unit Tests'
    'mitm_tests' = 'MITM Attack Tests'
    'replay_tests' = 'Replay Attack Tests'
    'xss_tests' = 'XSS Security Tests'
}

foreach ($key in $testNames.Keys) {
    $name = $testNames[$key]
    $status = if ($results[$key]) { "✓ PASSED" } else { "✗ FAILED" }
    $color = if ($results[$key]) { "Green" } else { "Red" }
    
    Write-Host ("{0,-50} " -f $name) -NoNewline
    Write-Host $status -ForegroundColor $color
}

Write-Host "================================================================================" -ForegroundColor Cyan

# Overall status
if ($failedSuites -eq 0) {
    Write-Host "`n🎉 ALL TESTS PASSED! 🎉" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ SOME TESTS FAILED" -ForegroundColor Red
    exit 1
}
