# ==============================================================================
# CyberNex — Automated Launcher Script (PowerShell)
# ==============================================================================

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CyberNex — Intelligent Cybersecurity Monitoring Platform" -ForegroundColor Cyan
Write-Host "  AI-Powered Threat Detection with Blockchain-Audited Security Intelligence" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Launching CyberNex FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
$backendJob = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload" -PassThru

Write-Host "[*] Launching CyberNex Next.js Frontend on http://localhost:3000..." -ForegroundColor Yellow
$frontendJob = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory ".\frontend" -PassThru

Write-Host ""
Write-Host "[+] CyberNex is now running!" -ForegroundColor Green
Write-Host "    Frontend Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "    Backend API:        http://127.0.0.1:8000" -ForegroundColor White
Write-Host "    Swagger Docs:       http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "Press Enter to stop all CyberNex services..." -ForegroundColor Magenta
Read-Host

Stop-Process -Id $backendJob.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $frontendJob.Id -Force -ErrorAction SilentlyContinue
Write-Host "[*] CyberNex services stopped cleanly." -ForegroundColor Yellow

