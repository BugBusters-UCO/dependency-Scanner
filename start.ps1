$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$InstallStamp = Join-Path $ProjectRoot ".venv\.requirements.hash"
$Port = if ($env:SCANNER_PORT) { $env:SCANNER_PORT } else { "8001" }

Set-Location $ProjectRoot

if (-not (Test-Path $VenvPython)) {
    Write-Host "Creating virtual environment..."
    $Python = Get-Command python -ErrorAction SilentlyContinue

    if (-not $Python) {
        $BundledPython = "C:\Users\hp\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
        if (Test-Path $BundledPython) {
            $Python = @{ Source = $BundledPython }
        }
    }

    if (-not $Python) {
        throw "Python was not found. Install Python 3.12+ or update start.ps1 with your Python path."
    }

    & $Python.Source -m venv ".venv"
}

$RequirementsHash = (Get-FileHash $Requirements -Algorithm SHA256).Hash
$InstalledHash = if (Test-Path $InstallStamp) { Get-Content $InstallStamp -Raw } else { "" }

if ($InstalledHash.Trim() -ne $RequirementsHash) {
    Write-Host "Installing backend dependencies..."
    & $VenvPython -m pip install -r $Requirements
    Set-Content -Path $InstallStamp -Value $RequirementsHash
}

Write-Host "Starting Dependency Scanner Backend on http://127.0.0.1:$Port"
Write-Host "API docs: http://127.0.0.1:$Port/docs"
& $VenvPython -m uvicorn app.main:app --host 127.0.0.1 --port $Port --env-file .env --reload
