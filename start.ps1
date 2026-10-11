param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$socPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $socPython)) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required.' }
}
& $socPython -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required. Recreate .venv with a supported Python.' }
$socDependencyStamp = Join-Path $PSScriptRoot '.venv\requirements.sha256'
$socRequirementsHash = ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'requirements.txt'), (Join-Path $PSScriptRoot 'requirements.lock.txt') -Algorithm SHA256).Hash -join ':')
$socInstalledHash = if (Test-Path -LiteralPath $socDependencyStamp) { (Get-Content -LiteralPath $socDependencyStamp -Raw).Trim() } else { '' }
if ($socInstalledHash -ne $socRequirementsHash) {
    & $socPython -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    Set-Content -LiteralPath $socDependencyStamp -Value $socRequirementsHash -Encoding ASCII
}
if (-not $env:SOC_MODE) { $env:SOC_MODE = 'demo' }
if (-not $env:SOC_ORIGIN) { $env:SOC_ORIGIN = "http://127.0.0.1:$Port" }
Write-Output "AI-SOC: http://127.0.0.1:$Port"
Write-Output "Live HTTP range: http://127.0.0.1:$Port/#lab"
Write-Output 'HTTP range enforces real loopback-only blocks. Bank response adapters remain simulated.'
& $socPython -m uvicorn app.main:app --host 127.0.0.1 --port $Port --workers 1 --no-proxy-headers
