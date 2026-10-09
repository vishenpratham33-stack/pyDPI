<#
  PyDPI one-click launcher for Windows.

  Easiest: double-click  start_pydpi.bat
  Or run:  powershell -ExecutionPolicy Bypass -File .\start_pydpi.ps1 -Seconds 60

  What it does for you, in order:
    1. asks for administrator rights (needed to watch network traffic)
    2. finds Python 3.10+
    3. creates the .venv, or rebuilds it if it is broken (for example after a folder rename)
    4. installs PyDPI and its libraries if they are missing
    5. runs:  pydpi auto   (checks setup, picks the adapter, watches traffic, saves results)
    6. opens the results folder
#>
param(
    [int]$Seconds = 60,          # how long to watch (0 = until you press Ctrl+C)
    [string]$Interface = "",     # adapter number or name; empty = detect automatically
    [switch]$Save,               # also keep the captured packets
    [switch]$Demo,               # use the demo capture, no admin rights or driver needed
    [switch]$NoAdmin             # do not ask for administrator rights
)

$ErrorActionPreference = "Continue"
Set-Location -Path $PSScriptRoot            # always work inside the project folder
$env:PYTHONUTF8 = "1"                       # avoids 'charmap' text errors on Windows
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Stop-Here([int]$code) {
    Write-Host ""
    Read-Host "Press Enter to close this window" | Out-Null
    exit $code
}
function Fail([string]$message) {
    Write-Host ""
    Write-Host "ERROR: $message" -ForegroundColor Red
    Stop-Here 1
}

# ---- 1. administrator rights -------------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoAdmin -and -not $Demo) {
    Write-Host "PyDPI needs administrator rights to watch network traffic."
    Write-Host "A Windows permission window will open. Click Yes."
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Seconds", $Seconds)
    if ($Interface) { $argList += @("-Interface", "`"$Interface`"") }
    if ($Save) { $argList += "-Save" }
    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
    exit 0
}

# ---- 2. find Python 3.10+ ----------------------------------------------------------------
$candidates = @(
    @{ Exe = "python"; Extra = @() },
    @{ Exe = "py";     Extra = @("-3") }
)
$pythonExe = $null
$pythonExtra = @()
foreach ($c in $candidates) {
    $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $out = & $cmd.Source @($c.Extra) -c "import sys; print(sys.version_info >= (3, 10))" 2>$null
    if ("$out".Trim() -eq "True") {
        $pythonExe = $cmd.Source
        $pythonExtra = $c.Extra
        break
    }
}
if (-not $pythonExe) {
    Fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads and tick 'Add python.exe to PATH'."
}
Write-Host "Using Python: $pythonExe"

# ---- 3. virtual environment (rebuilt automatically if broken) ----------------------------
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$healthy = $false
if (Test-Path $venvPython) {
    try {
        & $venvPython -c "import sys" 2>$null
        $healthy = ($LASTEXITCODE -eq 0)
    } catch {
        $healthy = $false          # a corrupted python.exe throws instead of returning an error code
    }
}
if (-not $healthy) {
    Write-Host "Creating the project environment (.venv)..."
    if (Test-Path (Join-Path $PSScriptRoot ".venv")) {
        Remove-Item -Recurse -Force (Join-Path $PSScriptRoot ".venv")
    }
    & $pythonExe @pythonExtra -m venv (Join-Path $PSScriptRoot ".venv")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Fail "Could not create the .venv folder. Check that you have write permission here."
    }
}

# ---- 4. install PyDPI if needed ----------------------------------------------------------
$installed = $false
try {
    & $venvPython -c "import pydpi, scapy, dpkt, cryptography, yaml, rich, typer" 2>$null
    $installed = ($LASTEXITCODE -eq 0)
} catch { $installed = $false }
if (-not $installed) {
    Write-Host "Installing PyDPI and its libraries (first time only, about 1-2 minutes)..."
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -e "." --quiet
    if ($LASTEXITCODE -ne 0) {
        Fail "Installation failed. Check your internet connection and run this file again."
    }
}

# ---- 5. run the one-command workflow -----------------------------------------------------
if ($Demo) {
    $runArgs = @("auto", "--replay", "examples\demo.pcap")
} else {
    $runArgs = @("auto", "--seconds", $Seconds)
    if ($Interface) { $runArgs += @("--interface", $Interface) }
    if ($Save) { $runArgs += "--save" }
}
& $venvPython -m pydpi @runArgs
$exitCode = $LASTEXITCODE

# ---- 6. open the newest results folder ---------------------------------------------------
$latest = Get-ChildItem -Path (Join-Path $PSScriptRoot "pydpi_reports") -Directory -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest -and $exitCode -eq 0) {
    Write-Host "Opening your results folder: $($latest.FullName)"
    Start-Process explorer.exe $latest.FullName
}
Stop-Here $exitCode
