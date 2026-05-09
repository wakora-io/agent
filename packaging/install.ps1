$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$base = "https://get.wakora.io"
$key = $env:WAKORA_KEY

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "wakora installer needs an elevated PowerShell (run as Administrator)" -ForegroundColor Red
    exit 1
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $asset = "wakora.exe" }
    "ARM64" { $asset = "wakora-windows-arm64.exe" }
    default { Write-Host "unsupported windows arch: $($env:PROCESSOR_ARCHITECTURE) (amd64/arm64 published)" -ForegroundColor Red; exit 1 }
}

$tmp = Join-Path $env:TEMP "wakora-install.exe"
Write-Host "downloading $asset ..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/bin/$asset" -OutFile $tmp
$want = ((Invoke-WebRequest -UseBasicParsing -Uri "$base/bin/$asset.sha256").Content.Trim()).ToLower()
$got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if ($want -ne $got) {
    Remove-Item $tmp -Force
    Write-Host "checksum mismatch (want $want got $got)" -ForegroundColor Red
    exit 1
}

$dir = Join-Path $env:ProgramFiles "Wakora"
$exe = Join-Path $dir "wakora.exe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$svc = Get-Service -Name wakora -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") { Stop-Service -Name wakora -Force }
Move-Item -Force $tmp $exe
Write-Host "installed $exe ($(& $exe --version))"

if ($key) {
    & $exe --key $key
} else {
    Write-Host "no WAKORA_KEY set; register later with: & '$exe' --key <TEAMKEY>"
}

& $exe service install
Write-Host "Done! Host will appear in the console within ~1 minute"
