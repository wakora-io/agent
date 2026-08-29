$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$base = "https://get.wakora.io"
$pubEc = "__WAKORA_PUBKEY_EC__"
$key = $env:WAKORA_KEY

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "wakora installer needs an elevated PowerShell (run as Administrator)" -ForegroundColor Red
    exit 1
}

function Pad32([byte[]]$v, [int]$off, [byte[]]$dst) {
    $src = $v
    while ($src.Length -gt 32 -and $src[0] -eq 0) { $src = [byte[]]$src[1..($src.Length - 1)] }
    if ($src.Length -gt 32) { throw "signature integer does not fit a P-256 coordinate" }
    [Array]::Copy($src, 0, $dst, $off + 32 - $src.Length, $src.Length)
}

function RawSigFromDer([byte[]]$der) {
    if ($der.Length -lt 8 -or $der[0] -ne 0x30) { throw "signature is not a DER sequence" }
    $i = 2
    if ($der[1] -gt 0x7f) { $i += ($der[1] - 0x80) }
    if ($der[$i] -ne 0x02) { throw "signature r is not an integer" }
    $rl = $der[$i + 1]
    $r = [byte[]]$der[($i + 2)..($i + 1 + $rl)]
    $i = $i + 2 + $rl
    if ($der[$i] -ne 0x02) { throw "signature s is not an integer" }
    $sl = $der[$i + 1]
    $s = [byte[]]$der[($i + 2)..($i + 1 + $sl)]
    $out = New-Object byte[] 64
    Pad32 $r 0 $out
    Pad32 $s 32 $out
    return $out
}

function EcdsaFromSpki([byte[]]$spki) {
    if ($spki.Length -lt 65) { throw "publisher key is not a P-256 SubjectPublicKeyInfo" }
    $point = [byte[]]$spki[($spki.Length - 65)..($spki.Length - 1)]
    if ($point[0] -ne 4) { throw "publisher key is not an uncompressed P-256 point" }
    $blob = New-Object byte[] 72
    [Array]::Copy([BitConverter]::GetBytes([int]0x31534345), 0, $blob, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes([int]32), 0, $blob, 4, 4)
    [Array]::Copy($point, 1, $blob, 8, 64)
    $k = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    return New-Object Security.Cryptography.ECDsaCng($k)
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $asset = "wakora.exe" }
    "ARM64" { $asset = "wakora-windows-arm64.exe" }
    default { Write-Host "unsupported windows arch: $($env:PROCESSOR_ARCHITECTURE) (amd64/arm64 published)" -ForegroundColor Red; exit 1 }
}

$tmp = Join-Path $env:TEMP "wakora-install.exe"
$sigTmp = "$tmp.sig2"
Write-Host "downloading $asset ..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/bin/$asset" -OutFile $tmp
$want = ((Invoke-WebRequest -UseBasicParsing -Uri "$base/bin/$asset.sha256").Content.Trim()).ToLower()
$got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if ($want -ne $got) {
    Remove-Item $tmp -Force
    Write-Host "checksum mismatch (want $want got $got)" -ForegroundColor Red
    exit 1
}

if (-not $pubEc -or $pubEc -eq "__WAKORA_PUBKEY_EC__") {
    Remove-Item $tmp -Force
    Write-Host "installer has no publisher key baked in; refusing to install an unverified binary" -ForegroundColor Red
    Write-Host "(the get.wakora.io deploy must replace __WAKORA_PUBKEY_EC__ with the real key)" -ForegroundColor Red
    exit 1
}
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/bin/$asset.sig2" -OutFile $sigTmp
} catch {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Host "binary signature missing from channel; aborting" -ForegroundColor Red
    exit 1
}
try {
    $ec = EcdsaFromSpki ([Convert]::FromBase64String($pubEc))
    $sig = RawSigFromDer ([IO.File]::ReadAllBytes($sigTmp))
    $ok = $ec.VerifyData([IO.File]::ReadAllBytes($tmp), $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)
} catch {
    $ok = $false
    Write-Host "signature check could not run: $($_.Exception.Message)" -ForegroundColor Red
}
Remove-Item $sigTmp -Force -ErrorAction SilentlyContinue
if (-not $ok) {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Host "binary signature INVALID; aborting" -ForegroundColor Red
    exit 1
}
Write-Host "signature verified"

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
