param(
  [string]$MoveLock = "device_vc_chain\Move.lock",
  [string]$Env = "testnet",
  [string]$GasBudget = "100000000"
)

if (!(Test-Path $MoveLock)) {
  throw "Move.lock not found: $MoveLock. Publish device_vc_chain first."
}

$text = Get-Content -Raw $MoveLock
$match = [regex]::Match($text, 'latest-published-id\s*=\s*"([^"]+)"')
if (!$match.Success) {
  throw "latest-published-id not found in $MoveLock"
}

$env:IOTA_DEVICE_VC_PACKAGE_ID = $match.Groups[1].Value
$env:IOTA_CLIENT_ENV = $Env
$env:IOTA_GAS_BUDGET = $GasBudget

Write-Host "IOTA_DEVICE_VC_PACKAGE_ID=$env:IOTA_DEVICE_VC_PACKAGE_ID"
Write-Host "IOTA_CLIENT_ENV=$env:IOTA_CLIENT_ENV"
Write-Host "IOTA_GAS_BUDGET=$env:IOTA_GAS_BUDGET"
