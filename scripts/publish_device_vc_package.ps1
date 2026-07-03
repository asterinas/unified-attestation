param(
  [string]$Config = ".iota-client.yaml",
  [string]$Env = "testnet",
  [string]$PackagePath = "device_vc_chain",
  [string]$GasBudget = "100000000"
)

$result = iota client `
  --client.config $Config `
  --client.env $Env `
  publish $PackagePath `
  --gas-budget $GasBudget `
  --json

$result

$lock = Join-Path $PackagePath "Move.lock"
if (Test-Path $lock) {
  $text = Get-Content -Raw $lock
  $match = [regex]::Match($text, 'latest-published-id\s*=\s*"([^"]+)"')
  if ($match.Success) {
    Write-Host "Set this before running verifier:"
    Write-Host "`$env:IOTA_DEVICE_VC_PACKAGE_ID=`"$($match.Groups[1].Value)`""
    Write-Host "`$env:IOTA_CLIENT_ENV=`"$Env`""
    Write-Host "`$env:IOTA_GAS_BUDGET=`"$GasBudget`""
  }
}
