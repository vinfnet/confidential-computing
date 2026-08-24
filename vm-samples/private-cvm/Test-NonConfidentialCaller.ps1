[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$VaultName,

    [Parameter(Mandatory)]
    [string]$KeyName
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required.'
}

$keyJson = & az rest `
    --method get `
    --url "https://$VaultName.vault.azure.net/keys/$($KeyName)?api-version=7.4" `
    --resource 'https://vault.azure.net'
if ($LASTEXITCODE -ne 0) {
    throw 'The key could not be reached. Run this from a non-confidential machine with DNS and network access to the Key Vault private endpoint.'
}
$key = $keyJson | ConvertFrom-Json
$keyVersion = $key.key.kid.TrimEnd('/').Split('/')[-1]

# This is a valid signed JWT for this caller, but it is not an MAA environment assertion.
$nonAttestationToken = (& az account get-access-token `
    --resource 'https://vault.azure.net' `
    --query accessToken `
    --output tsv).Trim()
$body = @{ target = $nonAttestationToken } | ConvertTo-Json -Compress

Write-Host "Calling release as a non-confidential caller against key version $keyVersion..."
$failure = & az rest `
    --method post `
    --url "https://$VaultName.vault.azure.net/keys/$KeyName/$keyVersion/release?api-version=7.4" `
    --resource 'https://vault.azure.net' `
    --headers 'Content-Type=application/json' `
    --body $body 2>&1

if ($LASTEXITCODE -eq 0) {
    throw 'Unexpected result: Key Vault released the key to a non-attested caller.'
}

Write-Host 'Expected failure: authentication and RBAC succeeded, but the supplied token did not satisfy the SKR policy.' -ForegroundColor Green
$failure | Write-Host
