<#
.SYNOPSIS
    Initialize Managed HSM security domain for citizen registry.

.DESCRIPTION
    Creates and initializes the security domain for Managed HSM,
    configured for mTLS certificate management and key escrow.

.PARAMETER HsmName
    Name of the Managed HSM.

.PARAMETER ResourceGroupName
    Name of the resource group containing the HSM.

.PARAMETER QuorumThreshold
    Security domain quorum threshold (default: 3).

.PARAMETER AdminPrincipal
    Object ID of the admin principal to authorize (default: current user).

.EXAMPLE
    .\initialize-hsm.ps1 -HsmName "yourprefixhsm234" -ResourceGroupName "yourprefixsharedinfra"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$HsmName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [ValidateRange(2, 3)]
    [int]$QuorumThreshold = 2,

    [string]$AdminPrincipal = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Initializing Managed HSM Security Domain                  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get HSM details
Write-Host "Retrieving Managed HSM: $HsmName" -ForegroundColor Yellow
$hsm = az keyvault show --hsm-name $HsmName --query "{id: id, name: name, location: location}" -o json | ConvertFrom-Json

if (-not $hsm) {
    Write-Host "✗ Managed HSM not found: $HsmName" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Managed HSM found:" -ForegroundColor Green
Write-Host "  ID: $($hsm.id)"
Write-Host "  Name: $($hsm.name)"
Write-Host ""

# Get current user if AdminPrincipal not specified
if (-not $AdminPrincipal) {
    $currentUser = az ad signed-in-user show --query "id" -o tsv
    $AdminPrincipal = $currentUser
    Write-Host "Using current user as admin principal: $AdminPrincipal" -ForegroundColor Yellow
}

# Check HSM status
Write-Host "Checking HSM status..." -ForegroundColor Yellow
$hsmStatus = az keyvault show --hsm-name $HsmName --query "properties.provisioningState" -o tsv

Write-Host "  Provisioning State: $hsmStatus" -ForegroundColor Yellow

# A successful local role assignment and key list prove the HSM is active.
$isActive = $false
try {
    az keyvault role assignment create `
        --hsm-name $HsmName `
        --role 'Managed HSM Crypto Officer' `
        --assignee-object-id $AdminPrincipal `
        --scope /keys `
        --output none
    az keyvault role assignment create `
        --hsm-name $HsmName `
        --role 'Managed HSM Crypto User' `
        --assignee-object-id $AdminPrincipal `
        --scope /keys `
        --output none
    az keyvault key list --hsm-name $HsmName --maxresults 1 -o none 2>$null
    $isActive = $LASTEXITCODE -eq 0
} catch { $isActive = $false }

if ($isActive) {
    Write-Host "✓ Managed HSM is already active" -ForegroundColor Green
    exit 0
}

Write-Host "Initializing security domain..." -ForegroundColor Yellow
$backupPath = Join-Path $PSScriptRoot "..\shared-infra\security-domain"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
$securityDomainFile = Join-Path $backupPath "$HsmName-security-domain.json"
$publicKeys = @()

try {
    for ($share = 1; $share -le 3; $share++) {
        $privateKey = Join-Path $backupPath "recovery-$share-private.pem"
        $wrappingCertificate = Join-Path $backupPath "recovery-$share-certificate.pem"
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $privateKeyLoaded = $false
            if (Test-Path $privateKey) {
                try {
                    $rsa.ImportFromPem((Get-Content $privateKey -Raw))
                    $privateKeyLoaded = $true
                } catch {
                    Remove-Item $privateKey -Force
                }
            }
            if (-not $privateKeyLoaded) {
                $rsa.KeySize = 3072
                $privatePem = [System.Security.Cryptography.PemEncoding]::Write(
                    'PRIVATE KEY',
                    $rsa.ExportPkcs8PrivateKey()
                ) -join ''
                [System.IO.File]::WriteAllText($privateKey, $privatePem)
            }
            $certificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                "CN=$HsmName Recovery Share $share",
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $certificate = $certificateRequest.CreateSelfSigned(
                [System.DateTimeOffset]::UtcNow.AddMinutes(-5),
                [System.DateTimeOffset]::UtcNow.AddYears(10)
            )
            try {
                $certificatePem = [System.Security.Cryptography.PemEncoding]::Write(
                    'CERTIFICATE',
                    $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                ) -join ''
                [System.IO.File]::WriteAllText($wrappingCertificate, $certificatePem)
            } finally {
                $certificate.Dispose()
            }
        } finally {
            $rsa.Dispose()
        }
        $publicKeys += $wrappingCertificate
    }

    az keyvault security-domain download `
        --hsm-name $HsmName `
        --security-domain-file $securityDomainFile `
        --sd-quorum $QuorumThreshold `
        --sd-wrapping-keys $publicKeys `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Security-domain download failed" }

    az keyvault role assignment create `
        --hsm-name $HsmName `
        --role 'Managed HSM Crypto Officer' `
        --assignee-object-id $AdminPrincipal `
        --scope /keys `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Crypto Officer role assignment failed" }
    az keyvault role assignment create `
        --hsm-name $HsmName `
        --role 'Managed HSM Crypto User' `
        --assignee-object-id $AdminPrincipal `
        --scope /keys `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Crypto User role assignment failed" }

    Write-Host "✓ Managed HSM activated" -ForegroundColor Green
    Write-Host "  Security-domain backup: $securityDomainFile" -ForegroundColor Yellow
    Write-Host "  Recovery quorum: $QuorumThreshold of 3" -ForegroundColor Yellow
    Write-Warning "Protect the security-domain file and private recovery keys; they are required for disaster recovery."
} catch {
    Write-Host "✗ Security domain initialization failed: $_" -ForegroundColor Red
    exit 1
}
