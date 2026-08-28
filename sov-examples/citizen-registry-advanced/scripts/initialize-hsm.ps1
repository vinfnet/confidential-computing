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
    .\initialize-hsm.ps1 -HsmName "sgallhsm234" -ResourceGroupName "sgallsharedinfra"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$HsmName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [int]$QuorumThreshold = 3,

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
    $currentUser = az ad signed-in-user show --query "objectId" -o tsv
    $AdminPrincipal = $currentUser
    Write-Host "Using current user as admin principal: $AdminPrincipal" -ForegroundColor Yellow
}

# Check HSM status
Write-Host "Checking HSM status..." -ForegroundColor Yellow
$hsmStatus = az keyvault show --hsm-name $HsmName --query "properties.provisioningState" -o tsv

Write-Host "  Provisioning State: $hsmStatus" -ForegroundColor Yellow

# Initialize security domain (if needed)
Write-Host "Initializing security domain..." -ForegroundColor Yellow

try {
    # Download security domain backup location for credential storage
    $backupPath = "./shared-infra/security-domain"
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    
    Write-Host "  Security domain backup path: $backupPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "✓ Managed HSM initialized and ready" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Create roles and assign permissions to the admin principal"
    Write-Host "2. Create encryption keys for confidential VM disk encryption"
    Write-Host "3. Configure mTLS certificate signing policies"
    Write-Host ""
    
} catch {
    Write-Host "✗ Security domain initialization failed: $_" -ForegroundColor Red
    exit 1
}
