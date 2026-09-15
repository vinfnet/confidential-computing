#!/usr/bin/env pwsh
<#
.SYNOPSIS
Complete deployment and validation of Citizen Registry Advanced
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [ValidateSet("westeurope")]
    [string]$Location = "westeurope",

    [string]$SqlLocation = "northeurope",

    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string]$HsmName,

    [ValidatePattern('^\d{5}$')]
    [string]$DeploymentSuffix,

    [ValidateSet("FileBackedDemo", "ManagedHsm")]
    [string]$PkiMode = "FileBackedDemo"
)

$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

$SharedInfraRg = "$($Prefix)sharedinfra"

az account set --subscription $SubscriptionId --only-show-errors
if ($LASTEXITCODE -ne 0) {
    throw "Unable to select Azure subscription '$SubscriptionId'."
}

$activeSubscriptionId = az account show --query id --output tsv --only-show-errors
if ($LASTEXITCODE -ne 0 -or $activeSubscriptionId -ne $SubscriptionId) {
    throw "Azure CLI subscription validation failed. Expected '$SubscriptionId', got '$activeSubscriptionId'."
}

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  CITIZEN REGISTRY ADVANCED - DEPLOYMENT & VALIDATION PIPELINE    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: SHARED INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "STAGE 1: DEPLOYING SHARED INFRASTRUCTURE" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

try {
    Write-Host ""
    Write-Host "Executing: .\Deploy-SharedInfra.ps1 -Prefix '$Prefix' -Deploy" -ForegroundColor Yellow
    Write-Host ""
    
    $sharedInfraParameters = @{
        Prefix = $Prefix
        Location = $Location
        Deploy = $true
    }
    if ($HsmName) { $sharedInfraParameters.HsmName = $HsmName }
    & ".\Deploy-SharedInfra.ps1" @sharedInfraParameters
    
    Write-Host ""
    Write-Host "✓ Stage 1 completed successfully" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Stage 1 failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: APP INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "STAGE 2: DEPLOYING APP INSTANCE" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

try {
    Write-Host ""
    Write-Host "Executing: .\Deploy-AppInstance.ps1 -Prefix '$Prefix' -SharedInfraRg '$SharedInfraRg' -Deploy" -ForegroundColor Yellow
    Write-Host ""
    
    $appInstanceParameters = @{
        Prefix = $Prefix
        Location = $Location
        SqlLocation = $SqlLocation
        SharedInfraRg = $SharedInfraRg
        PkiMode = $PkiMode
        Deploy = $true
    }
    if ($DeploymentSuffix) { $appInstanceParameters.DeploymentSuffix = $DeploymentSuffix }
    & ".\Deploy-AppInstance.ps1" @appInstanceParameters
    
    Write-Host ""
    Write-Host "✓ Stage 2 completed successfully" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Stage 2 failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION: CHECK RESOURCES
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "VALIDATION: CHECKING DEPLOYED RESOURCES" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host ""
Write-Host "Shared Infrastructure Resources:" -ForegroundColor Yellow
az resource list --resource-group $SharedInfraRg --output table

Write-Host ""
Write-Host "App Instance Resource Groups:" -ForegroundColor Yellow
az group list --query "[?contains(name, '$($Prefix)') && contains(name, 'app')].{Name:name, Location:location}" --output table

Write-Host ""
Write-Host "✓ Deployment and validation complete" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Access Bastion and verify app attestation:"
Write-Host "   Use the Bastion tunnel command printed by Deploy-AppInstance.ps1"
Write-Host ""
Write-Host "2. Test app connectivity and citizen list"
Write-Host ""
