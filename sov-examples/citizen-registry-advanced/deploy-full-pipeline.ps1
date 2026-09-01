#!/usr/bin/env pwsh
<#
.SYNOPSIS
Complete deployment and validation of Citizen Registry Advanced
#>

$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Configuration
$Prefix = "sgall"
$Location = "northeurope"
$SharedInfraRg = "$($Prefix)sharedinfra"

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
    
    & ".\Deploy-SharedInfra.ps1" -Prefix $Prefix -Location $Location -Deploy
    
    if ($LASTEXITCODE -ne 0) {
        throw "Stage 1 deployment failed with exit code: $LASTEXITCODE"
    }
    
    Write-Host ""
    Write-Host "✓ Stage 1 completed successfully" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Stage 1 failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Start-Sleep -Seconds 5

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
    
    & ".\Deploy-AppInstance.ps1" -Prefix $Prefix -Location $Location -SharedInfraRg $SharedInfraRg -Deploy
    
    if ($LASTEXITCODE -ne 0) {
        throw "Stage 2 deployment failed with exit code: $LASTEXITCODE"
    }
    
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
