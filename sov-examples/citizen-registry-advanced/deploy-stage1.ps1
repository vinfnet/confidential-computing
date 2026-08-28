#!/usr/bin/env pwsh
<#
.SYNOPSIS
Deploy Stage 1 Shared Infrastructure
#>

$ErrorActionPreference = "Stop"
$DebugPreference = "Continue"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  STAGE 1: DEPLOYING SHARED INFRASTRUCTURE                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Parameters
$Prefix = "sgall"
$Location = "eastus"
$RgName = "$($Prefix)sharedinfra"

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Prefix: $Prefix"
Write-Host "  Resource Group: $RgName"
Write-Host "  Location: $Location"
Write-Host ""

try {
    # Step 1: Check subscription
    Write-Host "Step 1: Verifying Azure subscription..." -ForegroundColor Cyan
    $sub = az account show --query "{id:id, name:name}" -o json | ConvertFrom-Json
    Write-Host "✓ Subscription: $($sub.name)" -ForegroundColor Green
    Write-Host ""

    # Step 2: Create resource group
    Write-Host "Step 2: Creating resource group: $RgName" -ForegroundColor Cyan
    az group create --name $RgName --location $Location --output none
    Write-Host "✓ Resource group created" -ForegroundColor Green
    Write-Host ""

    # Step 3: Validate Bicep template
    Write-Host "Step 3: Validating Bicep template..." -ForegroundColor Cyan
    $validation = az deployment group validate `
        --resource-group $RgName `
        --template-file "./bicep/shared-infra.bicep" `
        --parameters `
            hsmName="$($Prefix)hsm$(Get-Random -Minimum 100 -Maximum 999)" `
            vnetName="$($Prefix)-shared-vnet" `
            privateLinkSubnetName="privatelink-subnet" `
            location=$Location `
            ownerTag="sgallagher@microsoft.com" `
            costControlTag="confidential-computing" `
        2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Template validation passed" -ForegroundColor Green
    } else {
        Write-Host "✗ Template validation failed: $validation" -ForegroundColor Red
        exit 1
    }
    Write-Host ""

    # Step 4: Deploy Bicep template
    Write-Host "Step 4: Deploying Bicep template (this may take 3-5 minutes)..." -ForegroundColor Cyan
    Write-Host "  Creating Managed HSM, VNet, Private Link, DNS zones..." -ForegroundColor Gray
    
    $deployment = az deployment group create `
        --resource-group $RgName `
        --template-file "./bicep/shared-infra.bicep" `
        --parameters `
            hsmName="$($Prefix)hsm$(Get-Random -Minimum 100 -Maximum 999)" `
            vnetName="$($Prefix)-shared-vnet" `
            privateLinkSubnetName="privatelink-subnet" `
            location=$Location `
            ownerTag="sgallagher@microsoft.com" `
            costControlTag="confidential-computing" `
        --query "properties.outputs" `
        2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Deployment completed" -ForegroundColor Green
        Write-Host ""
        Write-Host "Deployment Outputs:" -ForegroundColor Cyan
        Write-Host $deployment
        
        # Save outputs
        $deployment | Out-File -FilePath "./shared-infra-outputs.json" -Encoding utf8
        Write-Host ""
        Write-Host "✓ Outputs saved to: shared-infra-outputs.json" -ForegroundColor Green
    } else {
        Write-Host "✗ Deployment failed: $deployment" -ForegroundColor Red
        exit 1
    }
    Write-Host ""

    # Step 5: Verify resources
    Write-Host "Step 5: Verifying resources in $RgName..." -ForegroundColor Cyan
    $resources = az resource list --resource-group $RgName --query "[].{Name:name, Type:type, State:provisioningState}" --output json
    Write-Host $resources | ConvertFrom-Json | Format-Table -AutoSize
    Write-Host ""

    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  ✓ STAGE 1 DEPLOYMENT SUCCESSFUL                             ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next: Deploy Stage 2 (App Instance)" -ForegroundColor Cyan
    Write-Host "  Run: .\deploy-stage2.ps1" -ForegroundColor Yellow
    Write-Host ""

} catch {
    Write-Host "✗ ERROR: $_" -ForegroundColor Red
    exit 1
}
