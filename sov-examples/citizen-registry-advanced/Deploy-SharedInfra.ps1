<#
.SYNOPSIS
    Deploy Shared Infrastructure for Citizen Registry Advanced Demo.

.DESCRIPTION
    Stage 1: Creates shared infrastructure resource group containing:
    - Managed HSM (private link only, no public access)
    - Virtual Network with private DNS zones
    - Private Link endpoint for HSM
    - Security domain initialization
    
    This shared infrastructure is used by multiple app instances (Stage 2).

.PARAMETER Prefix
    REQUIRED. Short unique identifier (3-12 chars) for resource naming.
    Used to create resource group: {prefix}sharedinfra

.PARAMETER Location
    Azure region for resources. Defaults to "northeurope".
    Managed HSM availability may vary by region.

.PARAMETER Deploy
    Execute the deployment.

.PARAMETER ValidateOnly
    Validate Bicep templates without deployment.

.PARAMETER Cleanup
    Delete the shared infrastructure resource group and all resources.

.EXAMPLE
    .\Deploy-SharedInfra.ps1 -Prefix "yourprefix" -Location "northeurope" -Deploy

.EXAMPLE
    .\Deploy-SharedInfra.ps1 -Prefix "yourprefix" -ValidateOnly

.EXAMPLE
    .\Deploy-SharedInfra.ps1 -Prefix "yourprefix" -Cleanup

.NOTES
    Author: Autonomous AI-Assisted Development
    Requires: Azure CLI, PowerShell 7+, Bicep
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,

    [string]$Location = "northeurope",

    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string]$HsmName,

    [switch]$Deploy,
    [switch]$ValidateOnly,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# Configuration
$RgName = "$($Prefix)sharedinfra"
if (-not $HsmName) {
    $HsmName = "$($Prefix)hsm$(Get-Random -Minimum 100 -Maximum 999)"
}
$VnetName = "$($Prefix)-shared-vnet"
$PrivateLinkSubnetName = "privatelink-subnet"

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Citizen Registry Advanced — Stage 1: Shared Infrastructure ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prefix:              $Prefix"
Write-Host "Resource Group:      $RgName"
Write-Host "Location:            $Location"
Write-Host "Managed HSM Name:    $HsmName"
Write-Host ""

# Check if cleanup requested
if ($Cleanup) {
    Write-Host "Cleaning up shared infrastructure..." -ForegroundColor Yellow
    
    Write-Host "Checking for resource group: $RgName" -ForegroundColor Yellow
    $rg = az group show --name $RgName --query "id" -o tsv 2>$null
    
    if ($rg) {
        Write-Host "Deleting resource group: $RgName" -ForegroundColor Yellow
        az group delete --name $RgName --yes --no-wait
        Write-Host "Resource group deletion initiated (running in background)" -ForegroundColor Green
    } else {
        Write-Host "Resource group not found: $RgName" -ForegroundColor Yellow
    }
    
    exit 0
}

# Ensure resource group exists
Write-Host "Ensuring resource group exists: $RgName" -ForegroundColor Yellow
az group create --name $RgName --location $Location | Out-Null
Write-Host "✓ Resource group ready" -ForegroundColor Green

# Get current user info for tagging
$userId = az ad signed-in-user show --query "id" -o tsv
$userUpn = az ad signed-in-user show --query "userPrincipalName" -o tsv

Write-Host "Current user: $userUpn" -ForegroundColor Yellow

# Prepare Bicep parameters using Azure CLI's native name=value format.
$bicepParams = @(
    "hsmName=$HsmName"
    "vnetName=$VnetName"
    "privateLinkSubnetName=$PrivateLinkSubnetName"
    "location=$Location"
    "ownerTag=$userUpn"
    "costControlTag=confidential-computing"
    "initialAdminObjectId=$userId"
)

Write-Host "Deploying Bicep template: shared-infra.bicep" -ForegroundColor Yellow

if ($ValidateOnly) {
    Write-Host "Running template validation only..." -ForegroundColor Cyan
    
    $validation = az deployment group validate `
        --resource-group $RgName `
        --template-file "./bicep/shared-infra.bicep" `
        --parameters $bicepParams `
        --query "properties.validationResult" `
        2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Template validation passed" -ForegroundColor Green
        Write-Host $validation
    } else {
        Write-Host "✗ Template validation failed" -ForegroundColor Red
        Write-Host $validation
        exit 1
    }
    
    exit 0
}

if ($Deploy) {
    Write-Host "Starting deployment..." -ForegroundColor Cyan
    
    # Deploy using Bicep
    try {
        $deployment = az deployment group create `
            --resource-group $RgName `
            --template-file "./bicep/shared-infra.bicep" `
            --parameters $bicepParams `
            --only-show-errors `
            --query "properties.outputs" `
            2>&1
        
        Write-Host "✓ Deployment completed successfully" -ForegroundColor Green
        Write-Host ""
        Write-Host "Deployment Outputs:" -ForegroundColor Cyan
        Write-Host $deployment | ConvertFrom-Json | ConvertTo-Json -Depth 10
        
        # Save outputs to file
        $outputFile = "./shared-infra-outputs.json"
        $deployment | Out-File -FilePath $outputFile
        Write-Host ""
        Write-Host "Outputs saved to: $outputFile" -ForegroundColor Green

        $deploymentOutputs = $deployment | ConvertFrom-Json
        $deployedHsmName = $deploymentOutputs.hsmName.value
        & "$PSScriptRoot\scripts\initialize-hsm.ps1" `
            -HsmName $deployedHsmName `
            -ResourceGroupName $RgName `
            -QuorumThreshold 2 `
            -AdminPrincipal $userId
        if ($LASTEXITCODE -ne 0) { throw "Managed HSM activation failed" }
        
        # Export for Stage 2
        Write-Host ""
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Run Stage 2 app instance deployment:"
        Write-Host "   .\Deploy-AppInstance.ps1 -Prefix `"$Prefix`" -SharedInfraRg `"$RgName`" -Deploy"
        Write-Host ""
        
    } catch {
        Write-Host "✗ Deployment failed: $_" -ForegroundColor Red
        exit 1
    }
    
    exit 0
}

# If no action specified
Write-Host "No action specified. Use one of: -Deploy, -ValidateOnly, or -Cleanup" -ForegroundColor Yellow
Write-Host "Example: .\Deploy-SharedInfra.ps1 -Prefix `"yourprefix`" -Deploy" -ForegroundColor Cyan
