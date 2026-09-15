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
    $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        $resourceGroupExists = az group exists --name $RgName --output tsv --only-show-errors
        if ($LASTEXITCODE -ne 0) { throw "Unable to check resource group '$RgName'." }

        $existingHsmNames = @()
        if ($resourceGroupExists -eq 'true') {
            $existingHsmNames = @(az resource list `
                --resource-group $RgName `
                --resource-type Microsoft.KeyVault/managedHSMs `
                --query '[].name' `
                --output tsv `
                --only-show-errors)
            if ($LASTEXITCODE -ne 0) { throw "Unable to inspect Managed HSM resources in '$RgName'." }
        }
        if ($existingHsmNames.Count -gt 1) {
            throw "Resource group '$RgName' contains multiple Managed HSMs. Specify -HsmName explicitly."
        }
        if ($existingHsmNames.Count -eq 1) {
            $HsmName = $existingHsmNames[0]
        } else {
            $unavailableHsmNames = @(
                az resource list `
                    --resource-type Microsoft.KeyVault/managedHSMs `
                    --query '[].name' `
                    --output tsv `
                    --only-show-errors
                az keyvault list-deleted `
                    --resource-type hsm `
                    --query '[].name' `
                    --output tsv `
                    --only-show-errors
            )
            for ($attempt = 1; $attempt -le 100; $attempt++) {
                $candidate = "$($Prefix)hsm$(Get-Random -Minimum 100 -Maximum 999)"
                if ($candidate -notin $unavailableHsmNames) {
                    $HsmName = $candidate
                    break
                }
            }
            if (-not $HsmName) {
                throw "Unable to select an available Managed HSM name after 100 attempts. Specify -HsmName explicitly."
            }
        }
    } finally {
        $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
    }
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
        # Managed HSM provisioning intermittently returns a transient ARM error
        # ('The response for resource had empty or invalid content.') even when the
        # HSM actually provisions successfully. Retry and reconcile against the real
        # HSM state so a transient blip does not fail the whole pipeline.
        $maxAttempts = 3
        $deployment = $null
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            $prevNative = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
            $deployment = az deployment group create `
                --resource-group $RgName `
                --template-file "./bicep/shared-infra.bicep" `
                --parameters $bicepParams `
                --only-show-errors `
                --query "properties.outputs" `
                2>&1
            $deployExit = $LASTEXITCODE
            $hsmState = az keyvault show --hsm-name $HsmName --query "properties.provisioningState" -o tsv 2>$null
            $PSNativeCommandUseErrorActionPreference = $prevNative

            if ($deployExit -eq 0) { break }

            if ($hsmState -eq 'Succeeded') {
                Write-Host "⚠ Deployment reported a transient error, but Managed HSM '$HsmName' is provisioned. Continuing." -ForegroundColor Yellow
                $deployment = az deployment group show `
                    --resource-group $RgName `
                    --name shared-infra `
                    --query "properties.outputs" `
                    --only-show-errors 2>$null
                break
            }

            if ($attempt -eq $maxAttempts) {
                throw "Shared infrastructure deployment failed after $maxAttempts attempts: $deployment"
            }
            Write-Host "Deployment attempt $attempt failed transiently; retrying in 30 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
        }

        Write-Host "✓ Deployment completed successfully" -ForegroundColor Green
        Write-Host ""
        Write-Host "Deployment Outputs:" -ForegroundColor Cyan
        try { Write-Host ($deployment | ConvertFrom-Json | ConvertTo-Json -Depth 10) } catch { }
        
        # Save outputs to file
        $outputFile = "./shared-infra-outputs.json"
        $deployment | Out-File -FilePath $outputFile
        Write-Host ""
        Write-Host "Outputs saved to: $outputFile" -ForegroundColor Green

        # Resolve the deployed HSM name from outputs, falling back to the requested
        # name when a transient failure left the deployment record without outputs.
        $deployedHsmName = $HsmName
        try {
            $deploymentOutputs = $deployment | ConvertFrom-Json -ErrorAction Stop
            if ($deploymentOutputs.hsmName.value) { $deployedHsmName = $deploymentOutputs.hsmName.value }
        } catch { }
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
        throw
    }
    
    exit 0
}

# If no action specified
Write-Host "No action specified. Use one of: -Deploy, -ValidateOnly, or -Cleanup" -ForegroundColor Yellow
Write-Host "Example: .\Deploy-SharedInfra.ps1 -Prefix `"yourprefix`" -Deploy" -ForegroundColor Cyan
