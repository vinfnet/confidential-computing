# Script to create an Azure Key Vault and populate it with 50 encryption keys with random expiry dates
# April 2025
# Tested on Windows (PWSH 7.4.6)
#
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
#
# Usage: ./BuildRandomCMK.ps1 -subsID <YOUR SUBSCRIPTION ID> -Prefix <YOUR PREFIX>
#
# Prefix is used to create a resource group named <prefix><5 random chars> and all resources within it
#
# You'll need to have the latest Azure PowerShell module installed (update-module -force)

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$Prefix
)

if ($subsID -eq "" -or $Prefix -eq "") {
    Write-Host "You must enter a subscription ID and a prefix"
    exit
}

# Generate unique basename: prefix + 5 random lowercase letters
$basename = $Prefix + -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$resgrp = $basename
$akvname = $basename + "akv"
$region = "northeurope"
$keyCount = 50

Set-AzContext -SubscriptionId $subsID
if (!$?) {
    Write-Host "Failed to connect to the Azure subscription $subsID - exiting"
    exit
}

# Get username for tagging
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

Write-Host "Creating resource group: $resgrp in $region" -ForegroundColor Cyan

New-AzResourceGroup -Name $resgrp -Location $region -Tag @{
    owner   = $ownername
    BuiltBy = "BuildRandomCMK.ps1"
} -Force

Write-Host "Creating Key Vault: $akvname" -ForegroundColor Cyan

New-AzKeyVault -Name $akvname `
    -Location $region `
    -ResourceGroupName $resgrp `
    -Sku Premium `
    -EnabledForDiskEncryption `
    -SoftDeleteRetentionInDays 7 `
    -DisableRbacAuthorization

# Wait for Key Vault propagation
Write-Host "Waiting for Key Vault propagation..." -ForegroundColor Gray
Start-Sleep -Seconds 30

Write-Host "Creating $keyCount encryption keys with random expiry dates..." -ForegroundColor Cyan

$now = Get-Date

# Guarantee at least 10% of keys are expired (expiry in the past)
$expiredCount = [math]::Ceiling($keyCount * 0.10)
$expiredIndices = 1..$keyCount | Get-Random -Count $expiredCount

for ($i = 1; $i -le $keyCount; $i++) {
    $keyName = "$basename-key-$('{0:D3}' -f $i)"

    if ($expiredIndices -contains $i) {
        # Force expired: 1 to 30 days in the past
        $randomDays = Get-Random -Minimum -30 -Maximum 0
    }
    else {
        # Random expiry: today to 3 years (1095 days) from now
        $randomDays = Get-Random -Minimum 0 -Maximum 1095
    }
    $expiryDate = $now.AddDays($randomDays)

    $keyParams = @{
        VaultName   = $akvname
        Name        = $keyName
        KeyType     = "RSA"
        Size        = 3072
        KeyOps      = @("wrapKey", "unwrapKey")
        Expires     = $expiryDate
        Destination = "Software"
    }

    try {
        Add-AzKeyVaultKey @keyParams | Out-Null

        # Color the output based on expiry status
        $daysUntilExpiry = ($expiryDate - $now).Days
        if ($daysUntilExpiry -lt 0) {
            $statusColor = "Red"
            $statusText = "EXPIRED"
        }
        elseif ($daysUntilExpiry -le 90) {
            $statusColor = "DarkYellow"
            $statusText = "EXPIRING SOON"
        }
        else {
            $statusColor = "Green"
            $statusText = "OK"
        }

        Write-Host "  [$i/$keyCount] $keyName | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | " -NoNewline
        Write-Host $statusText -ForegroundColor $statusColor
    }
    catch {
        Write-Warning "  Failed to create key '$keyName': $_"
    }
}

Write-Host ""
Write-Host "Done! Created $keyCount keys in Key Vault '$akvname' (Resource Group: $resgrp)" -ForegroundColor Green
Write-Host ""
Write-Host "To analyze these keys, run:" -ForegroundColor Cyan
Write-Host "  . .\DetectCMKStatus.ps1" -ForegroundColor White
Write-Host "  Get-CMKStatus -ResourceGroupName '$resgrp'" -ForegroundColor White
