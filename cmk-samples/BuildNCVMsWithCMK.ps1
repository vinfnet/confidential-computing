# Script to build Confidential VMs with CMK disk encryption on a shared private subnet
# April 2026
# Tested on Windows (PWSH 7.4.6)
#
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
#
# Creates CVMs on the cheapest confidential SKU (Standard_DC2as_v5), with confidential OS disk
# encryption using customer managed keys. 10% of VMs use an expired CMK key. No public IPs, all on
# same private subnet, boot diagnostics disabled. Auto-shutdown at 19:00 daily.
#
# After all VMs are built, runs DetectCMKStatus to report key expiry status.
#
# Usage: ./Build10CVMsWithCMK.ps1 -subsID <YOUR SUBSCRIPTION ID> [-vmCount <NUMBER>] [-region <AZURE REGION>]
#
# You'll need to have the latest Azure PowerShell module installed (update-module -force)

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory = $false)][int]$vmCount = 10,
    [Parameter(Mandatory = $false)][string]$region = "northeurope"
)

if ($subsID -eq "") {
    Write-Host "You must enter a subscription ID"
    exit
}

$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name

# Configuration
$prefix = "sgall"
$basename = $prefix + -join ((48..57) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ }) # prefix + 5 random alphanumeric chars
$resgrp = $basename
$vmSize = "Standard_DC2as_v5" # cheapest confidential computing SKU
$akvname = $basename + "akv"
$vnetname = $basename + "vnet"
$vmsubnetname = $basename + "vmsubnet"
$vmusername = "azureuser"
$KeySize = 3072

# CVM security settings
$identityType = "SystemAssigned"
$secureEncryptGuestState = "DiskWithVMGuestState"
$vmSecurityType = "ConfidentialVM"
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey"

# Auto-shutdown settings
$shutdownTime = "1900" # 19:00
$shutdownTimezone = "GMT Standard Time"

Write-Host "================================================================================================================" -ForegroundColor Cyan
Write-Host "Building $vmCount Confidential VMs with CMK Disk Encryption" -ForegroundColor Cyan
Write-Host "Resource Group: $resgrp | Region: $region | SKU: $vmSize" -ForegroundColor Cyan
Write-Host "10% of VMs will use an expired CMK key" -ForegroundColor Yellow
Write-Host "Auto-shutdown configured for $shutdownTime ($shutdownTimezone) daily" -ForegroundColor Cyan
Write-Host "================================================================================================================" -ForegroundColor Cyan

Set-AzContext -SubscriptionId $subsID
if (!$?) {
    Write-Host "Failed to connect to the Azure subscription $subsID - exiting"
    exit
}

# Register Microsoft.DevTestLab provider (required for auto-shutdown schedules)
$dtlProvider = Get-AzResourceProvider -ProviderNamespace Microsoft.DevTestLab
if ($dtlProvider.RegistrationState -ne "Registered") {
    Write-Host "Registering Microsoft.DevTestLab resource provider..." -ForegroundColor Gray
    try {
        Register-AzResourceProvider -ProviderNamespace Microsoft.DevTestLab | Out-Null
    }
    catch {
        Write-Host "ERROR: Failed to register Microsoft.DevTestLab provider: $_" -ForegroundColor Red
        Write-Host "Register manually: Register-AzResourceProvider -ProviderNamespace Microsoft.DevTestLab" -ForegroundColor Yellow
        exit 1
    }
    # Wait for registration (timeout after 120 seconds)
    $regTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ((Get-AzResourceProvider -ProviderNamespace Microsoft.DevTestLab).RegistrationState -ne "Registered") {
        if ($regTimer.Elapsed.TotalSeconds -gt 120) {
            Write-Host "ERROR: Timed out waiting for Microsoft.DevTestLab registration." -ForegroundColor Red
            Write-Host "Check status: (Get-AzResourceProvider -ProviderNamespace Microsoft.DevTestLab).RegistrationState" -ForegroundColor Yellow
            exit 1
        }
        Start-Sleep -Seconds 5
    }
    $regTimer.Stop()
    Write-Host "  Microsoft.DevTestLab registered" -ForegroundColor Green
}

# Get username for tagging
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

# Get GitHub repository URL for tagging
$gitRemoteUrl = ""
try { $gitRemoteUrl = git remote get-url origin; $gitRemoteUrl = $gitRemoteUrl -replace "\.git$", "" } catch {}
if (-not $gitRemoteUrl) { $gitRemoteUrl = "https://github.com/Azure-Samples/confidential-computing" }

# ---- Create Resource Group ----
Write-Host "`n[1/6] Creating resource group: $resgrp" -ForegroundColor Cyan
New-AzResourceGroup -Name $resgrp -Location $region -Tag @{
    owner   = $ownername
    BuiltBy = $scriptName
    GitRepo = $gitRemoteUrl
    VMCount = "$vmCount"
} -Force

# ---- Create Key Vault ----
Write-Host "[2/6] Creating Key Vault: $akvname" -ForegroundColor Cyan
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium `
    -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection

# Grant CVM Orchestrator service principal access to keys
$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.Id -PermissionsToKeys get,release

Write-Host "Waiting for Key Vault propagation..." -ForegroundColor Gray
Start-Sleep -Seconds 30

# ---- Create CMK Keys (one per VM, 10% expired) ----
Write-Host "[3/6] Creating $vmCount CMK keys (10% with expired expiry dates)..." -ForegroundColor Cyan

$now = Get-Date
$expiredCount = [math]::Ceiling($vmCount * 0.10) # at least 1 out of 10
$expiredIndices = 1..$vmCount | Get-Random -Count $expiredCount

$keyNames = @()
$keyExpiries = @()

for ($i = 1; $i -le $vmCount; $i++) {
    $keyName = "$basename-cmk-key-$('{0:D2}' -f $i)"
    $keyNames += $keyName

    if ($expiredIndices -contains $i) {
        # Expired: 1 to 30 days in the past
        $randomDays = Get-Random -Minimum -30 -Maximum -1
        $statusLabel = "EXPIRED"
        $statusColor = "Red"
    }
    else {
        # Valid: 91 days to 3 years from now (avoid EXPIRING SOON for clarity)
        $randomDays = Get-Random -Minimum 91 -Maximum 1095
        $statusLabel = "OK"
        $statusColor = "Green"
    }
    $expiryDate = $now.AddDays($randomDays)
    $keyExpiries += $expiryDate

    Add-AzKeyVaultKey -VaultName $akvname -Name $keyName -Size $KeySize `
        -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy `
        -Expires $expiryDate | Out-Null

    Write-Host "  Key $i/$vmCount : $keyName | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | " -NoNewline
    Write-Host $statusLabel -ForegroundColor $statusColor
}

# ---- Create shared VNet and Subnet ----
Write-Host "[4/6] Creating shared VNet and subnet" -ForegroundColor Cyan
$subnet = New-AzVirtualNetworkSubnetConfig -Name $vmsubnetname -AddressPrefix "10.0.0.0/24"
$vnet = New-AzVirtualNetwork -Force -Name $vnetname -ResourceGroupName $resgrp -Location $region `
    -AddressPrefix "10.0.0.0/16" -Subnet $subnet
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$subnetId = $vnet.Subnets[0].Id

# ---- Build 10 CVMs ----
Write-Host "[5/6] Building $vmCount Confidential VMs..." -ForegroundColor Cyan
$script:hasErrors = $false

# Generate one shared admin password for all VMs
$vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40)
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword)

Write-Host "  VM admin username: $vmusername" -ForegroundColor White
Write-Host "  VM admin password: $vmadminpassword" -ForegroundColor White
Write-Host "  SAVE THIS PASSWORD NOW - you cannot retrieve it later" -ForegroundColor Yellow
Write-Host ""

for ($i = 1; $i -le $vmCount; $i++) {
    $vmname = "$basename-cvm-$('{0:D2}' -f $i)"
    $nicname = "$vmname-nic"
    $keyName = $keyNames[$i - 1]
    $desname = "$basename-des-$('{0:D2}' -f $i)"

    $isExpired = $expiredIndices -contains $i
    if ($isExpired) {
        Write-Host "  [$i/$vmCount] Building $vmname (CMK: $keyName - EXPIRED KEY)" -ForegroundColor Red
    } else {
        Write-Host "  [$i/$vmCount] Building $vmname (CMK: $keyName)" -ForegroundColor Green
    }

    # Get key details for DES
    $encryptionKeyVaultId = (Get-AzKeyVault -VaultName $akvname -ResourceGroupName $resgrp).ResourceId
    $encryptionKeyURL = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyName).Key.Kid

    # Create Disk Encryption Set for this VM
    $desConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $encryptionKeyVaultId `
        -KeyUrl $encryptionKeyURL -IdentityType SystemAssigned -EncryptionType $diskEncryptionType
    New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname -DiskEncryptionSet $desConfig

    $diskencset = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname
    $desIdentity = $diskencset.Identity.PrincipalId
    Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $desIdentity `
        -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation

    # Create NIC (no public IP)
    $nic = New-AzNetworkInterface -Force -Name $nicname -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId
    $nic = Get-AzNetworkInterface -Name $nicname -ResourceGroupName $resgrp

    # Configure VM
    $VirtualMachine = New-AzVMConfig -VMName $vmname -VMSize $vmSize
    $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred
    $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest"
    $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nic.Id

    # Confidential OS disk encryption with CMK
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" `
        -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id -Linux
    $VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType
    $VirtualMachine = Set-AzVmUefi -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true

    # Disable boot diagnostics
    $VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Disable

    # Create the VM
    try {
        New-AzVM -ResourceGroupName $resgrp -Location $region -VM $VirtualMachine
        Write-Host "    VM $vmname created successfully" -ForegroundColor Green
    }
    catch {
        Write-Warning "    Failed to create VM '$vmname': $_"
        $script:hasErrors = $true
        continue
    }

    # Configure auto-shutdown at 19:00 daily
    $vmResourceId = (Get-AzVM -ResourceGroupName $resgrp -Name $vmname).Id
    $shutdownResourceId = "/subscriptions/$subsID/resourceGroups/$resgrp/providers/microsoft.devtestlab/schedules/shutdown-computevm-$vmname"

    $properties = @{
        status = "Enabled"
        taskType = "ComputeVmShutdownTask"
        dailyRecurrence = @{ time = $shutdownTime }
        timeZoneId = $shutdownTimezone
        targetResourceId = $vmResourceId
    }

    try {
        New-AzResource -ResourceId $shutdownResourceId -Location $region -Properties $properties -Force | Out-Null
        Write-Host "    Auto-shutdown at $shutdownTime configured for $vmname" -ForegroundColor Gray
    }
    catch {
        Write-Warning "    Failed to configure auto-shutdown for '$vmname': $_"
        $script:hasErrors = $true
    }
}

# ---- Run DetectCMKStatus ----
Write-Host "`n[6/6] Running CMK status detection on resource group '$resgrp'..." -ForegroundColor Cyan
Write-Host ""

# Dot-source and run DetectCMKStatus from the same directory
$detectScript = Join-Path $PSScriptRoot "DetectCMKStatus.ps1"
if (Test-Path $detectScript) {
    & $detectScript -ResourceGroupName $resgrp
} else {
    Write-Warning "DetectCMKStatus.ps1 not found at '$detectScript'. Run it manually:"
    Write-Host "  .\DetectCMKStatus.ps1 -ResourceGroupName '$resgrp'" -ForegroundColor White
}

# Summary
Write-Host ""
Write-Host "================================================================================================================" -ForegroundColor Cyan
if ($script:hasErrors) {
    Write-Host "DEPLOYMENT COMPLETED WITH ERRORS" -ForegroundColor Yellow
} else {
    Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Green
}
Write-Host "  Resource Group : $resgrp" -ForegroundColor White
Write-Host "  Key Vault      : $akvname" -ForegroundColor White
Write-Host "  VMs Created    : $vmCount (on $vmSize)" -ForegroundColor White
Write-Host "  Expired Keys   : $expiredCount out of $vmCount" -ForegroundColor Yellow
Write-Host "  Auto-Shutdown  : $shutdownTime ($shutdownTimezone) daily" -ForegroundColor White
Write-Host "  Admin User     : $vmusername" -ForegroundColor White
Write-Host "  VNet/Subnet    : $vnetname / $vmsubnetname (10.0.0.0/24)" -ForegroundColor White
Write-Host ""
if ($script:hasErrors) {
    Write-Host "ERRORS OCCURRED - to clean up all resources, run:" -ForegroundColor Red
    Write-Host "  Remove-AzResourceGroup -Name $resgrp -Force -AsJob" -ForegroundColor Yellow
    Write-Host "This will delete ALL resources (VMs, Key Vault, VNet, etc.) in the resource group." -ForegroundColor Yellow
} else {
    Write-Host "To clean up: Remove-AzResourceGroup -Name $resgrp -Force" -ForegroundColor Yellow
}
Write-Host "================================================================================================================" -ForegroundColor Cyan

$myTimeSpan = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Execution time was {0} minutes and {1} seconds." -f $myTimeSpan.Minutes, $myTimeSpan.Seconds)
