<#
.SYNOPSIS
    Deploy a simple Azure Confidential VM (AMD SEV-SNP) with no public IP.

.DESCRIPTION
    Creates a minimal Confidential VM on AMD SEV-SNP hardware with:
    - Platform Managed Keys (PMK) — Azure manages disk encryption automatically,
      no Key Vault or customer-managed key required
    - Confidential OS disk encryption (DiskWithVMGuestState)
    - No public IP address (private VNet only)
    - Random username and password (displayed at the end)

    This is intended as a quick way to get a CVM running for testing.
    The VM is accessible only via its private IP within the VNet.

.PARAMETER Prefix
    3-8 character lowercase alphanumeric prefix for resource naming.
    A random 5-character suffix is appended automatically.

.PARAMETER Location
    Azure region (default: northeurope). Must support DCas_v5 series.

.PARAMETER VMSize
    VM SKU (default: Standard_DC2as_v5).

.PARAMETER Cleanup
    Remove all resources created by a previous deployment.

.EXAMPLE
    .\Deploy-SimpleCVM.ps1 -Prefix "mycvm"
    Deploy a Confidential VM with random credentials.

.EXAMPLE
    .\Deploy-SimpleCVM.ps1 -Cleanup
    Remove all deployed resources.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z][a-z0-9]{2,7}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$VMSize = "Standard_DC2as_v5",

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "simplecvm-config.json"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function New-RandomCredential {
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $username = "cvm" + -join ((0..7) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $passChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = -join ((0..39) | ForEach-Object { $passChars[(Get-Random -Maximum $passChars.Length)] })
    return @{ Username = $username; Password = $password }
}


# ============================================================================
# CLEANUP
# ============================================================================
if ($Cleanup) {
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Yellow
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        $rg = $config.resourceGroup
        Write-Host "Removing resource group: $rg ..." -ForegroundColor Yellow
        Remove-AzResourceGroup -Name $rg -Force -AsJob | Out-Null
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue
        Write-Host "Cleanup job submitted. Deletion continues in background." -ForegroundColor Green
        Write-Host "Check status: Get-Job | Where-Object Command -like '*Remove-AzResourceGroup*'" -ForegroundColor Gray
    }
    else {
        Write-Host "No config file found. Nothing to clean up." -ForegroundColor Yellow
    }
    exit
}


# ============================================================================
# VALIDATE
# ============================================================================
if (-not $Prefix) {
    Write-Host "`n=== Simple Confidential VM (AMD SEV-SNP) ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\$scriptName -Prefix <name>    Deploy a Confidential VM"
    Write-Host "  .\$scriptName -Cleanup          Remove all resources"
    Write-Host ""
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        Write-Host "Current deployment:" -ForegroundColor Cyan
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Location:       $($config.location)"
        Write-Host "  VM:             $($config.vmName)"
        Write-Host "  Private IP:     $($config.privateIp)"
        Write-Host "  Username:       $($config.username)"
    }
    exit
}

# Prerequisites
Write-Host "`nChecking prerequisites..." -ForegroundColor Cyan
$azModule = Get-Module -ListAvailable -Name Az.Accounts | Select-Object -First 1
if (-not $azModule) { throw "Azure PowerShell (Az) not installed. Run: Install-Module -Name Az -Force" }
Write-Host "  Az module: $($azModule.Version)" -ForegroundColor Green
$context = Get-AzContext
if (-not $context) { throw "Not logged in to Azure. Run: Connect-AzAccount" }
Write-Host "  Logged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "  Subscription: $($context.Subscription.Name)" -ForegroundColor Green


# ============================================================================
# GENERATE NAMES
# ============================================================================
$suffix = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$basename = $Prefix + $suffix
$resgrp = "$basename-cvm-rg"
$vnetName = "$basename-vnet"
$nsgName = "$basename-nsg"
$vmName = "$basename-cvm"
$cred = New-RandomCredential

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Simple Confidential VM — AMD SEV-SNP (no public IP)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Basename:       $basename"
Write-Host "  Resource Group: $resgrp"
Write-Host "  Location:       $Location"
Write-Host "  VM:             $vmName ($VMSize)"
Write-Host "  Disk Encryption: Platform Managed Keys (PMK)"
Write-Host "  Username:       $($cred.Username)"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""


try {

# ============================================================================
# PHASE 1: RESOURCE GROUP + NETWORKING (no public IP)
# ============================================================================
Write-Host "Phase 1: Creating resource group and networking..." -ForegroundColor White

$tags = @{
    owner   = (Get-AzContext).Account.Id
    BuiltBy = $scriptName
    demo    = "simple-cvm"
}
New-AzResourceGroup -Name $resgrp -Location $Location -Tag $tags -Force | Out-Null
Write-Host "  Resource group: $resgrp" -ForegroundColor Green

# Private VNet — single subnet, no public IP
$subnetConfig = New-AzVirtualNetworkSubnetConfig -Name "VMSubnet" -AddressPrefix "10.0.1.0/24"
$vnet = New-AzVirtualNetwork `
    -Name $vnetName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnetConfig
Write-Host "  VNet: $vnetName (10.0.0.0/16)" -ForegroundColor Green

# NSG — deny all inbound by default (no SSH rule, no public IP)
$nsg = New-AzNetworkSecurityGroup `
    -Name $nsgName `
    -ResourceGroupName $resgrp `
    -Location $Location
Write-Host "  NSG: $nsgName (default deny — no public access)" -ForegroundColor Green

Write-Host "Phase 1 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 2: DEPLOY CONFIDENTIAL VM (PMK, no public IP)
# ============================================================================
Write-Host "Phase 2: Deploying Confidential VM (Platform Managed Keys)..." -ForegroundColor White

$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
$vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "VMSubnet" }

# NIC — private IP only, no public IP
$nicName = "$vmName-nic"
$nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resgrp
$ipConfig = New-AzNetworkInterfaceIpConfig -Name "ipconfig1" -Subnet $vmSubnet -PrivateIpAddress "10.0.1.4"
$nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $resgrp -Location $Location `
    -IpConfiguration $ipConfig -NetworkSecurityGroup $nsg
Write-Host "  NIC: $nicName (private IP 10.0.1.4, no public IP)" -ForegroundColor Green

# VM configuration — password auth (no SSH key needed since no public access)
$securePassword = ConvertTo-SecureString -String $cred.Password -AsPlainText -Force
$vmCred = New-Object System.Management.Automation.PSCredential ($cred.Username, $securePassword)

$vm = New-AzVMConfig -VMName $vmName -VMSize $VMSize
$vm = Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName $vmName -Credential $vmCred
$vm = Set-AzVMSourceImage -VM $vm `
    -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest"
$vm = Add-AzVMNetworkInterface -VM $vm -Id $nic.Id

# Confidential OS disk — Platform Managed Keys (no DES needed)
$vm = Set-AzVMOSDisk -VM $vm `
    -StorageAccountType "StandardSSD_LRS" `
    -CreateOption "FromImage" `
    -SecurityEncryptionType "DiskWithVMGuestState" `
    -Linux

$vm = Set-AzVmSecurityProfile -VM $vm -SecurityType "ConfidentialVM"
$vm = Set-AzVmUefi -VM $vm -EnableVtpm $true -EnableSecureBoot $true
$vm = Set-AzVMBootDiagnostic -VM $vm -Disable

Write-Host "  Creating VM: $vmName (this takes 2-5 minutes)..." -ForegroundColor Cyan
New-AzVM -ResourceGroupName $resgrp -Location $Location -VM $vm | Out-Null
Write-Host "  VM created: $vmName" -ForegroundColor Green

$vmObj = Get-AzVM -ResourceGroupName $resgrp -Name $vmName
Write-Host "  VmId: $($vmObj.VmId)" -ForegroundColor Gray

Write-Host "Phase 2 complete.`n" -ForegroundColor Green


# ============================================================================
# SAVE CONFIG + SUMMARY
# ============================================================================
$elapsed = (Get-Date) - $startTime
$config = @{
    basename      = $basename
    resourceGroup = $resgrp
    location      = $Location
    vmName        = $vmName
    vmSize        = $VMSize
    vmId          = $vmObj.VmId
    privateIp     = "10.0.1.4"
    username      = $cred.Username
    password      = $cred.Password
    timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Force

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " Confidential VM deployed successfully!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group: $resgrp"
Write-Host "  VM Name:        $vmName"
Write-Host "  VM Size:        $VMSize"
Write-Host "  VM ID:          $($vmObj.VmId)"
Write-Host "  Private IP:     10.0.1.4"
Write-Host "  Username:       $($cred.Username)"
Write-Host "  Password:       $($cred.Password)"
Write-Host ""
Write-Host "  No public IP — connect via Azure Bastion, VPN, or serial console." -ForegroundColor Yellow
Write-Host "  Config saved to: $configFile" -ForegroundColor Gray
Write-Host "  Total time: $($elapsed.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host ""
Write-Host "  To clean up: .\$scriptName -Cleanup" -ForegroundColor Cyan
Write-Host ""

}
catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Resources may have been partially created in: $resgrp" -ForegroundColor Yellow
    Write-Host "To clean up: Remove-AzResourceGroup -Name '$resgrp' -Force" -ForegroundColor Yellow
    throw
}
