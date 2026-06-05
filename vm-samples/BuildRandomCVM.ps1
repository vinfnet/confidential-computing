# Hands-off script to build a windows CVM and then make it do attestation by automating an attestation process /inside/ the VM
# VM will be created in a private vnet with no public IP and can only be accessed over the Internet via the Azure Bastion service
# Feb 2025 - ported to all native PowerShell code and re-implemented Azure Bastion code and added command line parameters rather than editing file
# April 2025 - attestation check now runs inside the VM using the WindowsAttest.ps1 script
# Tested on MacOS (PWSH 7.5) & Windows (7.4.6)
# 
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
# based on https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-azure-cli
# 
# Clone this repo to a folder (relies on the WindowsAttest.ps1 script being in the same folder as this script)
#
# Usage: ./BuildRandomCVM.ps1 -subsID <YOUR SUBSCRIPTION ID> -basename <YOUR BASENAME> -osType <Windows|Windows11|Windows2019|Ubuntu|RHEL> [-description <OPTIONAL DESCRIPTION>] [-smoketest] [-region <AZURE REGION>] [-policyFilePath <PATH TO POLICY FILE>] [-DisableBastion] [-SkipSkuPreflight] [-GPU]
#
# Basename is a prefix for all resources created, it's used to create unique names for the resources
# osType specifies which OS to deploy: Windows (Server 2022), Windows11 (Windows 11 Enterprise), Ubuntu (24.04), or RHEL (9.5)
# description is an optional parameter that will be added as a tag to the resource group
# smoketest is an optional switch that automatically removes all resources after completion (useful for testing)
# region is an optional parameter that specifies the Azure region (defaults to northeurope)
# policyFilePath is an optional parameter that specifies the path to a custom policy file for key vault key creation
# DisableBastion is an optional switch that skips the creation of Azure Bastion (VM will only be accessible via private network)
# GPU is an optional switch that builds a Confidential VM with an NVIDIA H100 GPU (Standard_NCC40ads_H100_v5,
#     SEV-SNP + H100 CC mode). When set this overrides -vmsize, forces -osType to Ubuntu (Linux-only),
#     switches to the Ubuntu 22.04 CVM image which is the documented base for NCC H100 v5, and after the
#     VM boots installs the NVIDIA open-kernel driver and the NVIDIA local GPU verifier (nvtrust) inside
#     the VM. The script then runs both a GPU confidential-mode attestation (verifier.cc_admin) and the
#     normal CPU SEV-SNP attestation (cvm-attestation-tools), and surfaces both outputs to the caller.
#
# You'll need to have the latest Azure PowerShell module installed as older versions don't have the parameters for AKV & ACC (update-module -force)
#

# TODO
# - look at the credential handling, it's not optimal

# handle command line parameters, mandatory, will force you to enter them
param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory)]
    [ValidateSet("Windows", "Windows11", "Windows2019", "Ubuntu", "RHEL")]
    $osType,
    [Parameter(Mandatory=$false)]$description = "",
    [Parameter(Mandatory=$false)][switch]$smoketest,
    [Parameter(Mandatory=$false)]$region = "northeurope",
    [Parameter(Mandatory=$false)]$vmsize = "Standard_DC2as_v5",
    [Parameter(Mandatory=$false)]$policyFilePath = "",
    [Parameter(Mandatory=$false)][switch]$DisableBastion,
    [Parameter(Mandatory=$false)][switch]$SkipSkuPreflight,
    [Parameter(Mandatory=$false)][switch]$GPU
)

# -GPU: Override VM SKU / image / region defaults so we provision a Confidential VM with
# an NVIDIA H100 GPU running in CC (confidential compute) mode. This SKU is Linux-only
# (Ubuntu 22.04 CVM is the documented base image), so we also force osType=Ubuntu and
# warn if the caller asked for something else. Region defaults to eastus2 (which is one
# of the regions where Standard_NCC40ads_H100_v5 is offered without subscription
# restriction; the other is westeurope).
if ($GPU) {
    $h100Sku    = 'Standard_NCC40ads_H100_v5'
    $h100Family = 'StandardNCCads2023Family'
    if ($vmsize -ne 'Standard_DC2as_v5' -and $vmsize -ne $h100Sku) {
        write-host "-GPU was specified: overriding -vmsize '$vmsize' with '$h100Sku' (NVIDIA H100 SEV-SNP CVM)." -ForegroundColor Yellow
    }
    $vmsize = $h100Sku
    if ($osType -ne 'Ubuntu') {
        write-host "-GPU was specified: overriding -osType '$osType' with 'Ubuntu' (NVIDIA H100 CC mode is Linux-only on Azure)." -ForegroundColor Yellow
        $osType = 'Ubuntu'
    }
    # Regions where Standard_NCC40ads_H100_v5 is generally offered. If the user picked
    # something else (or just accepted the default northeurope, which does NOT have H100),
    # switch to eastus2 and tell them why.
    $h100Regions = @('eastus2','westeurope','southcentralus','westus3','swedencentral','centraluseuap')
    if ($h100Regions -notcontains $region) {
        write-host "-GPU was specified: region '$region' does not offer '$h100Sku'. Switching to 'eastus2'. Pass -region with one of: $($h100Regions -join ', ') to override." -ForegroundColor Yellow
        $region = 'eastus2'
    }
}

if ($subsID -eq "" -or $basename -eq "" -or $osType -eq "") {
    write-host "You must enter a subscription ID, basename, and OS type (Windows, Windows11, Ubuntu, or RHEL)"
    exit
}# exit if any of the parameters are empty

# mark the start time of the script execution
$startTime = Get-Date
# get the name of the script so we can tag the resource group with it
$scriptName = $MyInvocation.MyCommand.Name

# Get GitHub repository URL from git remote - we use this to tag the resource group with the repo URL
$gitRemoteUrl = ""  
    $gitRemoteUrl = git remote get-url origin
    # Remove .git suffix if present
    $gitRemoteUrl = $gitRemoteUrl -replace "\.git$", ""
  
# If git remote didn't work, use fallback
if (-not $gitRemoteUrl) {
    $gitRemoteUrl = "[Originally from] https://github.com/Microsoft/confidential-computing"
}


# Set PowerShell variables to use in the script
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
$vmusername = "azureuser" # you can adjust this if you want
# Alphanumeric-only so the printed password is a single "word" the user can double-click to select and copy.
# 40 random chars from [A-Za-z0-9] easily satisfies Azure's 3-of-4 complexity rule (upper+lower+digit) without any
# punctuation chars (!@#$%) that act as word-break boundaries in most terminals.
$vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray() | Get-Random -Count 40)
$resgrp =  $basename # name of the resource group where all resources will be created, copied from $basename
$akvname = $basename + "akv"    #Name of the Azure Key Vault
$desname = $basename + "des"    #Name of the Disk Encryption Set
$keyname = $basename + "-cmk-key" #Name of the key in the Key Vault
$vmname = $basename # name of the VM, copied from $basename, or customise it here
$vnetname = $vmname + "vnet" # name of the VNET
$bastionname = $vnetname + "-bastion" # name of the bastion host
$vnetipname = $vnetname + "-pip"     #Name of the VNET IP
$nicPrefix = $basename + "-nic"    #Name of the NIC
$bastionsubnetName = "AzureBastionSubnet" # don't change this
$vmsubnetname = $basename + "vmsubnet" # don't change this
# region is now a command line parameter with default value of northeurope
$vmSize = $vmsize # Use the value from the command line parameter
$identityType = "SystemAssigned";
$secureEncryptGuestState = "DiskWithVMGuestState";
$vmSecurityType = "ConfidentialVM";
$KeySize = 3072
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey";

# Display region information
if ($region -eq "northeurope") {
    write-host "Using default region: $region (North Europe)" -ForegroundColor Cyan
    write-host "To use a different region, specify -region parameter. Ensure the region supports Confidential VMs." -ForegroundColor Cyan
} else {
    write-host "Using specified region: $region" -ForegroundColor Cyan
    write-host "Please ensure this region supports Confidential VMs and the selected VM SKU." -ForegroundColor Cyan
}

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Building a Confidential Virtual Machine ($osType) in " $basename " in " $region
if ($GPU) {
    write-host "GPU MODE: Provisioning '$vmsize' (NVIDIA H100 SEV-SNP CVM). NVIDIA driver + nvtrust local GPU verifier will be installed inside the VM and a GPU CC-mode attestation will be performed in addition to the CPU SEV-SNP attestation." -ForegroundColor Magenta
}
if ($smoketest) {
    write-host "SMOKETEST MODE: Resources will be automatically deleted after completion" -ForegroundColor Yellow
}
if ($DisableBastion) {
    write-host "BASTION DISABLED: VM will only be accessible via private network connectivity" -ForegroundColor Yellow
}
write-host "IMPORTANT - save these credentials now, they CANNOT be retrieved later:" -ForegroundColor Yellow
write-host ("  username: {0}" -f $vmusername)
write-host ("  password: {0}" -f $vmadminpassword)
write-host ""
write-host "(the password is alphanumeric only so you can double-click it to select, then Ctrl+C to copy)" -ForegroundColor DarkGray
write-host ""
write-host "Script: $scriptName"
write-host "Repository URL: $gitRemoteUrl"
write-host "----------------------------------------------------------------------------------------------------------------"

#Interactive login for PowerShell - uncomment if you want the script to prompt you
#If you are not logged in, or dont have the correct subscription selected you will need to do so 1st
#Connect-AzAccount -SubscriptionId $subsid -Tenant <ADD TENANT ID>

Set-AzContext -SubscriptionId $subsID
if (!$?) {
    write-host "Failed to connect to the Azure subscription " $subsID " extiting"
    exit
}

#Get username of logged-in Azure user so we can tag the resource group with it
$tmp = Get-AzContext
$ownername = $tmp.Account.Id

#---------Pre-flight: SKU availability and quota check---------------------------------------------------------------
# Verify the chosen VM SKU is a Confidential VM SKU (AMD SEV-SNP or Intel TDX, NOT Intel SGX which is
# a different isolation model and not supported by this script), is offered in the chosen region and not
# restricted for this subscription, and that there's enough vCPU quota left in the SKU's family before
# we start creating resources.
# Note: Get-AzComputeResourceSku and Get-AzVMUsage have been observed to misreport NotAvailableForSubscription / 0 quota
# even when ARM accepts the deployment (e.g. Standard_DC*as_v6 in koreacentral). Use -SkipSkuPreflight to bypass.
if ($SkipSkuPreflight) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "Pre-flight check SKIPPED (-SkipSkuPreflight). ARM will validate '$vmSize' in '$region' at deploy time." -ForegroundColor Yellow
    write-host "----------------------------------------------------------------------------------------------------------------"
}
else {
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Pre-flight check: confirming '$vmSize' is available in '$region' with sufficient quota..." -ForegroundColor Cyan

# Reject Intel SGX SKUs early - this script targets Confidential VMs (full-VM isolation),
# not SGX enclaves (per-process isolation). SGX SKUs use the DC*s_v3 / DC*s_v2 naming.
if ($vmSize -match '^Standard_DC\d+s_v[23]$') {
    write-host "ERROR: '$vmSize' is an Intel SGX SKU (application-enclave isolation), which is NOT supported by this script." -ForegroundColor Red
    write-host "This script provisions Confidential VMs (whole-VM hardware isolation) using either:" -ForegroundColor Yellow
    write-host "  - AMD SEV-SNP : DCa*/ECa*   (e.g. Standard_DC2as_v5, Standard_DC4as_v5)" -ForegroundColor Yellow
    write-host "  - Intel TDX   : DCe*/ECe*   (e.g. Standard_DC2es_v6, Standard_EC4es_v6)" -ForegroundColor Yellow
    write-host "For Intel SGX (DCsv3/DCsv2) workloads, see https://learn.microsoft.com/azure/confidential-computing/virtual-machine-solutions-sgx instead." -ForegroundColor Yellow
    exit 1
}

# Warn (but don't fail) if the SKU doesn't look like a known CVM SKU naming pattern.
# Recognised CVM patterns:
#   - DCa*/ECa* (AMD SEV-SNP, e.g. Standard_DC2as_v5)
#   - DCe*/ECe* (Intel TDX, e.g. Standard_DC2es_v6)
#   - NCCads*_H100_v5 (NVIDIA H100 SEV-SNP confidential GPU VM, e.g. Standard_NCC40ads_H100_v5)
$isKnownCvmSku = ($vmSize -match '^Standard_(DC|EC)\d+[a-z]+_v\d+$' -and $vmSize -match '_(DC|EC)\d+(a|e)') `
              -or ($vmSize -match '^Standard_NCC\d+ads_H100_v\d+$')
if (-not $isKnownCvmSku) {
    write-host "Warning: '$vmSize' does not match a known Confidential VM SKU pattern (DCa*/ECa* for SEV-SNP, DCe*/ECe* for TDX, NCCads_H100 for confidential GPU). Continuing, but deployment may fail if this is not a CVM SKU." -ForegroundColor Yellow
}

$skuInfo = $null
try {
    $skuInfo = Get-AzComputeResourceSku -Location $region -ErrorAction Stop |
        Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq $vmSize } |
        Select-Object -First 1
} catch {
    write-host "Warning: could not query Get-AzComputeResourceSku for '$region': $($_.Exception.Message)" -ForegroundColor Yellow
}

function Show-QuotaHelp($sku, $region) {
    write-host ""
    write-host "To find regions where this SKU IS available to your subscription, try:" -ForegroundColor Yellow
    write-host "  Get-AzComputeResourceSku | Where-Object { `$_.ResourceType -eq 'virtualMachines' -and `$_.Name -eq '$sku' -and (-not `$_.Restrictions -or `$_.Restrictions.Count -eq 0) } | Select-Object Locations, Name" -ForegroundColor Gray
    write-host ""
    write-host "To list the Confidential VM SKUs offered in '$region' (SEV-SNP DCa*/ECa* and Intel TDX DCe*/ECe*):" -ForegroundColor Yellow
    write-host "  Get-AzComputeResourceSku -Location '$region' | Where-Object { `$_.ResourceType -eq 'virtualMachines' -and `$_.Name -match '_(DC|EC)\d+(a|e)' } | Select-Object Name, @{n='Restricted';e={`$_.Restrictions.Count -gt 0}}" -ForegroundColor Gray
    write-host ""
    write-host "To see your vCPU usage and limits in '$region':" -ForegroundColor Yellow
    write-host "  Get-AzVMUsage -Location '$region' | Where-Object { `$_.Name.Value -match 'DCa|DCe|ECa|ECe|cores' } | Format-Table -AutoSize" -ForegroundColor Gray
    write-host ""
    write-host "To request a quota increase, see: https://learn.microsoft.com/azure/quotas/quickstart-increase-quota-portal" -ForegroundColor Yellow
}

if ($null -eq $skuInfo) {
    write-host "ERROR: VM SKU '$vmSize' is not offered in region '$region'." -ForegroundColor Red
    Show-QuotaHelp $vmSize $region
    exit 1
}

# Check subscription-level restrictions (e.g. NotAvailableForSubscription)
$subRestriction = $skuInfo.Restrictions | Where-Object {
    $_.ReasonCode -eq 'NotAvailableForSubscription' -or
    ($_.RestrictionInfo -and $_.RestrictionInfo.Locations -contains $region) -or
    ($_.Values -contains $region)
}
if ($subRestriction) {
    $reason = ($skuInfo.Restrictions | ForEach-Object { $_.ReasonCode }) -join ', '
    write-host "ERROR: VM SKU '$vmSize' is restricted for this subscription in '$region' (reason: $reason)." -ForegroundColor Red
    Show-QuotaHelp $vmSize $region
    exit 1
}

# Determine vCPU count and family for the SKU
$skuVCpus = ($skuInfo.Capabilities | Where-Object { $_.Name -eq 'vCPUs' } | Select-Object -First 1).Value -as [int]
$skuFamily = $skuInfo.Family   # e.g. 'standardDCASv5Family'
if (-not $skuVCpus) { $skuVCpus = 2 }   # fall back to a sensible minimum

# Check vCPU quota for that family in this region
try {
    $usage = Get-AzVMUsage -Location $region -ErrorAction Stop |
        Where-Object { $_.Name.Value -eq $skuFamily } |
        Select-Object -First 1
    if ($usage) {
        $available = [int]$usage.Limit - [int]$usage.CurrentValue
        write-host ("Quota for {0} in {1}: {2}/{3} used, {4} vCPUs available, this SKU needs {5}." -f `
            $skuFamily, $region, $usage.CurrentValue, $usage.Limit, $available, $skuVCpus) -ForegroundColor Cyan
        if ($available -lt $skuVCpus) {
            write-host "ERROR: Insufficient vCPU quota in family '$skuFamily' in '$region' to deploy '$vmSize' ($skuVCpus vCPUs needed, $available available)." -ForegroundColor Red
            Show-QuotaHelp $vmSize $region
            exit 1
        }
    } else {
        write-host "Note: could not find VM usage entry for family '$skuFamily' in '$region' - proceeding without quota check." -ForegroundColor Yellow
    }
} catch {
    write-host "Warning: Get-AzVMUsage failed for '$region': $($_.Exception.Message). Proceeding without quota check." -ForegroundColor Yellow
}

write-host "Pre-flight check passed: '$vmSize' is available and within quota in '$region'." -ForegroundColor Green
write-host "----------------------------------------------------------------------------------------------------------------"
}

# Create Resource Group
$resourceGroupTags = @{
    owner = $ownername
    BuiltBy = $scriptName
    OSType = $osType
    GitRepo = $gitRemoteUrl
}

# Add description tag if provided
if ($description -ne "") {
    $resourceGroupTags.Add("description", $description)
}

# Add smoketest tag if running in smoketest mode
if ($smoketest) {
    $resourceGroupTags.Add("smoketest", "true")
}

# Add DisableBastion tag if running without Bastion
if ($DisableBastion) {
    $resourceGroupTags.Add("BastionDisabled", "true")
}

New-AzResourceGroup -Name $resgrp -Location $region -Tag $resourceGroupTags -force

#create a credential object
$securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force # this could probably be done better inline rather than via a variable
$cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword);

# Create Key Vault
New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection;

#TO DO - if the SP hasn't been created in this tenant yet - break here, or prompt to create it (code as follows)
#Connect-Graph -Tenant "your tenant ID" Application.ReadWrite.All
#New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 -DisplayName "Confidential VM Orchestrator"

$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0';
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.id -PermissionsToKeys get,release;

# Add Key vault Key
if ($policyFilePath -ne "" -and (Test-Path $policyFilePath)) {
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -ReleasePolicyPath $policyFilePath;
} else {
    if ($policyFilePath -ne "" -and !(Test-Path $policyFilePath)) {
        Write-Host "Warning: Policy file path '$policyFilePath' does not exist. Using default CVM policy instead." -ForegroundColor Yellow
    }
    Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size $KeySize -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy;
}
        
# Capture Key Vault and Key details
$encryptionKeyVaultId = (Get-AzKeyVault -VaultName $akvname -ResourceGroupName $resgrp).ResourceId;
$encryptionKeyURL = (Get-AzKeyVaultKey -VaultName $akvname -KeyName $keyName).Key.Kid;

# Create new DES Config and Disk Encryption Set
$desConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $encryptionKeyVaultId -KeyUrl $encryptionKeyURL -IdentityType SystemAssigned -EncryptionType $diskEncryptionType;
New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName -DiskEncryptionSet $desConfig;
        
$diskencset = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desName;
        
# Assign DES Access Policy to key vault
$desIdentity = (Get-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resgrp).Identity.PrincipalId;
        
Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $desIdentity -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation;
        
$VirtualMachine = New-AzVMConfig -VMName $VMName -VMSize $vmSize;

# Configure OS based on the selected type
switch ($osType) {
    "Windows" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2022-datacenter-smalldisk-g2' -Version "latest";
        $VMIsLinux = $false
    }
    "Windows11" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'Windows-11' -Skus 'win11-23h2-ent' -Version "latest";
        $VMIsLinux = $false
    }
    "Windows2019" {
        # Windows Server 2019 Confidential VM image (G2)
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' -Offer 'windowsserver' -Skus '2019-datacenter-smalldisk-g2' -Version "latest";
        $VMIsLinux = $false
    }
    "Ubuntu" { # updated to use Ubuntu 24.04 LTS (or Ubuntu 22.04 CVM when -GPU is set, which is the
              # documented base image for the NVIDIA H100 SEV-SNP confidential VM SKU).
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred;
        if ($GPU) {
            # H100 CC mode requires Ubuntu 22.04 CVM (jammy). The 24.04 CVM image isn't
            # listed by Microsoft as a supported base for NCC H100 v5 today.
            $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer '0001-com-ubuntu-confidential-vm-jammy' -Skus '22_04-lts-cvm' -Version "latest";
        } else {
            $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest";
        }
        $VMIsLinux = $true
    }
    "RHEL" {
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Linux -ComputerName $vmname -Credential $cred;
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'redhat' -Offer 'rhel-cvm' -Skus '9_5_cvm' -Version "latest";
        $VMIsLinux = $true
    }
}
        
$subnet = New-AzVirtualNetworkSubnetConfig -Name ($vmsubnetName) -AddressPrefix "10.0.0.0/24";
$vnet = New-AzVirtualNetwork -Force -Name ($vnetname) -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/16" -Subnet $subnet;
$vnet = Get-AzVirtualNetwork -Name ($vnetname) -ResourceGroupName $resgrp;
$subnetId = $vnet.Subnets[0].Id;

# NAT Gateway for outbound internet from the VM subnet.
# Azure retired default outbound access on 30 Sep 2025: a new VM in a new VNet with no
# public IP / no NAT gateway / no LB outbound rule has zero internet access (it can't
# reach github.com to download the attest tool, can't apt/yum/winget update, etc).
# Bastion only provides inbound, so it doesn't help here. A NAT gateway on the subnet
# gives outbound to every VM in it without exposing any inbound surface, and is the
# Azure-recommended pattern. See https://learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access
write-host "Creating NAT Gateway for outbound internet access on the VM subnet..." -ForegroundColor Cyan
$natpipName = $basename + "-natgw-pip"
$natgwName  = $basename + "-natgw"
$natpip = New-AzPublicIpAddress -ResourceGroupName $resgrp -Name $natpipName -Location $region -Sku Standard -AllocationMethod Static
$natgw  = New-AzNatGateway -ResourceGroupName $resgrp -Name $natgwName -Location $region -Sku Standard -PublicIpAddress $natpip -IdleTimeoutInMinutes 10
# Re-fetch vnet, attach NAT gateway to the VM subnet, and push the update.
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $vmsubnetName }
$vmSubnet.NatGateway = New-Object Microsoft.Azure.Commands.Network.Models.PSResourceId
$vmSubnet.NatGateway.Id = $natgw.Id
Set-AzVirtualNetwork -VirtualNetwork $vnet | Out-Null
$vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$subnetId = ($vnet.Subnets | Where-Object { $_.Name -eq $vmsubnetName }).Id

#uncomment the below if you want to add a public IP address to the VM
#$pubip = New-AzPublicIpAddress -Force -Name ($pubIpPrefix + $resgrp) -ResourceGroupName $resgrp -Location $region -AllocationMethod Static -DomainNameLabel $domainNameLabel2;
#$pubip = Get-AzPublicIpAddress -Name ($pubIpPrefix + $resgrp) -ResourceGroupName $resgrp;
#$pubipId = $pubip.Id;

$nic = New-AzNetworkInterface -Force -Name ($nicPrefix) -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId #-PublicIpAddressId $pubip.Id;
$nic = Get-AzNetworkInterface -Name ($nicPrefix) -ResourceGroupName $resgrp;
$nicId = $nic.Id;

$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId;

# Set VM SecurityType and connect to DES
if ($VMisLinux) {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id -Linux;
} else {
    $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.Id;
}
$VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType;
$VirtualMachine = Set-AzVmUefi -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true;
$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -disable #disable boot diagnostics, you can re-enable if required

New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine;
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname;

# Create the Bastion to allow accessing the VM via the Azure portal (unless disabled)
if (-not $DisableBastion) {
    write-host "VM created, now enabling Bastion for the VM"
    $vnet = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
    Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vnet -AddressPrefix "10.0.99.0/26" | Set-AzVirtualNetwork # you can make this subnet anything you like as long as it fits into the vnet address space
    $publicip = New-AzPublicIpAddress -ResourceGroupName $resgrp -name "VNet1-ip" -location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName $resgrp -Name $bastionname -PublicIpAddressRgName $resgrp -PublicIpAddressName $publicIp.Name -VirtualNetworkRgName $resgrp -VirtualNetworkName $vnetname -Sku "Basic"
} else {
    write-host "VM created, Bastion creation skipped due to -DisableBastion parameter"
    write-host "VM is only accessible via private network connectivity (VPN, ExpressRoute, or peered networks)"
}

#---------GPU mode: install NVIDIA open-kernel driver + nvtrust local GPU verifier and run a GPU CC-mode attestation--
# Only runs when -GPU was specified. The H100 SKU exposes a GPU running in CC (confidential
# compute) mode; the NVIDIA local GPU verifier (nvtrust) talks to the GPU's RoT, fetches an
# attestation report, validates it against NVIDIA's reference values, and prints a verdict.
# This block is intentionally separate from the CPU SEV-SNP attestation below: with -GPU we
# do *both* a GPU and a CPU attestation, so the caller sees end-to-end runtime evidence for
# both the AMD SEV-SNP TEE and the NVIDIA H100 in CC mode.
if ($GPU) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "GPU step 1/3: installing NVIDIA open-kernel driver and nvtrust local GPU verifier inside the VM..." -ForegroundColor Magenta
    $gpuInstallScript = @"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
echo "--- apt-get update + install build deps ---"
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y build-essential dkms python3-pip python3-venv git curl jq unzip linux-headers-`$(uname -r) >/dev/null 2>&1 || true

echo "--- adding NVIDIA CUDA apt repo (Ubuntu 22.04) ---"
curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
dpkg -i /tmp/cuda-keyring.deb >/dev/null 2>&1
apt-get update -y >/dev/null 2>&1

echo "--- installing nvidia-open driver (required for H100 CC mode) ---"
# The 'open' kernel module variant is required for H100 confidential compute mode.
# We pin to a known-good major version that ships open-kernel modules and supports CC mode.
apt-get install -y nvidia-open >/dev/null 2>&1 || apt-get install -y nvidia-driver-555-open || apt-get install -y nvidia-driver-550-open || true

echo "--- cloning NVIDIA nvtrust (local GPU verifier) ---"
rm -rf /opt/nvtrust
git clone --depth 1 https://github.com/NVIDIA/nvtrust.git /opt/nvtrust 2>&1 | tail -5

echo "--- creating venv and installing local_gpu_verifier ---"
python3 -m venv /opt/gpu-verifier-venv
/opt/gpu-verifier-venv/bin/pip install --quiet --upgrade pip
/opt/gpu-verifier-venv/bin/pip install --quiet -e /opt/nvtrust/guest_tools/gpu_verifiers/local_gpu_verifier 2>&1 | tail -5 || true

echo "--- driver/verifier install complete; the VM will now be rebooted to load the new NVIDIA kernel module ---"
"@
    try {
        $gpuInstallOut = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId 'RunShellScript' -ScriptString $gpuInstallScript -ErrorAction Stop
        foreach ($entry in $gpuInstallOut.Value) { if ($entry.Message) { write-host $entry.Message } }
    } catch {
        write-host "GPU step 1/3 failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "GPU step 2/3: rebooting VM to load NVIDIA open-kernel module..." -ForegroundColor Magenta
    Restart-AzVM -ResourceGroupName $resgrp -Name $vmname | Out-Null
    write-host "Waiting 60s after reboot for the OS + run-command extension to come back up..."
    Start-Sleep -Seconds 60

    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "GPU step 3/3: running NVIDIA local GPU verifier (verifier.cc_admin) for H100 CC-mode attestation..." -ForegroundColor Magenta
    $gpuAttestScript = @"
#!/bin/bash
set -e
echo "--- nvidia-smi ---"
nvidia-smi || echo "nvidia-smi failed (driver may not have loaded; check 'dmesg | grep -i nvidia' on the VM)"

echo ""
echo "--- /opt/nvtrust/.../local_gpu_verifier : verifier.cc_admin ---"
if [ -x /opt/gpu-verifier-venv/bin/python3 ] && [ -d /opt/nvtrust/guest_tools/gpu_verifiers/local_gpu_verifier ]; then
    cd /opt/nvtrust/guest_tools/gpu_verifiers/local_gpu_verifier
    /opt/gpu-verifier-venv/bin/python3 -m verifier.cc_admin 2>&1 || echo "verifier.cc_admin exited with code `$?"
else
    echo "Local GPU verifier was not installed in step 1/3; skipping."
fi
"@
    $gpuOutput = $null
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            write-host "GPU verifier run-command attempt $attempt of 6..." -ForegroundColor Cyan
            $gpuOutput = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId 'RunShellScript' -ScriptString $gpuAttestScript -ErrorAction Stop
            break
        } catch {
            $msg = $_.Exception.Message
            if ($attempt -lt 6 -and ($msg -like '*Conflict*' -or $msg -like '*in progress*' -or $msg -like '*409*' -or $msg -like '*not ready*')) {
                write-host "Run-command extension busy/not ready; waiting 30s..." -ForegroundColor Yellow
                Start-Sleep -Seconds 30
            } else { throw }
        }
    }
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "--------------Output from NVIDIA local GPU verifier (H100 CC-mode attestation)--------------" -ForegroundColor Magenta
    if ($gpuOutput) {
        foreach ($entry in $gpuOutput.Value) { if ($entry.Message) { write-host $entry.Message } }
    } else {
        write-host "(no GPU verifier output was captured)" -ForegroundColor Yellow
    }
    write-host "----------------------------------------------------------------------------------------------------------------"
}

#---------Do attestation check inside the VM using Azure/cvm-attestation-tools-----------------------------------
# Downloads the latest pre-built attest CLI release from https://github.com/Azure/cvm-attestation-tools/releases
# and runs it inside the freshly deployed CVM, returning the output to the caller.

# Pick the right config based on the VM SKU's isolation type:
#   AMD SEV-SNP: DCa*/DCad*/ECa*/ECad*  (e.g. Standard_DC2as_v5)  -> config_snp.json
#   Intel TDX  : DCe*/DCed*/ECe*/ECed*  (e.g. Standard_DC2es_v5)  -> config_tdx.json
if ($vmSize -match '_(DC|EC)\d+e[a-z]*_') {
    $attestConfig = "config_tdx.json"
    $isolationType = "Intel TDX"
} else {
    $attestConfig = "config_snp.json"
    $isolationType = "AMD SEV-SNP"
}

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Running attestation inside the $osType VM using cvm-attestation-tools (isolation: $isolationType, config: $attestConfig)..." -ForegroundColor Cyan
write-host "This downloads the latest release of attest from https://github.com/Azure/cvm-attestation-tools/releases inside the VM."

if ($VMisLinux) {
    # Linux: download attest-lin.zip from the latest release, extract, run attest
    # Note: the zip extracts files at its root (no "attest-lin/" subfolder)
    $attestScript = @"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
if ! command -v unzip >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    (apt-get update -y && apt-get install -y unzip jq) >/dev/null 2>&1 || \
        (dnf install -y unzip jq || yum install -y unzip jq) >/dev/null 2>&1
fi
WORKDIR=`$(mktemp -d)
cd "`$WORKDIR"
echo "Downloading latest attest-lin.zip from cvm-attestation-tools..."
curl -fsSL -o attest-lin.zip https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-lin.zip
unzip -q attest-lin.zip
chmod +x attest read_report 2>/dev/null || true
echo "--------- attest --c $attestConfig ---------"
./attest --c $attestConfig 2>&1 | tee attest.out || echo "attest exited with code `$?"

# Extract JWT (a single token of the form xxx.yyy.zzz with base64url chars)
# from the attest output and pretty-print header + payload claims using jq.
JWT=`$(grep -Eo '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' attest.out | awk '{ print length, `$0 }' | sort -nr | head -1 | cut -d' ' -f2-)
if [ -n "`$JWT" ] && command -v jq >/dev/null 2>&1; then
    echo ""
    echo "--------- Decoded JWT (via jq) ---------"
    b64d() { local s=`$1; local m=`$(( `${#s} % 4 )); if [ `$m -eq 2 ]; then s="`${s}=="; elif [ `$m -eq 3 ]; then s="`${s}="; fi; echo "`$s" | tr '_-' '/+' | base64 -d 2>/dev/null; }
    H=`$(echo "`$JWT" | cut -d. -f1)
    P=`$(echo "`$JWT" | cut -d. -f2)
    echo "--- header ---"
    b64d "`$H" | jq .
    echo "--- payload ---"
    b64d "`$P" | jq .
    echo "--- key MAA claims ---"
    b64d "`$P" | jq '{iss, "x-ms-attestation-type", "x-ms-compliance-status", "x-ms-isolation-tee": ."x-ms-isolation-tee"."x-ms-attestation-type", "x-ms-runtime-vm-configuration-secure-boot": ."x-ms-runtime"."vm-configuration"."secure-boot", "x-ms-runtime-vm-configuration-tpm-enabled": ."x-ms-runtime"."vm-configuration"."tpm-enabled"}'
else
    echo "(no JWT found in attest output to decode, or jq unavailable)"
fi

cd /
rm -rf "`$WORKDIR"
"@
    $runCommandId = 'RunShellScript'
} else {
    # Windows: download attest-win.zip from the latest release, extract, run attest.exe
    # Note: the zip extracts files at its root (no "attest-win/" subfolder)
    $attestScript = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$work = Join-Path `$env:TEMP "cvm-attest-`$(Get-Random)"
New-Item -ItemType Directory -Path `$work -Force | Out-Null
Set-Location `$work
Write-Host "Downloading latest attest-win.zip from cvm-attestation-tools..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Run-command runs as SYSTEM, which has no IE/WinINet proxy config; Invoke-WebRequest then
# fails with "Unable to connect to the remote server" even though outbound is fine.
# Prefer curl.exe (in-box on Win10/11/Server2019+, doesn't use WinINet); fall back to
# Invoke-WebRequest with the default proxy explicitly cleared.
`$attestUrl = 'https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-win.zip'
`$dlOk = `$false
`$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if (`$curl) {
    & `$curl.Source -fsSL --retry 5 --retry-connrefused --retry-delay 5 -o 'attest-win.zip' `$attestUrl
    if (`$LASTEXITCODE -eq 0 -and (Test-Path 'attest-win.zip')) { `$dlOk = `$true }
    else { Write-Host "curl.exe download failed (exit `$LASTEXITCODE); falling back to Invoke-WebRequest..." -ForegroundColor Yellow }
}
if (-not `$dlOk) {
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
    for (`$i = 1; `$i -le 5 -and -not `$dlOk; `$i++) {
        try {
            Invoke-WebRequest -Uri `$attestUrl -OutFile 'attest-win.zip' -UseBasicParsing
            `$dlOk = `$true
        } catch {
            Write-Host "Invoke-WebRequest attempt `$i failed: `$(`$_.Exception.Message)" -ForegroundColor Yellow
            if (`$i -lt 5) { Start-Sleep -Seconds 10 }
        }
    }
}
if (-not `$dlOk) { throw "Failed to download attest-win.zip from `$attestUrl" }
Expand-Archive -Path 'attest-win.zip' -DestinationPath '.' -Force
Write-Host "--------- attest.exe --c $attestConfig ---------"

# attest.exe writes INFO logs to stderr; under `$ErrorActionPreference='Stop' that surfaces
# as a NativeCommandError even though the tool is working. Relax EAP for this single call,
# merge stderr into stdout, and rely on `$LASTEXITCODE for success/failure.
# Use a wide -Width on Out-String so the JWT (which can be ~1.5KB on a single line)
# is not wrapped at the default ~80-char console width - otherwise the regex below only
# matches a wrapped fragment and base64url decoding fails with "Invalid length".
`$prevEap = `$ErrorActionPreference
`$ErrorActionPreference = 'Continue'
if (`$PSVersionTable.PSVersion.Major -ge 7) { `$PSNativeCommandUseErrorActionPreference = `$false }
`$attestOut = (& .\attest.exe --c $attestConfig 2>&1 | Out-String -Width 16384)
`$attestExit = `$LASTEXITCODE
`$ErrorActionPreference = `$prevEap
Write-Host `$attestOut
if (`$attestExit -ne 0) { Write-Host "attest.exe exited with code `$attestExit" -ForegroundColor Yellow }

# Extract JWT (xxx.yyy.zzz, base64url) from the attest output and pretty-print
# header + payload claims using built-in PowerShell JSON support (no jq needed).
# Defensive: collapse the captured output to a single line so any stray CR/LF inside
# the token is removed, then anchor the regex to 'eyJ' (base64url of '{"') which is
# the canonical JWT header start. Without that anchor, the greedy 3-segment match
# can cross attest.exe's interleaved Python INFO log lines (which share '-' / '_'
# with base64url) and pick up a corrupted token, producing garbage on decode.
`$attestOutFlat = (`$attestOut -replace '\s+', '')
`$jwtMatch = [regex]::Matches(`$attestOutFlat, 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{50,}') | Sort-Object { `$_.Length } -Descending | Select-Object -First 1
if (`$jwtMatch) {
    function ConvertFrom-Base64Url(`$s) {
        `$s = (`$s -replace '\s', '').Replace('-', '+').Replace('_', '/')
        switch (`$s.Length % 4) { 2 { `$s += '==' } 3 { `$s += '=' } }
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$s))
    }
    `$parts = `$jwtMatch.Value.Split('.')
    Write-Host ""
    Write-Host '--------- Decoded JWT ---------'
    Write-Host '--- header ---'
    ConvertFrom-Base64Url `$parts[0] | ConvertFrom-Json | ConvertTo-Json -Depth 10
    Write-Host '--- payload ---'
    `$payload = ConvertFrom-Base64Url `$parts[1] | ConvertFrom-Json
    `$payload | ConvertTo-Json -Depth 10
    Write-Host '--- key MAA claims ---'
    [pscustomobject]@{
        iss                            = `$payload.iss
        'x-ms-attestation-type'        = `$payload.'x-ms-attestation-type'
        'x-ms-compliance-status'       = `$payload.'x-ms-compliance-status'
        'x-ms-isolation-tee'           = `$payload.'x-ms-isolation-tee'.'x-ms-attestation-type'
        'secure-boot'                  = `$payload.'x-ms-runtime'.'vm-configuration'.'secure-boot'
        'tpm-enabled'                  = `$payload.'x-ms-runtime'.'vm-configuration'.'tpm-enabled'
    } | Format-List
} else {
    Write-Host '(no JWT found in attest output to decode)'
}

Set-Location `$env:TEMP
Remove-Item -Recurse -Force `$work -ErrorAction SilentlyContinue
"@
    $runCommandId = 'RunPowerShellScript'
}

# Retry loop: Invoke-AzVMRunCommand can return 409 Conflict for several minutes
# after VM creation while the run-command extension is still finalising. This is
# especially common on TDX SKUs. Back off and retry on Conflict / "in progress".
$output = $null
$maxAttempts = 10
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        write-host "Attestation run-command attempt $attempt of $maxAttempts..." -ForegroundColor Cyan
        $output = Invoke-AzVMRunCommand -Name $vmname -ResourceGroupName $resgrp -CommandId $runCommandId -ScriptString $attestScript -ErrorAction Stop
        break
    } catch {
        $msg = $_.Exception.Message
        if ($attempt -lt $maxAttempts -and ($msg -like '*Conflict*' -or $msg -like '*in progress*' -or $msg -like '*409*')) {
            write-host "Run-command extension busy (409); waiting 60s before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds 60
        } else {
            throw
        }
    }
}

write-host "----------------------------------------------------------------------------------------------------------------"
write-host "--------------Output from cvm-attestation-tools running inside the VM--------------"
foreach ($entry in $output.Value) {
    if ($entry.Message) { write-host $entry.Message }
}
write-host "----------------------------------------------------------------------------------------------------------------"
write-host "Build and attestation complete." -ForegroundColor Green


# Smoketest cleanup - automatically remove all resources if smoketest flag is used
if ($smoketest) {
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "SMOKETEST MODE: Automatically removing all created resources..."
    write-host "Removing resource group: $resgrp"
    if (-not $DisableBastion) {
        write-host "This will delete all resources including VM, Key Vault, Bastion, VNet, etc."
    } else {
        write-host "This will delete all resources including VM, Key Vault, VNet, etc."
    }
    write-host "WARNING: RESOURCES ARE NOT RECOVERABLE."  -ForegroundColor Red
    write-host "Press ANY KEY to cancel deletion, or wait 10 seconds to proceed..."  -ForegroundColor Yellow
    write-host "----------------------------------------------------------------------------------------------------------------"
    
    # Wait for 10 seconds or until a key is pressed
    $timeout = 10
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = $false
    
    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            [Console]::ReadKey($true) | Out-Null
            $cancelled = $true
            break
        }
        Start-Sleep -Milliseconds 100
        $remaining = [math]::Ceiling($timeout - $timer.Elapsed.TotalSeconds)
        Write-Host "`rDeletion in $remaining seconds... (Press any key to cancel)" -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()
    
    if ($cancelled) {
        write-host "`nDeletion cancelled by user. Resources remain in resource group: $resgrp" -ForegroundColor Green
        write-host "To clean up manually later, run: Remove-AzResourceGroup -Name $resgrp -Force"
    } else {
        write-host "`nProceeding with resource deletion..."
        try {
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob
            write-host "Resource group deletion initiated successfully (running in background)"
            write-host "All resources in resource group '$resgrp' are being removed"
        } catch {
            write-host "Error removing resource group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    write-host ""
    write-host "Resources created in resource group: $resgrp"
    write-host "To clean up manually, run: Remove-AzResourceGroup -Name $resgrp -Force"
}

# determine the execution time of the script
$myTimeSpan = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Output ("Execution time was {0} minutes and {1} seconds." -f $myTimeSpan.Minutes, $myTimeSpan.Seconds)
