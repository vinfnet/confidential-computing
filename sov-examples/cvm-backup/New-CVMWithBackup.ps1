# New-CVMWithBackup.ps1
# Deploys a Windows Confidential VM (CVM) in Korea Central with:
#   - Confidential OS disk encryption (DiskWithVMGuestState) backed by a Customer Managed Key
#   - Private VNet (no public IP address, no Bastion)
#   - All resources in a single resource group named <basename><5-digit random suffix>
#   - Azure Backup (Enhanced Policy) for CVMs configured to run every 4 hours
#   - An initial on-demand backup that is triggered and monitored to completion
#
# Korea Central supports Confidential VMs (DCasv5/ECasv5 series).
# The script relies on the Az PowerShell module (Az.Compute, Az.KeyVault,
# Az.Network, Az.RecoveryServices).  Update-Module Az -Force if needed.
#
# Usage:
#   ./New-CVMWithBackup.ps1 -subsID <SUBSCRIPTION_ID> -basename <PREFIX>
#
# Optional parameters:
#   -region      Azure region (default: koreacentral)
#   -vmsize      CVM SKU        (default: Standard_DC2as_v5)
#   -description Tag added to the resource group
#   -smoketest   Switch – automatically removes all resources after the backup completes
#
# Simon Gallagher / Copilot – sov-examples edition
# Use at your own risk, no warranties implied.

param (
    [Parameter(Mandatory)]$subsID,
    [Parameter(Mandatory)]$basename,
    [Parameter(Mandatory = $false)]$description  = "",
    [Parameter(Mandatory = $false)]$region       = "koreacentral",
    [Parameter(Mandatory = $false)]$vmsize       = "Standard_DC2as_v5",
    [Parameter(Mandatory = $false)][switch]$smoketest
)

# ─── Validate inputs ──────────────────────────────────────────────────────────
if ($subsID -eq "" -or $basename -eq "") {
    Write-Host "You must supply -subsID and -basename." -ForegroundColor Red
    exit 1
}

$startTime  = Get-Date
$scriptName = $MyInvocation.MyCommand.Name

# ─── Git repo tag (best-effort) ───────────────────────────────────────────────
$gitRemoteUrl = ""
try   { $gitRemoteUrl = (git remote get-url origin 2>$null) -replace "\.git$", "" } catch {}
if (-not $gitRemoteUrl) { $gitRemoteUrl = "https://github.com/vinfnet/confidential-computing" }

# ─── Resource names ───────────────────────────────────────────────────────────
# 5-digit random numeric suffix
$suffix      = -join ((0..9) | Get-Random -Count 5)
$resgrp      = $basename + $suffix          # resource group = prefix + 5 digits

# Key Vault name: must be globally unique, 3-24 chars, alphanumeric + hyphens
# We take up to the first 14 chars of basename so the whole name stays ≤ 24
$akvBaseName = ($basename -replace '[^a-zA-Z0-9]', '')[0..13] -join ''
$akvname     = ($akvBaseName + $suffix + "akv").ToLower()  # e.g. mybase12345akv

$desname     = $resgrp + "des"
$keyname     = $resgrp + "-cmk-key"
$vmname      = $resgrp
# Windows ComputerName must be ≤ 15 characters
$vmComputerName = $vmname.Substring(0, [Math]::Min($vmname.Length, 15))
$vnetname    = $resgrp + "vnet"
$vmsubnet    = $resgrp + "vmsubnet"
$nicname     = $resgrp + "-nic"
$rsvname     = $resgrp + "rsv"              # Recovery Services Vault
$policyname  = $resgrp + "-backup-policy"

# CVM security settings
$vmSecurityType         = "ConfidentialVM"
$secureEncryptGuestState = "DiskWithVMGuestState"
$diskEncryptionType     = "ConfidentialVmEncryptedWithCustomerKey"
$identityType           = "SystemAssigned"
$KeySize                = 3072

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host " CVM Backup Deployment – sov-examples" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host " Script      : $scriptName"
Write-Host " Repository  : $gitRemoteUrl"
Write-Host " Subscription: $subsID"
Write-Host " Region      : $region"
Write-Host " Basename    : $basename  →  Resource group: $resgrp"
Write-Host " VM name     : $vmname   (size: $vmsize)  ComputerName: $vmComputerName"
Write-Host " Key Vault   : $akvname"
Write-Host " RSV         : $rsvname"
if ($smoketest) {
    Write-Host " SMOKETEST : All resources will be deleted after the initial backup." -ForegroundColor Yellow
}
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan

# ─── Authenticate & set subscription ─────────────────────────────────────────
Set-AzContext -SubscriptionId $subsID -ErrorAction Stop
$ownername = (Get-AzContext).Account.Id

# ─── Resource Group ───────────────────────────────────────────────────────────
$rgTags = @{
    owner       = $ownername
    BuiltBy     = $scriptName
    GitRepo     = $gitRemoteUrl
    Purpose     = "CVM-Backup-Demo"
}
if ($description -ne "") { $rgTags["description"] = $description }
if ($smoketest)           { $rgTags["smoketest"]   = "true" }

Write-Host "`n[1/9] Creating resource group: $resgrp ..." -ForegroundColor Green
New-AzResourceGroup -Name $resgrp -Location $region -Tag $rgTags -Force | Out-Null

# ─── VM credentials ───────────────────────────────────────────────────────────
$vmusername    = "azureuser"
$vmpassword    = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40)
$securePass    = ConvertTo-SecureString -String $vmpassword -AsPlainText -Force
$cred          = New-Object System.Management.Automation.PSCredential ($vmusername, $securePass)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  VM admin username : $vmusername" -ForegroundColor Yellow
Write-Host "║  VM admin password : $vmpassword" -ForegroundColor Yellow
Write-Host "║  Save the password NOW – it cannot be retrieved later." -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

# ─── Key Vault ────────────────────────────────────────────────────────────────
Write-Host "`n[2/9] Creating Key Vault: $akvname ..." -ForegroundColor Green
New-AzKeyVault `
    -Name $akvname `
    -Location $region `
    -ResourceGroupName $resgrp `
    -Sku Premium `
    -EnabledForDiskEncryption `
    -DisableRbacAuthorization `
    -SoftDeleteRetentionInDays 10 `
    -EnablePurgeProtection | Out-Null

# Grant the CVM Orchestrator service principal access to the key vault
$cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'
Set-AzKeyVaultAccessPolicy `
    -VaultName $akvname `
    -ResourceGroupName $resgrp `
    -ObjectId $cvmAgent.Id `
    -PermissionsToKeys get,release | Out-Null

# ─── Key Vault Key ────────────────────────────────────────────────────────────
Write-Host "`n[3/9] Creating CMK key in Key Vault ..." -ForegroundColor Green
Add-AzKeyVaultKey `
    -VaultName $akvname `
    -Name $keyname `
    -Size $KeySize `
    -KeyOps wrapKey,unwrapKey `
    -KeyType RSA `
    -Destination HSM `
    -Exportable `
    -UseDefaultCVMPolicy | Out-Null

$encryptionKeyVaultId = (Get-AzKeyVault -VaultName $akvname -ResourceGroupName $resgrp).ResourceId
$encryptionKeyURL     = (Get-AzKeyVaultKey  -VaultName $akvname -KeyName $keyname).Key.Kid

# ─── Disk Encryption Set ──────────────────────────────────────────────────────
Write-Host "`n[4/9] Creating Disk Encryption Set: $desname ..." -ForegroundColor Green
$desConfig = New-AzDiskEncryptionSetConfig `
    -Location          $region `
    -SourceVaultId     $encryptionKeyVaultId `
    -KeyUrl            $encryptionKeyURL `
    -IdentityType      SystemAssigned `
    -EncryptionType    $diskEncryptionType

New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname -DiskEncryptionSet $desConfig | Out-Null

$diskencset  = Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname
$desIdentity = $diskencset.Identity.PrincipalId

# Grant DES access to Key Vault
Set-AzKeyVaultAccessPolicy `
    -VaultName          $akvname `
    -ResourceGroupName  $resgrp `
    -ObjectId           $desIdentity `
    -PermissionsToKeys  wrapKey,unwrapKey,get `
    -BypassObjectIdValidation | Out-Null

# ─── Virtual Network (private, no public IP) ──────────────────────────────────
Write-Host "`n[5/9] Creating private VNet: $vnetname ..." -ForegroundColor Green
$subnet = New-AzVirtualNetworkSubnetConfig -Name $vmsubnet -AddressPrefix "10.0.0.0/24"
$vnet   = New-AzVirtualNetwork `
    -Force `
    -Name $vnetname `
    -ResourceGroupName $resgrp `
    -Location $region `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnet

$vnet     = Get-AzVirtualNetwork -Name $vnetname -ResourceGroupName $resgrp
$subnetId = $vnet.Subnets[0].Id

# NIC without a public IP
$nic    = New-AzNetworkInterface -Force -Name $nicname -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId
$nic    = Get-AzNetworkInterface -Name $nicname -ResourceGroupName $resgrp
$nicId  = $nic.Id

# ─── Confidential VM ──────────────────────────────────────────────────────────
Write-Host "`n[6/9] Creating Windows Confidential VM: $vmname ..." -ForegroundColor Green
$VirtualMachine = New-AzVMConfig -VMName $vmname -VMSize $vmsize

$VirtualMachine = Set-AzVMOperatingSystem `
    -VM $VirtualMachine -Windows `
    -ComputerName $vmComputerName `
    -Credential $cred `
    -ProvisionVMAgent `
    -EnableAutoUpdate

$VirtualMachine = Set-AzVMSourceImage `
    -VM $VirtualMachine `
    -PublisherName 'MicrosoftWindowsServer' `
    -Offer          'windowsserver' `
    -Skus           '2022-datacenter-smalldisk-g2' `
    -Version        "latest"

$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId

$VirtualMachine = Set-AzVMOSDisk `
    -VM $VirtualMachine `
    -StorageAccountType      "StandardSSD_LRS" `
    -CreateOption            "FromImage" `
    -SecurityEncryptionType  $secureEncryptGuestState `
    -SecureVMDiskEncryptionSet $diskencset.Id

$VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType
$VirtualMachine = Set-AzVmUefi             -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true
$VirtualMachine = Set-AzVMBootDiagnostic   -VM $VirtualMachine -Disable

New-AzVM -ResourceGroupName $resgrp -Location $region -VM $VirtualMachine -ErrorAction Stop | Out-Null
$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname
Write-Host "   VM provisioned: $($vm.Id)" -ForegroundColor DarkGreen

# ─── Recovery Services Vault ──────────────────────────────────────────────────
Write-Host "`n[7/9] Creating Recovery Services Vault: $rsvname ..." -ForegroundColor Green
$rsv = New-AzRecoveryServicesVault `
    -Name              $rsvname `
    -ResourceGroupName $resgrp `
    -Location          $region

# Opt the vault into Enhanced (Trusted Azure VM) backup for CVM support
Set-AzRecoveryServicesVaultProperty `
    -VaultId                        $rsv.ID `
    -EnableAzureMonitor             $true `
    -DisableClassicAlerts           $true | Out-Null

Set-AzRecoveryServicesVaultContext -Vault $rsv

# ─── Enhanced Backup Policy – every 4 hours ───────────────────────────────────
Write-Host "`n[8/9] Creating Enhanced Backup Policy ($policyname) – 4-hour schedule ..." -ForegroundColor Green

# Fetch the Enhanced policy template objects
$schPol = Get-AzRecoveryServicesBackupSchedulePolicyObject `
    -WorkloadType         "AzureVM" `
    -BackupManagementType "AzureVM" `
    -PolicySubType        "Enhanced"

$retPol = Get-AzRecoveryServicesBackupRetentionPolicyObject `
    -WorkloadType         "AzureVM" `
    -BackupManagementType "AzureVM" `
    -PolicySubType        "Enhanced"

# Configure an hourly schedule with a 4-hour interval covering the full day
$schPol.ScheduleRunFrequency                         = "Hourly"
$schPol.HourlySchedule.Interval                     = 4          # every 4 hours
$schPol.HourlySchedule.WindowStartTime              = (Get-Date).Date.AddHours(0)  # midnight UTC
$schPol.HourlySchedule.WindowDuration               = 24         # full 24-hour window

$policy = New-AzRecoveryServicesBackupProtectionPolicy `
    -Name                 $policyname `
    -WorkloadType         "AzureVM" `
    -BackupManagementType "AzureVM" `
    -RetentionPolicy      $retPol `
    -SchedulePolicy       $schPol `
    -PolicySubType        "Enhanced" `
    -VaultId              $rsv.ID

Write-Host "   Backup policy created: $($policy.Name)" -ForegroundColor DarkGreen

# Enable protection on the CVM
Write-Host "   Enabling backup protection on VM: $vmname ..." -ForegroundColor DarkGreen
Enable-AzRecoveryServicesBackupProtection `
    -Policy            $policy `
    -Name              $vmname `
    -ResourceGroupName $resgrp `
    -VaultId           $rsv.ID | Out-Null

# ─── Initial on-demand backup ─────────────────────────────────────────────────
Write-Host "`n[9/9] Triggering initial on-demand backup ..." -ForegroundColor Green

# Retry loop: the backup container registration can take a few minutes to propagate
$backupContainer = $null
$maxRetries      = 12       # up to ~6 minutes total
$retryDelay      = 30       # seconds between retries
$retryAttempt    = 0

Write-Host "   Waiting for backup container to register (up to ~6 min) ..."
while ($null -eq $backupContainer -and $retryAttempt -lt $maxRetries) {
    Start-Sleep -Seconds $retryDelay
    $retryAttempt++
    $backupContainer = Get-AzRecoveryServicesBackupContainer `
        -ContainerType      "AzureVM" `
        -FriendlyName       $vmname `
        -VaultId            $rsv.ID `
        -ErrorAction        SilentlyContinue
    Write-Host "   Attempt $retryAttempt/$maxRetries – container: $(if ($backupContainer) { 'found' } else { 'not yet registered' })"
}

if ($null -eq $backupContainer) {
    Write-Host "   Container not found after $($maxRetries * $retryDelay) seconds." -ForegroundColor Red
    Write-Host "   Check protection status in the Azure portal: Recovery Services Vault -> $rsvname" -ForegroundColor Red
    exit 1
}

$backupItem = Get-AzRecoveryServicesBackupItem `
    -Container    $backupContainer `
    -WorkloadType "AzureVM" `
    -VaultId      $rsv.ID

$backupJob = Backup-AzRecoveryServicesBackupItem `
    -Item    $backupItem `
    -VaultId $rsv.ID

Write-Host "   Initial backup job started – Job ID: $($backupJob.JobId)" -ForegroundColor DarkGreen
Write-Host "   Waiting for initial backup to complete (this can take 15–45 minutes) ..."

# Poll until the job reaches a terminal state
$completedStates = @("Completed", "Failed", "Cancelled", "CompletedWithWarnings")
do {
    Start-Sleep -Seconds 60
    $jobStatus = Get-AzRecoveryServicesBackupJob -JobId $backupJob.JobId -VaultId $rsv.ID
    $elapsed   = (New-TimeSpan -Start $startTime -End (Get-Date))
    Write-Host "   [+$($elapsed.Minutes)m] Backup status: $($jobStatus.Status)"
} until ($completedStates -contains $jobStatus.Status)

if ($jobStatus.Status -eq "Completed") {
    Write-Host "   ✔ Initial backup completed successfully." -ForegroundColor Green
} elseif ($jobStatus.Status -eq "CompletedWithWarnings") {
    Write-Host "   ⚠ Initial backup completed with warnings. Review the job in the Azure portal." -ForegroundColor Yellow
} else {
    Write-Host "   ✘ Initial backup ended with status: $($jobStatus.Status). Check the Azure portal for details." -ForegroundColor Red
}

# ─── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host " Deployment Summary" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host " Resource Group        : $resgrp"
Write-Host " Region                : $region"
Write-Host " VM                    : $vmname  ($vmsize)"
Write-Host " Key Vault             : $akvname"
Write-Host " Disk Encryption Set   : $desname"
Write-Host " Virtual Network       : $vnetname  (private, no public IP)"
Write-Host " Recovery Services RSV : $rsvname"
Write-Host " Backup Policy         : $policyname  (every 4 hours, Enhanced)"
Write-Host " Initial Backup Job    : $($backupJob.JobId)  →  $($jobStatus.Status)"
Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""
Write-Host " To access this VM use Azure Bastion (add one later) or a site-to-site VPN."
Write-Host " To clean up: Remove-AzResourceGroup -Name $resgrp -Force"
Write-Host ""

# ─── Smoketest cleanup ────────────────────────────────────────────────────────
if ($smoketest) {
    Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host " SMOKETEST MODE: All resources will be deleted in 10 seconds." -ForegroundColor Yellow
    Write-Host " Press ANY KEY to cancel ..." -ForegroundColor Yellow
    Write-Host "─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Yellow

    $timeout = 10
    $timer   = [System.Diagnostics.Stopwatch]::StartNew()
    $cancelled = $false
    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null; $cancelled = $true; break }
        Start-Sleep -Milliseconds 100
        $remaining = [math]::Ceiling($timeout - $timer.Elapsed.TotalSeconds)
        Write-Host "`rDeleting in $remaining s... (any key to cancel)" -NoNewline -ForegroundColor Yellow
    }
    $timer.Stop()

    if ($cancelled) {
        Write-Host "`nDeletion cancelled – resources remain in: $resgrp" -ForegroundColor Green
    } else {
        Write-Host "`nRemoving resource group $resgrp ..."
        Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
        Write-Host "Resource group deletion initiated (background job)." -ForegroundColor Green
    }
}

# ─── Execution time ───────────────────────────────────────────────────────────
$span = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Host ("Total execution time: {0} hours, {1} minutes, {2} seconds." -f $span.Hours, $span.Minutes, $span.Seconds) -ForegroundColor Cyan
