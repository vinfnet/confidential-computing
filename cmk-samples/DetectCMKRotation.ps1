# Script to detect CMK rotation status for Confidential VMs
# April 2026
# Tested on Windows (PWSH 7.4.6)
#
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
#
# Detects when a Customer Managed Key has been rotated for CVMs by examining each VM's
# Disk Encryption Set, the active key version, all historical key versions, and when
# the key was last rotated.
#
# Usage:
#   .\DetectCMKRotation.ps1 -ResourceGroupName "myRG"
#   .\DetectCMKRotation.ps1 -ResourceGroupName "myRG" -Csv "C:\reports\rotation-report.csv"

param (
    [Parameter(Mandatory)]$ResourceGroupName,
    [Parameter(Mandatory = $false)][string]$Csv
)

$context = Get-AzContext
if (-not $context) {
    Write-Error "No Azure context found. Please run Connect-AzAccount first."
    exit 1
}

Write-Host "Analyzing CMK rotation status for CVMs in resource group '$ResourceGroupName'..." -ForegroundColor Cyan

# Get all VMs in the resource group
$vms = Get-AzVM -ResourceGroupName $ResourceGroupName
if (-not $vms) {
    Write-Warning "No VMs found in resource group '$ResourceGroupName'."
    exit
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($vm in $vms) {
    $vmName = $vm.Name

    # Get the DES ID from the OS disk
    $osDisk = $vm.StorageProfile.OsDisk
    $desId = $null

    # Check SecureVMDiskEncryptionSetId (Confidential VM) first, then standard DiskEncryptionSetId
    if ($osDisk.ManagedDisk.SecurityProfile.DiskEncryptionSet.Id) {
        $desId = $osDisk.ManagedDisk.SecurityProfile.DiskEncryptionSet.Id
    }
    elseif ($osDisk.ManagedDisk.DiskEncryptionSet.Id) {
        $desId = $osDisk.ManagedDisk.DiskEncryptionSet.Id
    }

    if (-not $desId) {
        Write-Host "  $vmName - No Disk Encryption Set found, skipping" -ForegroundColor Gray
        continue
    }

    # Extract DES name from resource ID
    $desName = ($desId -split '/')[-1]

    # Get the Disk Encryption Set details
    try {
        $des = Get-AzDiskEncryptionSet -ResourceGroupName $ResourceGroupName -Name $desName
    }
    catch {
        Write-Warning "  Unable to get DES '$desName' for VM '$vmName': $_"
        continue
    }

    # Parse the key URL to extract vault name, key name, and version
    # Format: https://<vault>.vault.azure.net/keys/<keyname>/<version>
    $activeKeyUrl = $des.ActiveKey.KeyUrl
    if (-not $activeKeyUrl) {
        Write-Warning "  No active key URL found in DES '$desName' for VM '$vmName'"
        continue
    }

    $keyUrlParts = $activeKeyUrl -replace 'https://', '' -split '/'
    $vaultFqdn = $keyUrlParts[0]
    $vaultName = ($vaultFqdn -split '\.')[0]
    $keyName = $keyUrlParts[2]
    $activeVersion = $keyUrlParts[3]

    # Get all versions of this key from Key Vault to determine rotation history
    try {
        $keyVersions = Get-AzKeyVaultKey -VaultName $vaultName -Name $keyName -IncludeVersions |
            Sort-Object -Property Created -Descending
    }
    catch {
        Write-Warning "  Unable to read key versions for '$keyName' in vault '$vaultName': $_"
        continue
    }

    $totalVersions = $keyVersions.Count
    $activeKeyDetail = $keyVersions | Where-Object { $_.Version -eq $activeVersion }

    # Determine when the active version was created (i.e., when the last rotation happened)
    $activeCreated = if ($activeKeyDetail.Created) { $activeKeyDetail.Created } else { $null }

    # Check if key has been rotated (more than 1 version exists)
    $hasBeenRotated = $totalVersions -gt 1

    # Find previous version if rotation occurred
    $previousVersion = $null
    $previousCreated = $null
    if ($hasBeenRotated) {
        $prevKey = $keyVersions | Where-Object { $_.Version -ne $activeVersion } | Select-Object -First 1
        if ($prevKey) {
            $previousVersion = $prevKey.Version
            $previousCreated = $prevKey.Created
        }
    }

    # Determine rotation status
    if ($hasBeenRotated) {
        $rotationStatus = "ROTATED ($totalVersions versions)"
        $statusColor = "Green"
    }
    else {
        $rotationStatus = "NEVER ROTATED"
        $statusColor = "DarkYellow"
    }

    $results.Add([PSCustomObject]@{
        VMName              = $vmName
        DESName             = $desName
        VaultName           = $vaultName
        KeyName             = $keyName
        ActiveVersion       = $activeVersion.Substring(0, [Math]::Min(12, $activeVersion.Length)) + "..."
        ActiveVersionFull   = $activeVersion
        ActiveCreated       = if ($activeCreated) { $activeCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        PreviousVersion     = if ($previousVersion) { $previousVersion.Substring(0, [Math]::Min(12, $previousVersion.Length)) + "..." } else { "N/A" }
        PreviousCreated     = if ($previousCreated) { $previousCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        TotalVersions       = $totalVersions
        RotationStatus      = $rotationStatus
        RotationStatusClean = if ($hasBeenRotated) { "ROTATED" } else { "NEVER ROTATED" }
    })

    Write-Host "  $vmName -> $keyName (v$totalVersions)" -ForegroundColor Gray
}

if ($results.Count -eq 0) {
    Write-Warning "No CVMs with CMK disk encryption found in resource group '$ResourceGroupName'."
    exit
}

# Console output with color-coded status
Write-Host ""
$fmt = "{0,-22} {1,-20} {2,-18} {3,-15} {4,-22} {5,-10} {6,-25}"
Write-Host ($fmt -f "VM Name", "Key Name", "Active Version", "Vault", "Last Rotated", "Versions", "Status") -ForegroundColor White
Write-Host ($fmt -f ("-" * 22), ("-" * 20), ("-" * 18), ("-" * 15), ("-" * 22), ("-" * 10), ("-" * 25)) -ForegroundColor White

foreach ($row in $results) {
    $line = "{0,-22} {1,-20} {2,-18} {3,-15} {4,-22} {5,-10} " -f `
        $row.VMName, $row.KeyName, $row.ActiveVersion, $row.VaultName, $row.ActiveCreated, $row.TotalVersions

    Write-Host $line -NoNewline
    if ($row.RotationStatusClean -eq "ROTATED") {
        Write-Host ("{0,-25}" -f $row.RotationStatus) -ForegroundColor Green
    }
    else {
        Write-Host ("{0,-25}" -f $row.RotationStatus) -ForegroundColor DarkYellow
    }
}

# Show previous version details for rotated keys
$rotatedKeys = $results | Where-Object { $_.RotationStatusClean -eq "ROTATED" }
if ($rotatedKeys.Count -gt 0) {
    Write-Host ""
    Write-Host "Rotation History (most recent rotation):" -ForegroundColor Cyan
    $fmt2 = "  {0,-22} {1,-18} {2,-22} {3,-18} {4,-22}"
    Write-Host ($fmt2 -f "VM Name", "Current Version", "Current Created", "Previous Version", "Previous Created") -ForegroundColor White
    Write-Host ($fmt2 -f ("-" * 22), ("-" * 18), ("-" * 22), ("-" * 18), ("-" * 22)) -ForegroundColor White
    foreach ($row in $rotatedKeys) {
        Write-Host ($fmt2 -f $row.VMName, $row.ActiveVersion, $row.ActiveCreated, $row.PreviousVersion, $row.PreviousCreated) -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Total CVMs with CMK: $($results.Count) | Rotated: $($rotatedKeys.Count) | Never Rotated: $($results.Count - $rotatedKeys.Count)" -ForegroundColor Cyan

# CSV export
if ($Csv) {
    $csvResults = $results | Select-Object VMName, DESName, VaultName, KeyName, ActiveVersionFull, ActiveCreated, @{
        Name = 'PreviousVersionFull'; Expression = {
            if ($_.PreviousVersion -ne "N/A") {
                # Re-fetch full previous version from the ActiveVersionFull pattern
                $_.PreviousVersion
            } else { "N/A" }
        }
    }, PreviousCreated, TotalVersions, RotationStatusClean

    try {
        $csvResults | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to: $Csv" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV to '$Csv': $_"
    }
}
