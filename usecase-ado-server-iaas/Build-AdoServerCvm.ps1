param(
    [Parameter(Mandatory = $true)]
    [string]$subsID,

    [Parameter(Mandatory = $true)]
    [string]$basename,

    [Parameter(Mandatory = $false)]
    [string]$region = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$vmsize = "Standard_DC8as_v5",

    [Parameter(Mandatory = $false)]
    [int]$ExtraDiskSizeGB = 1024,

    [Parameter(Mandatory = $false)]
    [string]$description = "ADO Server CVM use case",

    [Parameter(Mandatory = $false)]
    [switch]$NoInternetAccess,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSkuPreflight,

    # Skip VM build and jump straight to post-provisioning steps (data disk, format, Bastion)
    # against an existing CVM. Provide the resource group name of the already-deployed CVM.
    [Parameter(Mandatory = $false)]
    [string]$ExistingResourceGroup = ""
)

$ErrorActionPreference = "Stop"

function Invoke-AzCli {
    param(
        [string]$CommandText,
        [switch]$IgnoreExitCode
    )

    Write-Host "-> $CommandText" -ForegroundColor DarkGray
    $null = Invoke-Expression $CommandText
    if (-not $IgnoreExitCode -and $LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: $CommandText"
    }

    return $LASTEXITCODE
}

function Get-ResourceGroupFromBuildOutput {
    param([string[]]$BuildOutput)

    foreach ($line in $BuildOutput) {
        # Strip ANSI escape codes before matching (Write-Host adds colour sequences when captured via *>&1)
        $plain = $line -replace '\x1b\[[0-9;]*[mK]', ''
        if ($plain -match "Resources created in resource group:\s*(\S+)") {
            return $Matches[1]
        }
    }

    foreach ($line in $BuildOutput) {
        $plain = $line -replace '\x1b\[[0-9;]*[mK]', ''
        if ($plain -match "Building a Confidential Virtual Machine\S*\s+in\s+([a-z0-9-]+)\s+in\s+") {
            return $Matches[1]
        }
    }

    return $null
}

function Ensure-DataDiskFormattedAsS {
    param(
        [string]$ResourceGroupName,
        [string]$VmName,
        [int]$Lun,
        [int]$ExpectedSizeGB
    )

    $script = @"
`$ErrorActionPreference = 'Stop'
`$lun = $Lun
`$expectedBytes = $ExpectedSizeGB * 1GB
`$target = Get-Disk | Where-Object {
    (`$_.Location -match "LUN `$lun") -or (`$_.PartitionStyle -eq 'RAW' -and [math]::Abs(`$_.Size - `$expectedBytes) -lt 5GB)
} | Sort-Object Number | Select-Object -First 1

if (-not `$target) {
    throw "Could not locate attached data disk for LUN `$lun"
}

if (`$target.IsOffline) {
    Set-Disk -Number `$target.Number -IsOffline `$false
}

if (`$target.IsReadOnly) {
    Set-Disk -Number `$target.Number -IsReadOnly `$false
}

if (`$target.PartitionStyle -eq 'RAW') {
    Initialize-Disk -Number `$target.Number -PartitionStyle GPT
}

`$partitions = Get-Partition -DiskNumber `$target.Number -ErrorAction SilentlyContinue
`$partition = `$partitions | Where-Object { `$_.Type -ne 'Reserved' } | Sort-Object Size -Descending | Select-Object -First 1

if (-not `$partition) {
    # A fresh GPT disk can contain only an MSR partition; create a usable primary partition.
    `$partition = New-Partition -DiskNumber `$target.Number -UseMaximumSize
}

`$mountedS = Get-Volume -DriveLetter S -ErrorAction SilentlyContinue
if (`$mountedS) {
    if (`$mountedS.FileSystem -ne 'NTFS' -or `$mountedS.FileSystemLabel -ne 'DATA') {
        Format-Volume -DriveLetter S -FileSystem NTFS -NewFileSystemLabel 'DATA' -Confirm:`$false -Force | Out-Null
    }
    Write-Host "Drive S already exists. Label=`$(`$mountedS.FileSystemLabel)"
    exit 0
}

if (`$partition.DriveLetter -ne 'S') {
    Set-Partition -DiskNumber `$target.Number -PartitionNumber `$partition.PartitionNumber -NewDriveLetter S
}

Format-Volume -DriveLetter S -FileSystem NTFS -NewFileSystemLabel 'DATA' -Confirm:`$false -Force | Out-Null
Write-Host "Disk initialized and mounted as S: with label DATA"
"@

    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -Name $VmName -CommandId "RunPowerShellScript" -ScriptString $script | Out-Null
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$buildRandomCvmScript = Join-Path $repoRoot "vm-samples\BuildRandomCVM.ps1"

if ($ExistingResourceGroup) {
    Write-Host "=== Step 1/4: Skipping VM build — using existing resource group: $ExistingResourceGroup ===" -ForegroundColor Yellow
    $resourceGroupName = $ExistingResourceGroup
} else {
    # Enforce one-CVM-at-a-time for this basename to avoid quota churn from parallel/leftover runs.
    $existingVms = Get-AzVM -Status -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match ("^" + [regex]::Escape($basename) + "[a-z0-9]{5}$") }
    if ($existingVms) {
        $existingList = ($existingVms | ForEach-Object { "$($_.ResourceGroupName)/$($_.Name)" }) -join ", "
        throw "Found existing VM deployment(s) for basename '$basename': $existingList. Delete existing resources first, or rerun with -ExistingResourceGroup to continue post-provisioning for one existing deployment."
    }

    if (-not (Test-Path $buildRandomCvmScript)) {
        throw "Required script not found: $buildRandomCvmScript"
    }

    Write-Host "=== Step 1/4: Build Windows CVM using existing vm-samples/BuildRandomCVM.ps1 ===" -ForegroundColor Cyan

    $buildArgs = @{
        subsID = $subsID
        basename = $basename
        osType = "Windows"
        region = $region
        vmsize = $vmsize
        description = $description
        DisableBastion = $true
    }

    if ($NoInternetAccess) { $buildArgs.NoInternetAccess = $true }
    if ($SkipSkuPreflight) { $buildArgs.SkipSkuPreflight = $true }

    $buildOutput = @()
    try {
        & $buildRandomCvmScript @buildArgs *>&1 | ForEach-Object {
            $line = "$_"
            $buildOutput += $line
            Write-Host $line
        }
    } catch {
        throw "Base VM deployment script failed. See output above. Error: $($_.Exception.Message)"
    }

    $resourceGroupName = Get-ResourceGroupFromBuildOutput -BuildOutput $buildOutput
    if (-not $resourceGroupName) {
        # Fallback: find the resource group that was just created for this basename in the target region
        Write-Host "Warning: Could not parse resource group from build output; querying Azure for recently created groups..." -ForegroundColor Yellow
        $resourceGroupName = (Get-AzResourceGroup -Location $region -ErrorAction SilentlyContinue |
            Where-Object { $_.ResourceGroupName -match "^$basename[a-z0-9]{4,8}$" -and $_.ProvisioningState -eq 'Succeeded' } |
            Sort-Object { $_.Tags['CreatedAt'] } -Descending |
            Select-Object -First 1).ResourceGroupName
        if (-not $resourceGroupName) {
            throw "Could not determine resource group name from BuildRandomCVM output or Azure query."
        }
    }
}

$vmName = $resourceGroupName
Write-Host "Detected resource group: $resourceGroupName" -ForegroundColor Green
Write-Host "Detected VM name: $vmName" -ForegroundColor Green

Write-Host "=== Step 2/4: Create and attach 1TB CMK-protected data disk ===" -ForegroundColor Cyan

$dataDesName = "$vmName-data-des"
$dataDes = Get-AzDiskEncryptionSet -ResourceGroupName $resourceGroupName -Name $dataDesName -ErrorAction SilentlyContinue

if (-not $dataDes) {
    $kvName = "$vmName" + "akv"
    $keyName = "$vmName-cmk-key"
    $kv = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $resourceGroupName
    $key = Get-AzKeyVaultKey -VaultName $kvName -KeyName $keyName

    # Use a separate DES for data disk CMK to avoid EncryptionType mismatch with CVM OS disk DES.
    $dataDesConfig = New-AzDiskEncryptionSetConfig -Location $region -SourceVaultId $kv.ResourceId -KeyUrl $key.Key.Kid -IdentityType SystemAssigned -EncryptionType EncryptionAtRestWithCustomerKey
    New-AzDiskEncryptionSet -ResourceGroupName $resourceGroupName -Name $dataDesName -DiskEncryptionSet $dataDesConfig | Out-Null
    $dataDes = Get-AzDiskEncryptionSet -ResourceGroupName $resourceGroupName -Name $dataDesName
    Set-AzKeyVaultAccessPolicy -VaultName $kvName -ResourceGroupName $resourceGroupName -ObjectId $dataDes.Identity.PrincipalId -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation | Out-Null
}

$vm = Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName
$existingDataDisk = $vm.StorageProfile.DataDisks | Where-Object { $_.DiskSizeGB -eq $ExtraDiskSizeGB } | Select-Object -First 1

if (-not $existingDataDisk) {
    $diskName = "$vmName-data-$ExtraDiskSizeGB-gb"
    $existingDisk = Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $diskName -ErrorAction SilentlyContinue

    if (-not $existingDisk) {
        $diskConfig = New-AzDiskConfig -Location $region -CreateOption Empty -DiskSizeGB $ExtraDiskSizeGB -SkuName "StandardSSD_LRS" -DiskEncryptionSetId $dataDes.Id
        $existingDisk = New-AzDisk -ResourceGroupName $resourceGroupName -DiskName $diskName -Disk $diskConfig
    }

    $nextLun = 0
    if ($vm.StorageProfile.DataDisks.Count -gt 0) {
        $nextLun = (($vm.StorageProfile.DataDisks | Measure-Object -Property Lun -Maximum).Maximum + 1)
    }

    $vm = Add-AzVMDataDisk -VM $vm -Name $existingDisk.Name -ManagedDiskId $existingDisk.Id -Lun $nextLun -CreateOption Attach -Caching ReadWrite
    Update-AzVM -ResourceGroupName $resourceGroupName -VM $vm | Out-Null
    $attachedLun = $nextLun
    Write-Host "Attached disk '$diskName' at LUN $attachedLun" -ForegroundColor Green
} else {
    $attachedLun = $existingDataDisk.Lun
    Write-Host "A $ExtraDiskSizeGB GB data disk is already attached at LUN $attachedLun" -ForegroundColor Yellow
}

Write-Host "=== Step 3/4: Format disk in guest as S: drive labeled DATA ===" -ForegroundColor Cyan
Ensure-DataDiskFormattedAsS -ResourceGroupName $resourceGroupName -VmName $vmName -Lun $attachedLun -ExpectedSizeGB $ExtraDiskSizeGB

Write-Host "=== Step 4/4: Create/upgrade Bastion to Standard with native client support ===" -ForegroundColor Cyan

$vnetName = "$vmName" + "vnet"
$bastionName = "$vnetName-bastion"
$bastionPipName = "$vnetName-bastion-pip"

$vnet = Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name $vnetName
$bastionSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "AzureBastionSubnet" } | Select-Object -First 1
if (-not $bastionSubnet) {
    Add-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -VirtualNetwork $vnet -AddressPrefix "10.0.99.0/26" | Set-AzVirtualNetwork | Out-Null
}

Invoke-AzCli "az network public-ip show --resource-group $resourceGroupName --name $bastionPipName --only-show-errors --output none" -IgnoreExitCode | Out-Null
if ($LASTEXITCODE -ne 0) {
    Invoke-AzCli "az network public-ip create --resource-group $resourceGroupName --name $bastionPipName --sku Standard --allocation-method Static --location $region --only-show-errors --output none"
}

Invoke-AzCli "az network bastion show --resource-group $resourceGroupName --name $bastionName --only-show-errors --output none" -IgnoreExitCode | Out-Null
if ($LASTEXITCODE -eq 0) {
    Invoke-AzCli "az network bastion update --resource-group $resourceGroupName --name $bastionName --sku Standard --enable-tunneling true --enable-ip-connect true --only-show-errors --output none"
} else {
    Invoke-AzCli "az network bastion create --resource-group $resourceGroupName --name $bastionName --public-ip-address $bastionPipName --vnet-name $vnetName --sku Standard --enable-tunneling true --enable-ip-connect true --only-show-errors --output none"
}

$vmId = (Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName).Id
Write-Host "" 
Write-Host "Build complete." -ForegroundColor Green
Write-Host "Resource Group: $resourceGroupName"
Write-Host "VM Name: $vmName"
Write-Host "Bastion Name: $bastionName"
Write-Host "Native RDP command:" -ForegroundColor Cyan
Write-Host "az network bastion rdp --name $bastionName --resource-group $resourceGroupName --target-resource-id $vmId --configure" -ForegroundColor Gray
