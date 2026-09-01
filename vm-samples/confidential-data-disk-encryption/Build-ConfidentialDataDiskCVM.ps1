<#
.SYNOPSIS
Creates a Linux or Windows confidential VM with confidential disk encryption.

.DESCRIPTION
Creates a private CVM with no public IP address assigned to its NIC. The VM uses
confidential OS disk encryption (DiskWithVMGuestState), and its data disk uses
Confidential Data Disk Encryption (CDE), a customer-managed RSA-HSM key, Secure
Key Release, and a confidential Disk Encryption Set.

The VM subnet uses a NAT Gateway for outbound access required by Azure VM Agent
and the CDE extension. Azure Bastion provides remote access. Neither public IP
address is assigned to the VM NIC.

CDE is a gated preview. The subscription must have
Microsoft.Compute/ConfidentialVMDataDiskEncryptionPreview registered, and the
selected region must support the feature.

.EXAMPLE
./Build-ConfidentialDataDiskCVM.ps1 `
    -SubscriptionId '<subscription-id>' `
    -Linux `
    -SshPublicKeyPath ~/.ssh/id_rsa.pub

.EXAMPLE
./Build-ConfidentialDataDiskCVM.ps1 `
    -SubscriptionId '<subscription-id>' `
    -Windows

.NOTES
References:
https://learn.microsoft.com/azure/confidential-computing/confidential-vm-overview
https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview
https://learn.microsoft.com/azure/confidential-computing/concept-skr-attestation
#>

[CmdletBinding(DefaultParameterSetName = 'Linux')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory, ParameterSetName = 'Linux')]
    [switch]$Linux,

    [Parameter(Mandatory, ParameterSetName = 'Windows')]
    [switch]$Windows,

    [Parameter()]
    [ValidatePattern('^[a-z][a-z0-9]{1,9}$')]
    [string]$Prefix = 'sgall',

    [Parameter()]
    [ValidatePattern('^[a-z][a-z0-9]{2,14}$')]
    [string]$BaseName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'northeurope',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$VmSize = 'Standard_DC2ads_v5',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdminUsername = 'azureuser',

    [Parameter(ParameterSetName = 'Linux')]
    [ValidateNotNullOrEmpty()]
    [string]$SshPublicKeyPath = '~/.ssh/id_rsa.pub',

    [Parameter()]
    [ValidateRange(4, 32767)]
    [int]$DataDiskSizeGB = 32,

    [Parameter()]
    [ValidateRange(0, 63)]
    [int]$DataDiskLun = 0,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyPath = (Join-Path $PSScriptRoot 'cdde-preview/DataDiskSKRPolicy.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$computeApiVersion = '2026-03-01'
$linuxImage = 'Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest'
$windowsImage = 'MicrosoftWindowsServer:WindowsServer2022:2022-datacenter-smalldisk-g2:latest'
$deployLinux = $PSCmdlet.ParameterSetName -eq 'Linux'
$vmImage = if ($deployLinux) { $linuxImage } else { $windowsImage }
$extensionName = if ($deployLinux) { 'CDELinux' } else { 'CDEWindows' }
$adminPassword = $null

function Invoke-AzCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Arguments
    )

    Write-Verbose "az $($Arguments -join ' ')"
    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed (exit $LASTEXITCODE): az $($Arguments -join ' ')`n$($output -join "`n")"
    }

    return ($output -join "`n").Trim()
}

function Invoke-AzCliJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Arguments
    )

    $json = Invoke-AzCli -Arguments ($Arguments + @('--only-show-errors', '--output', 'json'))
    if ([string]::IsNullOrWhiteSpace($json)) {
        return $null
    }

    return $json | ConvertFrom-Json -Depth 100
}

function Wait-AzCliOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Attempts = 12,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$DelaySeconds = 10
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            return & $Operation
        }
        catch {
            if ($attempt -eq $Attempts) {
                throw
            }

            Write-Warning "$Description failed on attempt $attempt of $Attempts. Waiting $DelaySeconds seconds for Azure RBAC propagation. $($_.Exception.Message)"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Set-RoleAssignmentIfMissing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalId,

        [Parameter(Mandatory)]
        [string]$PrincipalType,

        [Parameter(Mandatory)]
        [string]$Role,

        [Parameter(Mandatory)]
        [string]$Scope
    )

    $existing = Invoke-AzCli -Arguments @(
        'role', 'assignment', 'list',
        '--subscription', $SubscriptionId,
        '--assignee-object-id', $PrincipalId,
        '--scope', $Scope,
        '--query', "[?roleDefinitionName=='$Role'].id | [0]",
        '--only-show-errors', '--output', 'tsv'
    )

    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        Write-Host "Role already assigned: $Role" -ForegroundColor DarkGray
        return
    }

    try {
        Invoke-AzCli -Arguments @(
            'role', 'assignment', 'create',
            '--subscription', $SubscriptionId,
            '--assignee-object-id', $PrincipalId,
            '--assignee-principal-type', $PrincipalType,
            '--role', $Role,
            '--scope', $Scope,
            '--only-show-errors', '--output', 'none'
        ) | Out-Null
    }
    catch {
        if (-not (Get-Command New-AzRoleAssignment -ErrorAction SilentlyContinue)) {
            throw
        }

        Write-Warning 'Azure CLI could not create the role assignment. Retrying with the Azure PowerShell authentication context.'
        $azContext = Get-AzContext
        if (-not $azContext -or $azContext.Subscription.Id -ne $SubscriptionId) {
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        }
        New-AzRoleAssignment -ObjectId $PrincipalId -RoleDefinitionName $Role -Scope $Scope -ErrorAction Stop | Out-Null
    }
}

function Test-RoleAssignmentWritePermission {
    $scope = "/subscriptions/$SubscriptionId"
    $permissions = Invoke-AzCliJson -Arguments @(
        'rest', '--method', 'get',
        '--url', "https://management.azure.com${scope}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    )

    foreach ($permission in $permissions.value) {
        $allowed = $permission.actions | Where-Object {
            $_ -eq '*' -or
            $_ -eq 'Microsoft.Authorization/*' -or
            $_ -eq 'Microsoft.Authorization/roleAssignments/*' -or
            $_ -eq 'Microsoft.Authorization/roleAssignments/write'
        }
        $denied = $permission.notActions | Where-Object {
            $_ -eq '*' -or
            $_ -eq 'Microsoft.Authorization/*' -or
            $_ -eq 'Microsoft.Authorization/roleAssignments/*' -or
            $_ -eq 'Microsoft.Authorization/roleAssignments/write'
        }
        if ($allowed -and -not $denied) {
            return $true
        }
    }

    return $false
}

function Enable-EligiblePimRole {
    $scope = "/subscriptions/$SubscriptionId"
    $ownerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    $userAccessAdministratorRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    $eligibilityUrl = "https://management.azure.com${scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=asTarget()"
    $eligible = (Invoke-AzCliJson -Arguments @('rest', '--method', 'get', '--url', $eligibilityUrl)).value
    $selected = $eligible | Where-Object {
        $_.properties.roleDefinitionId -match "/$ownerRoleId$"
    } | Select-Object -First 1
    if (-not $selected) {
        $selected = $eligible | Where-Object {
            $_.properties.roleDefinitionId -match "/$userAccessAdministratorRoleId$"
        } | Select-Object -First 1
    }
    if (-not $selected) {
        throw 'Role-assignment write access is required, but no eligible Owner or User Access Administrator PIM role was found.'
    }

    $roleName = if ($selected.properties.roleDefinitionId -match "/$ownerRoleId$") {
        'Owner'
    }
    else {
        'User Access Administrator'
    }
    $answer = Read-Host "$roleName PIM elevation is required to create Key Vault role assignments. Activate it for one hour? [Y/n]"
    if ($answer -and $answer -notmatch '^[Yy]') {
        throw 'PIM elevation was declined.'
    }

    $principalId = Invoke-AzCli -Arguments @(
        'ad', 'signed-in-user', 'show', '--query', 'id',
        '--only-show-errors', '--output', 'tsv'
    )
    $requestId = [guid]::NewGuid().ToString()
    $requestPath = Join-Path ([System.IO.Path]::GetTempPath()) "$requestId-pim.json"
    @{
        properties = @{
            principalId = $principalId
            roleDefinitionId = $selected.properties.roleDefinitionId
            requestType = 'SelfActivate'
            justification = 'Deploy a confidential data disk encryption sample VM'
            scheduleInfo = @{
                startDateTime = (Get-Date).ToUniversalTime().ToString('o')
                expiration = @{
                    type = 'AfterDuration'
                    duration = 'PT1H'
                }
            }
        }
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $requestPath -Encoding utf8

    try {
        $requestUrl = "https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${requestId}?api-version=2020-10-01"
        Invoke-AzCli -Arguments @(
            'rest', '--method', 'put', '--url', $requestUrl,
            '--headers', 'Content-Type=application/json', '--body', "@$requestPath",
            '--only-show-errors', '--output', 'none'
        ) | Out-Null
    }
    catch {
        if ($_.Exception.Message -notmatch 'RoleAssignmentExists') {
            throw
        }
        Write-Host "$roleName already has an activation request. Waiting for it to become effective..." -ForegroundColor Yellow
    }
    finally {
        Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
    }

    for ($attempt = 1; $attempt -le 24; $attempt++) {
        Invoke-AzCli -Arguments @(
            'account', 'get-access-token', '--subscription', $SubscriptionId,
            '--resource', 'https://management.azure.com/',
            '--only-show-errors', '--output', 'none'
        ) | Out-Null
        if (Test-RoleAssignmentWritePermission) {
            Write-Host "$roleName PIM elevation is active." -ForegroundColor Green
            return
        }
        Start-Sleep -Seconds 5
    }

    throw "$roleName PIM activation did not become effective within two minutes."
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required. Install it from https://learn.microsoft.com/cli/azure/install-azure-cli.'
}

$resolvedPolicyPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PolicyPath)
if (-not (Test-Path -LiteralPath $resolvedPolicyPath -PathType Leaf)) {
    throw "Secure Key Release policy not found: $resolvedPolicyPath"
}
if ((Get-Item -LiteralPath $resolvedPolicyPath).Length -eq 0) {
    throw "Secure Key Release policy is empty: $resolvedPolicyPath"
}

$resolvedSshKeyPath = $null
if ($deployLinux) {
    $resolvedSshKeyPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SshPublicKeyPath)
    if (-not (Test-Path -LiteralPath $resolvedSshKeyPath -PathType Leaf)) {
        throw "SSH public key not found: $resolvedSshKeyPath"
    }
}
else {
    $passwordCharacters = @()
    $passwordCharacters += 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray() | Get-Random -Count 4
    $passwordCharacters += 'abcdefghijkmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count 4
    $passwordCharacters += '23456789'.ToCharArray() | Get-Random -Count 4
    $passwordCharacters += '!@#%'.ToCharArray() | Get-Random -Count 4
    $passwordCharacters += 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray() | Get-Random -Count 20
    $adminPassword = -join ($passwordCharacters | Get-Random -Count $passwordCharacters.Count)
}

$account = Invoke-AzCliJson -Arguments @('account', 'show', '--subscription', $SubscriptionId)
if (-not $account -or $account.id -ne $SubscriptionId) {
    throw "Azure CLI is not signed in to subscription $SubscriptionId. Run az login first."
}

Write-Host 'Checking permission to create required role assignments...' -ForegroundColor Cyan
if (-not (Test-RoleAssignmentWritePermission)) {
    Enable-EligiblePimRole
}
else {
    Write-Host 'Required role-assignment permission is already active.' -ForegroundColor Green
}

if ([string]::IsNullOrWhiteSpace($BaseName)) {
    $randomSuffix = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $BaseName = "$Prefix$randomSuffix"
}
if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    $ResourceGroupName = "$BaseName-cdde-rg"
}

$vmName = "$BaseName-cvm"
$vnetName = "$BaseName-vnet"
$subnetName = "$BaseName-snet"
$nsgName = "$BaseName-nsg"
$nicName = "$BaseName-nic"
$natGatewayName = "$BaseName-nat"
$natPublicIpName = "$BaseName-nat-pip"
$bastionName = "$BaseName-bastion"
$bastionPublicIpName = "$BaseName-bastion-pip"
$vaultName = "$BaseName-kv"
$keyName = "$BaseName-cdde-key"
$desName = "$BaseName-cdde-des"
$identityName = "$BaseName-cdde-id"
$scriptName = $MyInvocation.MyCommand.Name

Write-Host 'Running CDE preflight checks...' -ForegroundColor Cyan

foreach ($provider in @('Microsoft.Compute', 'Microsoft.KeyVault', 'Microsoft.ManagedIdentity', 'Microsoft.Network')) {
    $state = Invoke-AzCli -Arguments @(
        'provider', 'show', '--subscription', $SubscriptionId,
        '--namespace', $provider, '--query', 'registrationState',
        '--only-show-errors', '--output', 'tsv'
    )
    if ($state -ne 'Registered') {
        Write-Host "Registering resource provider $provider..." -ForegroundColor Yellow
        Invoke-AzCli -Arguments @(
            'provider', 'register', '--subscription', $SubscriptionId,
            '--namespace', $provider, '--wait',
            '--only-show-errors', '--output', 'none'
        ) | Out-Null
    }
}

$featureState = Invoke-AzCli -Arguments @(
    'feature', 'show', '--subscription', $SubscriptionId,
    '--namespace', 'Microsoft.Compute',
    '--name', 'ConfidentialVMDataDiskEncryptionPreview',
    '--query', 'properties.state', '--only-show-errors', '--output', 'tsv'
)
if ($featureState -ne 'Registered') {
    throw "Microsoft.Compute/ConfidentialVMDataDiskEncryptionPreview is '$featureState'. Request preview access and register the feature before continuing."
}

$sku = Invoke-AzCliJson -Arguments @(
    'vm', 'list-skus', '--subscription', $SubscriptionId,
    '--location', $Location, '--resource-type', 'virtualMachines',
    '--size', $VmSize, '--all',
    '--query', "[?name=='$VmSize'] | [0]"
)
if (-not $sku) {
    throw "VM size $VmSize is not offered in $Location."
}
if ($sku.restrictions -and $sku.restrictions.Count -gt 0) {
    throw "VM size $VmSize is restricted in $Location for this subscription: $($sku.restrictions | ConvertTo-Json -Compress -Depth 20)"
}

Invoke-AzCliJson -Arguments @(
    'vm', 'image', 'show', '--subscription', $SubscriptionId,
    '--location', $Location, '--urn', $vmImage
) | Out-Null

$requiredVcpus = [int](($sku.capabilities | Where-Object name -eq 'vCPUs' | Select-Object -First 1).value)
$skuFamily = $sku.family
$familyUsage = Invoke-AzCliJson -Arguments @(
    'vm', 'list-usage', '--subscription', $SubscriptionId,
    '--location', $Location,
    '--query', "[?name.value=='$skuFamily'] | [0]"
)
if ($familyUsage) {
    $availableVcpus = [int]$familyUsage.limit - [int]$familyUsage.currentValue
    if ($availableVcpus -lt $requiredVcpus) {
        throw "Insufficient $skuFamily quota in $Location. Available: $availableVcpus vCPUs; required: $requiredVcpus."
    }
}

Write-Host "Creating resources in $ResourceGroupName ($Location)..." -ForegroundColor Cyan
$owner = $account.user.name
Invoke-AzCli -Arguments @(
    'group', 'create', '--subscription', $SubscriptionId,
    '--name', $ResourceGroupName, '--location', $Location,
    '--tags', "owner=$owner", "BuiltBy=$scriptName", 'Sample=ConfidentialDataDiskEncryption',
    '--only-show-errors', '--output', 'none'
) | Out-Null

Invoke-AzCli -Arguments @(
    'keyvault', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vaultName,
    '--location', $Location, '--sku', 'premium',
    '--enable-rbac-authorization', 'true',
    '--enable-purge-protection', 'true',
    '--only-show-errors', '--output', 'none'
) | Out-Null

$vaultId = Invoke-AzCli -Arguments @(
    'keyvault', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vaultName,
    '--query', 'id', '--only-show-errors', '--output', 'tsv'
)
$operatorObjectId = Invoke-AzCli -Arguments @(
    'ad', 'signed-in-user', 'show', '--query', 'id',
    '--only-show-errors', '--output', 'tsv'
)
Set-RoleAssignmentIfMissing -PrincipalId $operatorObjectId -PrincipalType 'User' -Role 'Key Vault Crypto Officer' -Scope $vaultId

Wait-AzCliOperation -Description 'RSA-HSM key creation' -Operation {
    Invoke-AzCli -Arguments @(
        'keyvault', 'key', 'create', '--subscription', $SubscriptionId,
        '--vault-name', $vaultName, '--name', $keyName,
        '--kty', 'RSA-HSM', '--size', '3072',
        '--ops', 'wrapKey', 'unwrapKey',
        '--exportable', 'true', '--policy', $resolvedPolicyPath,
        '--only-show-errors', '--output', 'none'
    ) | Out-Null
} | Out-Null

$keyUrl = Invoke-AzCli -Arguments @(
    'keyvault', 'key', 'show', '--subscription', $SubscriptionId,
    '--vault-name', $vaultName, '--name', $keyName,
    '--query', 'key.kid', '--only-show-errors', '--output', 'tsv'
)
$releasePolicy = Invoke-AzCli -Arguments @(
    'keyvault', 'key', 'show', '--subscription', $SubscriptionId,
    '--vault-name', $vaultName, '--name', $keyName,
    '--query', 'releasePolicy.encodedPolicy', '--only-show-errors', '--output', 'tsv'
)
if ([string]::IsNullOrWhiteSpace($releasePolicy)) {
    throw 'The key releasePolicy.encodedPolicy is empty. Verify the supplied CDE SKR policy.'
}

$identity = Invoke-AzCliJson -Arguments @(
    'identity', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $identityName,
    '--location', $Location
)
$uamiId = $identity.id
$uamiPrincipalId = $identity.principalId

Invoke-AzCli -Arguments @(
    'disk-encryption-set', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $desName,
    '--location', $Location, '--source-vault', $vaultId,
    '--key-url', $keyUrl,
    '--encryption-type', 'ConfidentialVmEncryptedWithCustomerKey',
    '--mi-system-assigned', '--only-show-errors', '--output', 'none'
) | Out-Null

$des = Invoke-AzCliJson -Arguments @(
    'disk-encryption-set', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $desName
)
$desId = $des.id
$desPrincipalId = $des.identity.principalId

Set-RoleAssignmentIfMissing -PrincipalId $desPrincipalId -PrincipalType 'ServicePrincipal' -Role 'Key Vault Crypto Service Encryption User' -Scope $vaultId
Set-RoleAssignmentIfMissing -PrincipalId $uamiPrincipalId -PrincipalType 'ServicePrincipal' -Role 'Key Vault Crypto Service Encryption User' -Scope $vaultId
Set-RoleAssignmentIfMissing -PrincipalId $uamiPrincipalId -PrincipalType 'ServicePrincipal' -Role 'Key Vault Crypto Service Release User' -Scope $vaultId

Write-Host 'Creating private networking (the VM NIC receives no public IP)...' -ForegroundColor Cyan
Invoke-AzCli -Arguments @(
    'network', 'nsg', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $nsgName,
    '--location', $Location, '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'vnet', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vnetName,
    '--location', $Location, '--address-prefixes', '10.20.0.0/16',
    '--subnet-name', $subnetName, '--subnet-prefixes', '10.20.0.0/24',
    '--network-security-group', $nsgName,
    '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'vnet', 'subnet', 'update', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--vnet-name', $vnetName,
    '--name', $subnetName, '--default-outbound-access', 'false',
    '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'public-ip', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $natPublicIpName,
    '--location', $Location, '--sku', 'Standard', '--allocation-method', 'Static',
    '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'nat', 'gateway', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $natGatewayName,
    '--location', $Location, '--public-ip-addresses', $natPublicIpName,
    '--idle-timeout', '10', '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'vnet', 'subnet', 'update', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--vnet-name', $vnetName,
    '--name', $subnetName, '--nat-gateway', $natGatewayName,
    '--default-outbound-access', 'false',
    '--only-show-errors', '--output', 'none'
) | Out-Null

$nic = Invoke-AzCliJson -Arguments @(
    'network', 'nic', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $nicName,
    '--location', $Location, '--vnet-name', $vnetName,
    '--subnet', $subnetName
)
$nicId = $nic.NewNIC.id
if (-not $nicId) {
    $nicId = $nic.id
}

Write-Host "Creating confidential VM $vmName..." -ForegroundColor Cyan
$vmCreateArguments = @(
    'vm', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vmName,
    '--location', $Location, '--image', $vmImage,
    '--size', $VmSize, '--admin-username', $AdminUsername,
    '--nics', $nicId, '--assign-identity', $uamiId,
    '--security-type', 'ConfidentialVM',
    '--enable-vtpm', 'true', '--enable-secure-boot', 'true',
    '--os-disk-security-encryption-type', 'DiskWithVMGuestState',
    '--only-show-errors', '--output', 'none'
)
if ($deployLinux) {
    $vmCreateArguments += @('--ssh-key-values', $resolvedSshKeyPath)
}
else {
    $vmCreateArguments += @('--admin-password', $adminPassword)
}
Wait-AzCliOperation -Description 'confidential VM creation' -Operation {
    Invoke-AzCli -Arguments $vmCreateArguments | Out-Null
} | Out-Null

$vmUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/${vmName}?api-version=$computeApiVersion"
$tempFiles = [System.Collections.Generic.List[string]]::new()
try {
    $identityBodyPath = Join-Path ([System.IO.Path]::GetTempPath()) "$BaseName-cde-identity.json"
    $tempFiles.Add($identityBodyPath)
    @{
        identity = @{
            type = 'UserAssigned'
            userAssignedIdentities = @{ $uamiId = @{} }
        }
        properties = @{
            securityProfile = @{
                securityType = 'ConfidentialVM'
                uefiSettings = @{
                    secureBootEnabled = $true
                    vTpmEnabled = $true
                }
                confidentialDataDiskEncryptionIdentity = @{
                    userAssignedIdentityResourceId = $uamiId
                }
            }
        }
    } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $identityBodyPath -Encoding utf8

    Invoke-AzCli -Arguments @(
        'rest', '--method', 'patch', '--url', $vmUri,
        '--headers', 'Content-Type=application/json',
        '--body', "@$identityBodyPath", '--only-show-errors', '--output', 'none'
    ) | Out-Null

    $dataDiskBodyPath = Join-Path ([System.IO.Path]::GetTempPath()) "$BaseName-cde-data-disk.json"
    $tempFiles.Add($dataDiskBodyPath)
    @{
        properties = @{
            storageProfile = @{
                dataDisks = @(
                    @{
                        lun = $DataDiskLun
                        createOption = 'Empty'
                        diskSizeGB = $DataDiskSizeGB
                        managedDisk = @{
                            storageAccountType = 'Premium_LRS'
                            securityProfile = @{
                                securityEncryptionType = 'DataDiskEncryptedWithCustomerKey'
                                diskEncryptionSet = @{ id = $desId }
                            }
                        }
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $dataDiskBodyPath -Encoding utf8

    Invoke-AzCli -Arguments @(
        'rest', '--method', 'patch', '--url', $vmUri,
        '--headers', 'Content-Type=application/json',
        '--body', "@$dataDiskBodyPath", '--only-show-errors', '--output', 'none'
    ) | Out-Null
}
finally {
    foreach ($tempFile in $tempFiles) {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

if ($deployLinux) {
    Write-Host 'Formatting and mounting the new data disk at /cde-data...' -ForegroundColor Cyan
    $guestCommandId = 'RunShellScript'
    $mountScript = @'
set -eu
target=/dev/disk/azure/scsi1/lun__DATA_DISK_LUN__
test -b "$target"
if lsblk -n -o FSTYPE "$target" | grep -q '[^[:space:]]'; then
    echo "Refusing to format $target because it already contains a filesystem." >&2
  exit 1
fi
mkfs.ext4 -F "$target"
mkdir -p /cde-data
mount "$target" /cde-data
lsblk -f
'@.Replace('__DATA_DISK_LUN__', [string]$DataDiskLun)
}
else {
    Write-Host 'Initializing and formatting the new data disk as NTFS...' -ForegroundColor Cyan
    $guestCommandId = 'RunPowerShellScript'
    $mountScript = @'
$rawDisks = @(Get-Disk | Where-Object {
    $_.PartitionStyle -eq 'RAW' -and
    -not $_.IsBoot -and
    -not $_.IsSystem -and
    $_.BusType -in @('SAS', 'SCSI')
})
if ($rawDisks.Count -ne 1) {
    throw "Expected exactly one raw Azure data disk, found $($rawDisks.Count)."
}
$rawDisks[0] |
    Initialize-Disk -PartitionStyle GPT -PassThru |
    New-Partition -AssignDriveLetter -UseMaximumSize |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel 'CDEData' -Confirm:$false
'@
}
$mountResult = Invoke-AzCliJson -Arguments @(
    'vm', 'run-command', 'invoke', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vmName,
    '--command-id', $guestCommandId, '--scripts', $mountScript
)
$mountMessage = $mountResult.value[0].message
if ($mountMessage -notmatch 'Enable succeeded') {
    throw "Guest data-disk initialization failed:`n$mountMessage"
}

Write-Host 'Installing the Confidential Data Disk Encryption extension...' -ForegroundColor Cyan
$extensionSettings = @{ sequenceVersion = [guid]::NewGuid().ToString() } | ConvertTo-Json -Compress
$extensionSettingsPath = Join-Path ([System.IO.Path]::GetTempPath()) "$BaseName-cde-extension.json"
try {
    Set-Content -LiteralPath $extensionSettingsPath -Value $extensionSettings -Encoding utf8
    Invoke-AzCli -Arguments @(
        'vm', 'extension', 'set', '--subscription', $SubscriptionId,
        '--resource-group', $ResourceGroupName, '--vm-name', $vmName,
        '--publisher', 'Microsoft.Azure.Security.ConfidentialDiskEncryption',
        '--name', $extensionName, '--version', '1.0',
        '--settings', "@$extensionSettingsPath",
        '--only-show-errors', '--output', 'none'
    ) | Out-Null
}
finally {
    Remove-Item -LiteralPath $extensionSettingsPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Creating Azure Bastion for private remote access...' -ForegroundColor Cyan
Invoke-AzCli -Arguments @(
    'network', 'vnet', 'subnet', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--vnet-name', $vnetName,
    '--name', 'AzureBastionSubnet', '--address-prefixes', '10.20.1.0/26',
    '--default-outbound-access', 'false',
    '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'public-ip', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $bastionPublicIpName,
    '--location', $Location, '--sku', 'Standard', '--allocation-method', 'Static',
    '--only-show-errors', '--output', 'none'
) | Out-Null
Invoke-AzCli -Arguments @(
    'network', 'bastion', 'create', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $bastionName,
    '--location', $Location, '--vnet-name', $vnetName,
    '--public-ip-address', $bastionPublicIpName, '--sku', 'Standard',
    '--enable-tunneling', 'true',
    '--only-show-errors', '--output', 'none'
) | Out-Null

$vm = Invoke-AzCliJson -Arguments @(
    'vm', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $vmName
)
$privateIp = Invoke-AzCli -Arguments @(
    'network', 'nic', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $nicName,
    '--query', 'ipConfigurations[0].privateIPAddress',
    '--only-show-errors', '--output', 'tsv'
)
$nicPublicIpId = Invoke-AzCli -Arguments @(
    'network', 'nic', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--name', $nicName,
    '--query', 'ipConfigurations[0].publicIPAddress.id',
    '--only-show-errors', '--output', 'tsv'
)
if (-not [string]::IsNullOrWhiteSpace($nicPublicIpId)) {
    throw "Safety check failed: VM NIC unexpectedly has public IP resource $nicPublicIpId."
}

$cdeIdentity = Invoke-AzCli -Arguments @(
    'rest', '--method', 'get', '--url', $vmUri,
    '--query', 'properties.securityProfile.confidentialDataDiskEncryptionIdentity.userAssignedIdentityResourceId',
    '--only-show-errors', '--output', 'tsv'
)
$dataDiskSecurity = Invoke-AzCliJson -Arguments @(
    'rest', '--method', 'get', '--url', $vmUri,
    '--query', "properties.storageProfile.dataDisks[?lun==``$DataDiskLun``].managedDisk.securityProfile | [0]"
)
$extension = Invoke-AzCliJson -Arguments @(
    'vm', 'extension', 'show', '--subscription', $SubscriptionId,
    '--resource-group', $ResourceGroupName, '--vm-name', $vmName,
    '--name', $extensionName, '--expand', 'instanceView'
)

Write-Host ''
Write-Host 'Deployment complete.' -ForegroundColor Green
Write-Host "Resource group:       $ResourceGroupName"
Write-Host "VM:                   $($vm.name)"
Write-Host "OS:                   $(if ($deployLinux) { 'Linux' } else { 'Windows' })"
Write-Host "Private IP:           $privateIp"
Write-Host 'VM public IP:         none'
Write-Host "Bastion:              $bastionName"
Write-Host "CDE identity:         $cdeIdentity"
Write-Host "Data disk protection: $($dataDiskSecurity.securityEncryptionType)"
Write-Host "CDE extension state:  $($extension.provisioningState)"
Write-Host ''
Write-Host 'Remote access credentials (save these now):' -ForegroundColor Yellow
Write-Host "Username:             $AdminUsername"
if ($deployLinux) {
    $sshPrivateKeyPath = $resolvedSshKeyPath -replace '\.pub$', ''
    Write-Host "SSH private key:      $sshPrivateKeyPath"
    Write-Host "Bastion SSH:          az network bastion ssh --subscription $SubscriptionId --name $bastionName --resource-group $ResourceGroupName --target-resource-id $($vm.id) --auth-type ssh-key --username $AdminUsername --ssh-key $sshPrivateKeyPath"
    Write-Host ''
    Write-Host 'CDE runs asynchronously in the guest. Verify LUKS/dm-crypt after the extension finishes:' -ForegroundColor Yellow
    Write-Host "az vm run-command invoke --subscription $SubscriptionId --resource-group $ResourceGroupName --name $vmName --command-id RunShellScript --scripts 'sudo lsblk -f; sudo cat /etc/crypttab; sudo dmsetup ls; findmnt /cde-data'"
}
else {
    Write-Host "Password:             $adminPassword"
    Write-Host "Bastion RDP:          az network bastion rdp --subscription $SubscriptionId --name $bastionName --resource-group $ResourceGroupName --target-resource-id $($vm.id)"
    Write-Host ''
    Write-Host 'Verify BitLocker after the CDE extension finishes:' -ForegroundColor Yellow
    Write-Host "az vm run-command invoke --subscription $SubscriptionId --resource-group $ResourceGroupName --name $vmName --command-id RunPowerShellScript --scripts 'Get-BitLockerVolume | Format-List MountPoint,VolumeType,ProtectionStatus,VolumeStatus,EncryptionPercentage'"
}
