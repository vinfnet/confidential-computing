[CmdletBinding()]
param(
    [ValidatePattern('^[a-z][a-z0-9]{2,7}$')]
    [string]$Prefix = 'demo',

    [string]$Location = 'northeurope',

    [string]$SubscriptionId,

    [string]$VmSize = 'Standard_DC2as_v5',

    [switch]$BootstrapOnly,

    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$templateFile = Join-Path $scriptDirectory 'main.bicep'
$bootstrapFile = Join-Path $scriptDirectory 'bootstrap-cvm.sh'
$configFile = Join-Path $scriptDirectory '.private-cvm.json'
$resourceGroupName = "$Prefix-private-cvm-rg"
$sshDirectory = Join-Path $scriptDirectory '.ssh'
$sshPrivateKey = Join-Path $sshDirectory "$Prefix-private-cvm"
$storageSftpPrivateKey = Join-Path $sshDirectory "$Prefix-storage-sftp"

function Invoke-AzCli {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = & az @Arguments --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($output -join [Environment]::NewLine)
    }
    return $output
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required. Install it, then run az login.'
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $SubscriptionId = (Invoke-AzCli @('account', 'show', '--query', 'id', '--output', 'tsv') | Out-String).Trim()
}

if ($Cleanup) {
    Invoke-AzCli @('account', 'set', '--subscription', $SubscriptionId) | Out-Null
    Invoke-AzCli @('group', 'delete', '--name', $resourceGroupName, '--yes', '--no-wait') | Out-Null
    Remove-Item $configFile -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $sshDirectory "$Prefix-*") -Force -ErrorAction SilentlyContinue
    Write-Host "Deletion started for $resourceGroupName."
    return
}

if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH ssh-keygen is required.'
}

$maaEndpoints = @{
    eastus = 'sharedeus.eus.attest.azure.net'
    eastus2 = 'sharedeus2.eus2.attest.azure.net'
    westus2 = 'sharedwus2.wus2.attest.azure.net'
    westus3 = 'sharedwus3.wus3.attest.azure.net'
    centralus = 'sharedcus.cus.attest.azure.net'
    canadacentral = 'sharedcac.cac.attest.azure.net'
    northeurope = 'sharedneu.neu.attest.azure.net'
    westeurope = 'sharedweu.weu.attest.azure.net'
    uksouth = 'shareduks.uks.attest.azure.net'
    francecentral = 'sharedfrc.frc.attest.azure.net'
    swedencentral = 'sharedsec.sec.attest.azure.net'
    southeastasia = 'sharedsasia.sasia.attest.azure.net'
    japaneast = 'sharedjpe.jpe.attest.azure.net'
    australiaeast = 'sharedeau.eau.attest.azure.net'
}
$maaEndpoint = $maaEndpoints[$Location.ToLowerInvariant()]
if (-not $maaEndpoint) {
    throw "No shared MAA endpoint is configured for $Location. Add the region mapping before deploying."
}

Invoke-AzCli @('account', 'set', '--subscription', $SubscriptionId) | Out-Null
$account = (Invoke-AzCli @('account', 'show', '--output', 'json') | Out-String | ConvertFrom-Json)
if ($account.user.type -ne 'user') {
    throw 'This demo expects an interactive user login so it can grant that user the negative-test role.'
}
$operatorObjectId = (Invoke-AzCli @('ad', 'signed-in-user', 'show', '--query', 'id', '--output', 'tsv') | Out-String).Trim()
$cvmOrchestratorObjectId = (Invoke-AzCli @(
    'ad', 'sp', 'show',
    '--id', 'bf7b6499-ff71-4aa2-97a4-f372087be7f0',
    '--query', 'id',
    '--output', 'tsv'
) | Out-String).Trim()

Invoke-AzCli @('group', 'create', '--name', $resourceGroupName, '--location', $Location, '--output', 'none') | Out-Null

New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null
if (-not (Test-Path $sshPrivateKey)) {
    & ssh-keygen -t rsa -b 4096 -f $sshPrivateKey -N '' -q
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed.' }
}
$sshPublicKey = (Get-Content "$sshPrivateKey.pub" -Raw).Trim()
if (-not (Test-Path $storageSftpPrivateKey)) {
    & ssh-keygen -t rsa -b 3072 -m PEM -f $storageSftpPrivateKey -N '' -q
    if ($LASTEXITCODE -ne 0) { throw 'Storage SFTP ssh-keygen failed.' }
}
$storageSftpPublicKey = (Get-Content "$storageSftpPrivateKey.pub" -Raw).Trim()
$storageSftpPrivateKeyBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($storageSftpPrivateKey))

function Invoke-TemplateDeployment {
    param(
        [Parameter(Mandatory)][bool]$DeployKeys,
        [Parameter(Mandatory)][bool]$DeployVm,
        [Parameter(Mandatory)][bool]$DeployDataKey,
        [string]$ApplicationKeyVmId = ''
    )

    $existingDesPrincipalId = (az disk-encryption-set list `
        --resource-group $resourceGroupName `
        --subscription $SubscriptionId `
        --query '[0].identity.principalId' `
        --output tsv `
        --only-show-errors 2>$null | Out-String).Trim()

    $existingBastionName = (az network bastion list `
        --resource-group $resourceGroupName `
        --subscription $SubscriptionId `
        --query '[0].name' `
        --output tsv `
        --only-show-errors 2>$null | Out-String).Trim()
    $deployBastion = -not $DeployKeys -and -not $DeployVm -and -not $DeployDataKey -and [string]::IsNullOrWhiteSpace($existingBastionName)

    $arguments = @(
        'deployment', 'group', 'create',
        '--resource-group', $resourceGroupName,
        '--template-file', $templateFile,
        '--name', "private-cvm-$($DeployKeys.ToString().ToLowerInvariant())-$($DeployVm.ToString().ToLowerInvariant())-$($DeployDataKey.ToString().ToLowerInvariant())",
        '--parameters',
        "prefix=$Prefix",
        "location=$Location",
        "maaEndpoint=$maaEndpoint",
        "operatorObjectId=$operatorObjectId",
        "cvmOrchestratorObjectId=$cvmOrchestratorObjectId",
        "existingDesPrincipalId=$existingDesPrincipalId",
        "sshPublicKey=$sshPublicKey",
        "storageSftpPublicKey=$storageSftpPublicKey",
        "storageSftpPrivateKeyBase64=$storageSftpPrivateKeyBase64",
        "vmSize=$VmSize",
        "deployBastion=$($deployBastion.ToString().ToLowerInvariant())",
        "deployKeys=$($DeployKeys.ToString().ToLowerInvariant())",
        "deployDataKey=$($DeployDataKey.ToString().ToLowerInvariant())",
        "deployVm=$($DeployVm.ToString().ToLowerInvariant())"
    )
    if (-not [string]::IsNullOrWhiteSpace($ApplicationKeyVmId)) {
        $arguments += "applicationKeyVmId=$ApplicationKeyVmId"
    }
    $arguments += @('--output', 'json')
    return (Invoke-AzCli $arguments | Out-String | ConvertFrom-Json)
}

function Invoke-DeploymentWithRetry {
    param(
        [Parameter(Mandatory)][bool]$DeployKeys,
        [Parameter(Mandatory)][bool]$DeployVm,
        [Parameter(Mandatory)][bool]$DeployDataKey,
        [string]$ApplicationKeyVmId = '',
        [int]$Attempts = 6
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            return Invoke-TemplateDeployment `
                -DeployKeys $DeployKeys `
                -DeployVm $DeployVm `
                -DeployDataKey $DeployDataKey `
                -ApplicationKeyVmId $ApplicationKeyVmId
        }
        catch {
            if ($attempt -eq $Attempts) { throw }
            Write-Warning "Deployment pass failed while resource dependencies propagate (attempt $attempt/$Attempts): $($_.Exception.Message)"
            Start-Sleep -Seconds 20
        }
    }
}

function Confirm-ApplicationKeyVmIdPolicy {
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$KeyName,
        [Parameter(Mandatory)][string]$ExpectedVmId
    )

    $keyResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName/keys/$KeyName"
    $encodedPolicy = (Invoke-AzCli @(
        'resource', 'show',
        '--ids', $keyResourceId,
        '--api-version', '2024-11-01',
        '--query', 'properties.release_policy.data',
        '--output', 'tsv'
    ) | Out-String).Trim()
    $base64 = $encodedPolicy.Replace('-', '+').Replace('_', '/')
    $base64 += '=' * ((4 - $base64.Length % 4) % 4)
    $policy = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64)) | ConvertFrom-Json
    $vmIdClaim = $policy.anyOf[0].allOf | Where-Object claim -EQ 'x-ms-azurevm-vmid' | Select-Object -First 1
    if (-not $vmIdClaim -or $vmIdClaim.equals -cne $ExpectedVmId) {
        throw "Application key release policy is not bound to VMID $ExpectedVmId."
    }
    Write-Host "Application key release policy is bound to VMID $ExpectedVmId"
}

if ($BootstrapOnly) {
    $vmName = (Invoke-AzCli @('vm', 'list', '--resource-group', $resourceGroupName, '--query', '[0].name', '--output', 'tsv') | Out-String).Trim()
    if (-not $vmName) { throw "No VM exists in $resourceGroupName." }
    $identityClientId = (Invoke-AzCli @('identity', 'list', '--resource-group', $resourceGroupName, '--query', '[0].clientId', '--output', 'tsv') | Out-String).Trim()
    $keyVaultName = (Invoke-AzCli @('keyvault', 'list', '--resource-group', $resourceGroupName, '--query', '[0].name', '--output', 'tsv') | Out-String).Trim()
    $storageAccountName = (Invoke-AzCli @('storage', 'account', 'list', '--resource-group', $resourceGroupName, '--query', '[0].name', '--output', 'tsv') | Out-String).Trim()
    $vmId = (Invoke-AzCli @('vm', 'show', '--resource-group', $resourceGroupName, '--name', $vmName, '--query', 'id', '--output', 'tsv') | Out-String).Trim()
    $outputs = [pscustomobject]@{
        bastionName = [pscustomobject]@{ value = ($vmName -replace '-cvm$', '-bastion') }
        cvmName = [pscustomobject]@{ value = $vmName }
        cvmId = [pscustomobject]@{ value = $vmId }
        keyVaultName = [pscustomobject]@{ value = $keyVaultName }
        storageAccountName = [pscustomobject]@{ value = $storageAccountName }
        encryptedContainerName = [pscustomobject]@{ value = 'encrypted-data' }
        dataKeyName = [pscustomobject]@{ value = 'private-data-key' }
        cvmIdentityClientId = [pscustomobject]@{ value = $identityClientId }
        maaEndpoint = [pscustomobject]@{ value = $maaEndpoint }
        storageSftpKeySecretName = [pscustomobject]@{ value = 'storage-sftp-private-key' }
        storageSftpUserName = [pscustomobject]@{ value = 'cvmdata' }
        logAnalyticsName = [pscustomobject]@{ value = ($vmName -replace '-cvm$', '-logs') }
    }
}
else {
    Write-Host 'Pass 1/4: private network, Bastion, identity, Key Vault, Storage, and access policies'
    Invoke-DeploymentWithRetry -DeployKeys $false -DeployVm $false -DeployDataKey $false | Out-Null

    Write-Host 'Pass 2/4: confidential disk HSM key and disk encryption set'
    Invoke-DeploymentWithRetry -DeployKeys $true -DeployVm $false -DeployDataKey $false | Out-Null

    Write-Host 'Pass 3/4: confidential VM with no public IP'
    $deployment = Invoke-DeploymentWithRetry -DeployKeys $true -DeployVm $true -DeployDataKey $false
    $outputs = $deployment.properties.outputs
}

$applicationKeyVmId = (Invoke-AzCli @(
    'vm', 'show',
    '--resource-group', $resourceGroupName,
    '--name', $outputs.cvmName.value,
    '--query', 'vmId',
    '--output', 'tsv'
) | Out-String).Trim().ToUpperInvariant()
if ([string]::IsNullOrWhiteSpace($applicationKeyVmId)) {
    throw 'Azure did not return a VMID for the confidential VM.'
}
$applicationKeyName = "private-data-key-$($applicationKeyVmId.Replace('-', '').ToLowerInvariant().Substring(0, 12))"
$outputs.dataKeyName.value = $applicationKeyName

if (-not $BootstrapOnly) {
    Write-Host "Pass 4/4: application HSM key bound to VMID $applicationKeyVmId"
    Invoke-DeploymentWithRetry `
        -DeployKeys $false `
        -DeployVm $false `
        -DeployDataKey $true `
        -ApplicationKeyVmId $applicationKeyVmId | Out-Null
}
Confirm-ApplicationKeyVmIdPolicy `
    -VaultName $outputs.keyVaultName.value `
    -KeyName $outputs.dataKeyName.value `
    -ExpectedVmId $applicationKeyVmId

Write-Host 'Waiting for the CVM to reach PowerState/running'
Invoke-AzCli @(
    'vm', 'start',
    '--resource-group', $resourceGroupName,
    '--name', $outputs.cvmName.value,
    '--no-wait'
) | Out-Null
for ($attempt = 1; $attempt -le 30; $attempt++) {
    $powerState = (Invoke-AzCli @(
        'vm', 'get-instance-view',
        '--resource-group', $resourceGroupName,
        '--name', $outputs.cvmName.value,
        '--query', "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]",
        '--output', 'tsv'
    ) | Out-String).Trim()
    if ($powerState -eq 'PowerState/running') { break }
    if ($attempt -eq 30) { throw "CVM did not reach PowerState/running; last state: $powerState" }
    Start-Sleep -Seconds 10
}

Write-Host 'Installing and running the in-guest encrypt, attest, release, and decrypt flow'
$runCommandArguments = @(
    'vm', 'run-command', 'invoke',
    '--resource-group', $resourceGroupName,
    '--name', $outputs.cvmName.value,
    '--command-id', 'RunShellScript',
    '--scripts', "@$bootstrapFile",
    '--parameters',
    "keyVaultName=$($outputs.keyVaultName.value)",
    "storageAccountName=$($outputs.storageAccountName.value)",
    "containerName=$($outputs.encryptedContainerName.value)",
    "keyName=$($outputs.dataKeyName.value)",
    "storageSftpKeySecretName=$($outputs.storageSftpKeySecretName.value)",
    "storageSftpUserName=$($outputs.storageSftpUserName.value)",
    "identityClientId=$($outputs.cvmIdentityClientId.value)",
    "maaEndpoint=$($outputs.maaEndpoint.value)",
    "expectedVmId=$applicationKeyVmId",
    '--output', 'json'
)
$runResult = $null
for ($attempt = 1; $attempt -le 8; $attempt++) {
    try {
        Invoke-AzCli @(
            'vm', 'start',
            '--resource-group', $resourceGroupName,
            '--name', $outputs.cvmName.value
        ) | Out-Null
        $runResult = Invoke-AzCli $runCommandArguments | Out-String | ConvertFrom-Json
        break
    }
    catch {
        if ($attempt -eq 8) { throw }
        Write-Warning "Run Command was not ready (attempt $attempt/8): $($_.Exception.Message)"
        Start-Sleep -Seconds 30
    }
}
$runMessages = ($runResult.value | ForEach-Object { $_.message }) -join [Environment]::NewLine
Write-Host $runMessages
if ($runMessages -notmatch 'PRIVATE_CVM_DEMO_SUCCESS') {
    throw 'Guest bootstrap did not report PRIVATE_CVM_DEMO_SUCCESS.'
}

$configuration = [ordered]@{
    subscriptionId = $SubscriptionId
    resourceGroup = $resourceGroupName
    location = $Location
    bastionName = $outputs.bastionName.value
    cvmName = $outputs.cvmName.value
    cvmId = $outputs.cvmId.value
    keyVaultName = $outputs.keyVaultName.value
    keyName = $outputs.dataKeyName.value
    applicationKeyVmId = $applicationKeyVmId
    storageAccountName = $outputs.storageAccountName.value
    logAnalyticsName = $outputs.logAnalyticsName.value
    sshPrivateKey = $sshPrivateKey
}
$configuration | ConvertTo-Json | Set-Content -Path $configFile -Encoding utf8

Write-Host ''
Write-Host 'Deployment complete.' -ForegroundColor Green
Write-Host "Connect: az network bastion ssh --name $($configuration.bastionName) --resource-group $resourceGroupName --target-resource-id $($configuration.cvmId) --auth-type ssh-key --username azureuser --ssh-key `"$sshPrivateKey`""
Write-Host 'Inside the CVM: sudo /opt/private-cvm/run-demo decrypt'
Write-Host "Negative test: .\Test-NonConfidentialCaller.ps1 -VaultName $($configuration.keyVaultName) -KeyName $($configuration.keyName)"
Write-Host 'Cleanup: .\Deploy-PrivateCvm.ps1 -Cleanup'
