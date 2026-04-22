# Secure Snake ACI demo
# Repeatable deployment script for Azure Container Registry + Azure Confidential ACI

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$Prefix = 'sgall',

    [Parameter(Mandatory = $false)]
    [string]$Region = 'eastus',

    [Parameter(Mandatory = $false)]
    [string]$DeploymentName,

    [Parameter(Mandatory = $false)]
    [string]$ImageTag = 'v1',

    [Parameter(Mandatory = $false)]
    [switch]$SkipImageBuild
)

$ErrorActionPreference = 'Stop'

$paramsPath = $null
$generatedTemplatePath = $null

function Write-Stage {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Get-RandomSuffix {
    param([int]$Length = 5)
    return (-join ((48..57) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ }))
}

function Test-RequiredCommand {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Test-DockerRunning {
    try {
        docker info 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw 'Docker returned a non-zero exit code.'
        }
    }
    catch {
        throw 'Docker must be installed and running because confcom uses the local Docker daemon to generate the CCE policy.'
    }
}

function Ensure-ConfcomExtension {
    $installed = az extension show --name confcom --query name -o tsv 2>$null
    if (-not $installed) {
        Write-Host 'Installing Azure CLI confcom extension...' -ForegroundColor Gray
        az extension add --name confcom --upgrade | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to install the Azure CLI confcom extension.'
        }
    }
}

function Ensure-AcrDockerLogin {
    param([string]$AcrName)

    Write-Host "Authenticating Docker to ACR '$AcrName'..." -ForegroundColor Gray
    az acr login --name $AcrName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to authenticate Docker to ACR '$AcrName'."
    }
}

function Ensure-UserAssignedIdentity {
    param(
        [string]$ResourceGroupName,
        [string]$IdentityName,
        [string]$Location
    )

    $identityJson = az identity show --resource-group $ResourceGroupName --name $IdentityName -o json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $identityJson) {
        Write-Host "Creating managed identity '$IdentityName'..." -ForegroundColor Gray
        $identityJson = az identity create --resource-group $ResourceGroupName --name $IdentityName --location $Location -o json 2>&1
        if ($LASTEXITCODE -ne 0 -or -not $identityJson) {
            Write-Warning "Managed identity creation was skipped: $($identityJson | Out-String)"
            return $null
        }
    }

    return ($identityJson | ConvertFrom-Json)
}

function Get-SharedMaaEndpoint {
    param([string]$Location)

    $maaEndpoints = @{
        'eastus'       = 'sharedeus.eus.attest.azure.net'
        'eastus2'      = 'sharedeus2.eus2.attest.azure.net'
        'westus'       = 'sharedwus.wus.attest.azure.net'
        'westus2'      = 'sharedwus2.wus2.attest.azure.net'
        'centralus'    = 'sharedcus.cus.attest.azure.net'
        'northeurope'  = 'sharedneu.neu.attest.azure.net'
        'westeurope'   = 'sharedweu.weu.attest.azure.net'
        'uksouth'      = 'shareduks.uks.attest.azure.net'
        'southeastasia'= 'sharedsea.sea.attest.azure.net'
        'japaneast'    = 'sharedjpe.jpe.attest.azure.net'
    }

    $key = $Location.ToLower()
    if ($maaEndpoints.ContainsKey($key)) {
        return $maaEndpoints[$key]
    }

    Write-Warning "No explicit shared MAA mapping found for '$Location'. Falling back to East US shared endpoint."
    return 'sharedeus.eus.attest.azure.net'
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-AcrImageDigest {
    param(
        [string]$AcrName,
        [string]$Repository,
        [string]$Tag
    )

    $digest = az acr repository show --name $AcrName --image "${Repository}:${Tag}" --query digest -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $digest) {
        throw "Failed to resolve a digest for ${Repository}:${Tag} in registry '$AcrName'."
    }

    return $digest.Trim()
}

function New-PolicyParameterFile {
    param(
        [string]$Path,
        [string]$ContainerGroupName,
        [string]$Location,
        [string]$DnsNameLabel,
        [string]$ContainerImage,
        [string]$RegistryServer,
        [string]$RegistryUsername,
        [string]$RegistryPassword,
        [int]$AppPort,
        [string]$ImageDigest,
        [string]$MaaEndpoint,
        [string]$IdentityResourceId,
        [string]$HardeningSummary
    )

    $params = @{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
        contentVersion = '1.0.0.0'
        parameters = @{
            containerGroupName = @{ value = $ContainerGroupName }
            location = @{ value = $Location }
            dnsNameLabel = @{ value = $DnsNameLabel }
            containerImage = @{ value = $ContainerImage }
            registryServer = @{ value = $RegistryServer }
            registryUsername = @{ value = $RegistryUsername }
            registryPassword = @{ value = $RegistryPassword }
            appPort = @{ value = $AppPort }
            imageDigest = @{ value = $ImageDigest }
            maaEndpoint = @{ value = $MaaEndpoint }
            identityResourceId = @{ value = $IdentityResourceId }
            policyMode = @{ value = 'confcom-generated-digest-pinned-stdio-disabled' }
            hardeningSummary = @{ value = $HardeningSummary }
        }
    }

    $params | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
}

function Get-PolicyInfoFromConfcom {
    param(
        [string]$TemplatePath,
        [string]$ParamsPath
    )

    $output = az confcom acipolicygen --template-file $TemplatePath --parameters $ParamsPath --disable-stdio --exclude-default-fragments --approve-wildcards 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host ($output | Out-String) -ForegroundColor DarkYellow
        throw 'Failed to generate the Confidential Container Enforcement policy with confcom.'
    }

    $template = Get-Content $TemplatePath -Raw | ConvertFrom-Json -Depth 100
    $ccePolicy = $template.resources[0].properties.confidentialComputeProperties.ccePolicy
    if (-not $ccePolicy) {
        throw 'confcom completed, but no ccePolicy was injected into the generated template.'
    }

    $hashLine = $output | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1
    if (-not $hashLine) {
        $hashLine = Get-Sha256Hex -Bytes ([System.Convert]::FromBase64String($ccePolicy))
    }

    return @{
        PolicyBase64 = $ccePolicy
        PolicyHash = $hashLine.Trim()
    }
}

function Ensure-ImageAvailableLocally {
    param(
        [string]$ImageRef,
        [int]$MaxAttempts = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Host "Pulling pinned image locally for confcom (attempt $attempt/$MaxAttempts)..." -ForegroundColor Gray
        docker pull $ImageRef
        if ($LASTEXITCODE -eq 0) {
            return
        }

        if ($attempt -lt $MaxAttempts) {
            Start-Sleep -Seconds (5 * $attempt)
        }
    }

    throw "Failed to pull pinned image '$ImageRef' locally after $MaxAttempts attempts."
}

try {
    Write-Stage 'Validating prerequisites'
    Test-RequiredCommand -Name 'az'
    Test-RequiredCommand -Name 'docker'
    Test-DockerRunning
    Ensure-ConfcomExtension

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        throw 'No Azure PowerShell session found. Run Connect-AzAccount first.'
    }

    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    az account set --subscription $SubscriptionId
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to set Azure CLI subscription context.'
    }

    if (-not $DeploymentName) {
        $suffix = Get-RandomSuffix -Length 5
        $DeploymentName = ($Prefix + $suffix).ToLower()
    }

    $baseName = $DeploymentName.ToLower()
    $resourceGroupName = $baseName
    $acrName = (($baseName + 'acr') -replace '[^a-z0-9]', '')
    if ($acrName.Length -gt 50) { $acrName = $acrName.Substring(0, 50) }
    $containerGroupName = "$baseName-snake"
    $dnsLabel = (($baseName + 'snake') -replace '[^a-z0-9-]', '')
    if ($dnsLabel.Length -gt 63) { $dnsLabel = $dnsLabel.Substring(0, 63).TrimEnd('-') }
    $imageName = 'secure-snake-aci'
    $imageRef = "${acrName}.azurecr.io/${imageName}:${ImageTag}"
    $appPort = 8000
    $generatedTemplatePath = Join-Path $PSScriptRoot 'deployment-template.generated.json'
    $paramsPath = Join-Path $PSScriptRoot 'deployment-params.generated.json'
    $maaEndpoint = Get-SharedMaaEndpoint -Location $Region

    Write-Host "Resource Group : $resourceGroupName" -ForegroundColor Gray
    Write-Host "Region         : $Region" -ForegroundColor Gray
    Write-Host "Container Group: $containerGroupName" -ForegroundColor Gray
    Write-Host "MAA Endpoint   : $maaEndpoint" -ForegroundColor Gray

    Write-Stage 'Creating or reusing resource group'
    if (-not (Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $resourceGroupName -Location $Region -Force | Out-Null
    }

    Write-Stage 'Creating or reusing optional managed identity'
    $identityName = "$baseName-identity"
    $identity = Ensure-UserAssignedIdentity -ResourceGroupName $resourceGroupName -IdentityName $identityName -Location $Region
    $identityResourceId = if ($identity) { $identity.id } else { '' }
    if ($identityResourceId) {
        Write-Host "Managed Identity: $identityName" -ForegroundColor Gray
    }
    else {
        Write-Warning 'Managed identity is not attached for this deployment; attestation still works, but SKR/Key Vault integration remains optional.'
    }

    $hardeningSummary = 'single-container; digest-pinned; confcom-policy; stdio-disabled; default-fragments-excluded; managed-identity-optional'
    if ($identityResourceId) {
        $hardeningSummary = 'single-container; digest-pinned; confcom-policy; stdio-disabled; default-fragments-excluded; user-assigned-managed-identity-attached'
    }

    Write-Stage 'Creating or reusing Azure Container Registry'
    $acr = Get-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName -ErrorAction SilentlyContinue
    if (-not $acr) {
        New-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName -Location $Region -Sku Basic -EnableAdminUser | Out-Null
        $acr = Get-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName
    }
    $acrCred = Get-AzContainerRegistryCredential -ResourceGroupName $resourceGroupName -Name $acrName

    if (-not $SkipImageBuild) {
        Write-Stage 'Building container image in ACR'
        Push-Location $PSScriptRoot
        az acr build --registry $acrName --image "${imageName}:${ImageTag}" .
        $buildExit = $LASTEXITCODE
        Pop-Location
        if ($buildExit -ne 0) {
            throw 'ACR image build failed.'
        }
    }
    else {
        Write-Host 'Skipping image build as requested.' -ForegroundColor Yellow
    }

    Write-Stage 'Resolving immutable image digest'
    Ensure-AcrDockerLogin -AcrName $acrName
    $imageDigest = Get-AcrImageDigest -AcrName $acrName -Repository $imageName -Tag $ImageTag
    $pinnedImageRef = "$($acr.LoginServer)/${imageName}@${imageDigest}"
    Write-Host "Pinned image   : $pinnedImageRef" -ForegroundColor Gray
    Ensure-ImageAvailableLocally -ImageRef $pinnedImageRef

    Write-Stage 'Generating CCE policy with confcom'
    $templatePath = Join-Path $PSScriptRoot 'deployment-template.json'
    if (-not (Test-Path $templatePath)) {
        throw "Template file '$templatePath' was not found."
    }

    Copy-Item -Path $templatePath -Destination $generatedTemplatePath -Force
    New-PolicyParameterFile `
        -Path $paramsPath `
        -ContainerGroupName $containerGroupName `
        -Location $Region `
        -DnsNameLabel $dnsLabel `
        -ContainerImage $pinnedImageRef `
        -RegistryServer $acr.LoginServer `
        -RegistryUsername $acrCred.Username `
        -RegistryPassword $acrCred.Password `
        -AppPort $appPort `
        -ImageDigest $imageDigest `
        -MaaEndpoint $maaEndpoint `
        -IdentityResourceId $identityResourceId `
        -HardeningSummary $hardeningSummary

    $policyInfo = Get-PolicyInfoFromConfcom -TemplatePath $generatedTemplatePath -ParamsPath $paramsPath
    Write-Host "Policy hash    : $($policyInfo.PolicyHash)" -ForegroundColor Green
    Write-Host "Generated file : $generatedTemplatePath" -ForegroundColor Gray

    az confcom acipolicygen --template-file $generatedTemplatePath --parameters $paramsPath --diff --disable-stdio --exclude-default-fragments --approve-wildcards 1>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'confcom diff reported a policy/template mismatch; continuing with the freshly generated ccePolicy that was just injected into the deployment template.'
    }

    Write-Stage 'Deploying Confidential ACI'
    $existing = Get-AzContainerGroup -ResourceGroupName $resourceGroupName -Name $containerGroupName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Removing existing container group '$containerGroupName' before redeploy..." -ForegroundColor Gray
        Remove-AzContainerGroup -ResourceGroupName $resourceGroupName -Name $containerGroupName -Confirm:$false | Out-Null

        for ($retry = 1; $retry -le 18; $retry++) {
            Start-Sleep -Seconds 5
            $stillThere = Get-AzContainerGroup -ResourceGroupName $resourceGroupName -Name $containerGroupName -ErrorAction SilentlyContinue
            if (-not $stillThere) {
                break
            }
            Write-Host "Waiting for previous container group deletion... ($retry/18)" -ForegroundColor DarkYellow
        }
    }

    New-AzResourceGroupDeployment `
        -ResourceGroupName $resourceGroupName `
        -Name ("$baseName-cce") `
        -TemplateFile $generatedTemplatePath `
        -TemplateParameterFile $paramsPath | Out-Null

    Write-Stage 'Resolving endpoint'
    $containerGroup = Get-AzContainerGroup -ResourceGroupName $resourceGroupName -Name $containerGroupName
    $fqdn = $containerGroup.IPAddressFqdn
    if (-not $fqdn) {
        throw 'Could not resolve container FQDN.'
    }

    $endpoint = "http://$fqdn`:$appPort"
    Write-Host "Endpoint: $endpoint" -ForegroundColor Green

    Write-Stage 'Probing health endpoint'
    $healthy = $false
    for ($i = 1; $i -le 24; $i++) {
        Start-Sleep -Seconds 5
        try {
            $resp = Invoke-RestMethod -Uri "$endpoint/health" -Method Get -TimeoutSec 5
            if ($resp.status -eq 'ok') {
                $healthy = $true
                break
            }
        }
        catch {
            Write-Host "Waiting for container startup... ($i/24)" -ForegroundColor DarkYellow
        }
    }

    if ($healthy) {
        Write-Host 'Snake demo is live.' -ForegroundColor Green
        Write-Host 'Security posture:' -ForegroundColor Cyan
        Write-Host '  - exact image is pinned by digest' -ForegroundColor White
        Write-Host '  - ccePolicy was generated by az confcom' -ForegroundColor White
        Write-Host '  - stdio access is disabled in the policy' -ForegroundColor White
        Write-Host '  - default policy fragments were excluded to minimize allowed surface area' -ForegroundColor White
        if ($identityResourceId) {
            Write-Host '  - a user-assigned managed identity is attached like the visual attestation sample' -ForegroundColor White
        }
        Write-Host "  - policy hash: $($policyInfo.PolicyHash)" -ForegroundColor White
        Write-Host "Open these endpoints:" -ForegroundColor Cyan
        Write-Host "  $endpoint/" -ForegroundColor White
        Write-Host "  $endpoint/attestation" -ForegroundColor White
        Write-Host "  $endpoint/health" -ForegroundColor White
        Write-Host "  $endpoint/api/scenario" -ForegroundColor White
    }
    else {
        Write-Host 'Container deployed but the health probe did not succeed in time.' -ForegroundColor Yellow
    }

    Write-Host "`nCleanup:" -ForegroundColor Cyan
    Write-Host "  Remove-AzResourceGroup -Name $resourceGroupName -Force" -ForegroundColor White
}
catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($paramsPath -and (Test-Path -LiteralPath $paramsPath)) {
        Remove-Item $paramsPath -Force -ErrorAction SilentlyContinue
    }
}
