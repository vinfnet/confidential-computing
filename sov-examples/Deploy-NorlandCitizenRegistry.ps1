param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [string]$Location = "uaenorth"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not ($Build -or $Deploy -or $Cleanup)) {
    throw "Specify one of: -Build, -Deploy, -Cleanup"
}

if (($Build -or $Deploy) -and -not $Prefix) {
    throw "-Prefix is required for Build/Deploy"
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $ScriptRoot "norland-config.json"

function Write-Step([string]$msg) {
    Write-Host "`n=== $msg ===`n" -ForegroundColor Cyan
}

function Save-Config($obj) {
    $obj | ConvertTo-Json -Depth 8 | Set-Content -Path $configPath -Encoding UTF8
}

function Load-Config() {
    if (-not (Test-Path $configPath)) {
        throw "Missing config file: $configPath. Run -Build first."
    }
    return Get-Content $configPath -Raw | ConvertFrom-Json
}

if ($Cleanup) {
    $cfg = Load-Config
    Write-Step "Cleanup"
    az group delete --name $cfg.resourceGroup --yes --no-wait
    Write-Host "Resource group deletion requested: $($cfg.resourceGroup)" -ForegroundColor Yellow
    return
}

if ($Build) {
    $rg = "rg-$Prefix-norland"
    $acr = "${Prefix}noracr"
    $kv = "$Prefix-nor-kv"
    $identity = "$Prefix-nor-id"
    $imageName = "norland-citizen-cce"
    $imageTag = "latest"

    Write-Step "Create Resource Group"
    az group create --name $rg --location $Location | Out-Null

    Write-Step "Create ACR"
    az acr create --resource-group $rg --name $acr --sku Standard --admin-enabled true | Out-Null
    $acrLogin = az acr show --resource-group $rg --name $acr --query loginServer -o tsv

    Write-Step "Create Key Vault + Identity"
    az keyvault create --resource-group $rg --name $kv --location $Location --sku Premium | Out-Null
    az identity create --resource-group $rg --name $identity --location $Location | Out-Null

    Write-Step "Build and Push Container"
    az acr build --registry $acr --image "$imageName`:$imageTag" "$ScriptRoot"

    $cfg = [pscustomobject]@{
        prefix = $Prefix
        location = $Location
        resourceGroup = $rg
        acrName = $acr
        acrLoginServer = $acrLogin
        image = "$acrLogin/$imageName`:$imageTag"
        keyVaultName = $kv
        identityName = $identity
    }
    Save-Config $cfg
    Write-Host "Build complete and config saved to $configPath" -ForegroundColor Green
}

if ($Deploy) {
    $cfg = Load-Config

    Write-Step "Ensure confcom extension"
    az extension add --name confcom --upgrade | Out-Null

    Write-Step "Create VNet + delegated subnet"
    $vnetName = "$($cfg.prefix)-nor-vnet"
    $subnetName = "aci-subnet"
    az network vnet create --resource-group $cfg.resourceGroup --name $vnetName --address-prefix 10.20.0.0/16 --subnet-name $subnetName --subnet-prefix 10.20.1.0/24 | Out-Null
    az network vnet subnet update --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $subnetName --delegations Microsoft.ContainerInstance/containerGroups | Out-Null
    $subnetId = az network vnet subnet show --resource-group $cfg.resourceGroup --vnet-name $vnetName --name $subnetName --query id -o tsv

    Write-Step "Create PostgreSQL Flexible Server"
    $dbServer = "$($cfg.prefix)-norreg-pg"
    $dbName = "norlandregistry"
    $dbUser = "sovadmin"
    $dbPassword = [System.Web.Security.Membership]::GeneratePassword(24, 4)

    az postgres flexible-server create --resource-group $cfg.resourceGroup --name $dbServer --location $cfg.location --tier GeneralPurpose --sku-name Standard_D2ds_v5 --storage-size 128 --admin-user $dbUser --admin-password $dbPassword --public-access 0.0.0.0 --version 16 | Out-Null
    az postgres flexible-server db create --resource-group $cfg.resourceGroup --server-name $dbServer --database-name $dbName | Out-Null

    Write-Step "Seed PostgreSQL with ~5000 fictional citizen records"
    python "$ScriptRoot\generate_citizen_data.py" --count 5000 --output "$ScriptRoot\seed-data.sql"
    az postgres flexible-server execute --resource-group $cfg.resourceGroup --name $dbServer --database-name $dbName --admin-user $dbUser --admin-password $dbPassword --file-path "$ScriptRoot\seed-data.sql" | Out-Null

    Write-Step "Generate ccePolicy with confcom"
    $paramsFile = Join-Path $ScriptRoot "confcom-params.json"

    $acrUser = az acr credential show --name $cfg.acrName --query username -o tsv
    $acrPass = az acr credential show --name $cfg.acrName --query "passwords[0].value" -o tsv

    $paramObj = @{
        containerGroupName = @{ value = "$($cfg.prefix)-nor-citizen-cg" }
        dnsNameLabel = @{ value = "norland-$($cfg.prefix)-$((Get-Random -Minimum 1000 -Maximum 9999))" }
        appImage = @{ value = $cfg.image }
        registryServer = @{ value = $cfg.acrLoginServer }
        registryUsername = @{ value = $acrUser }
        registryPassword = @{ value = $acrPass }
        subnetId = @{ value = $subnetId }
        dbHost = @{ value = "$dbServer.postgres.database.azure.com" }
        dbName = @{ value = $dbName }
        dbUser = @{ value = "$dbUser" }
        dbPassword = @{ value = $dbPassword }
        securityPolicyHash = @{ value = "" }
    }

    @{ '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"; contentVersion = "1.0.0.0"; parameters = $paramObj } |
        ConvertTo-Json -Depth 20 |
        Set-Content -Path $paramsFile -Encoding UTF8

    $confcomOut = az confcom acipolicygen -a "$ScriptRoot\deployment-template.json" --parameters $paramsFile --disable-stdio --approve-wildcards 2>&1
    $policyHash = ($confcomOut | Where-Object { $_ -match '^[a-f0-9]{64}$' } | Select-Object -Last 1)
    if (-not $policyHash) {
        throw "Could not get policy hash from confcom output."
    }

    $paramsJson = Get-Content $paramsFile -Raw | ConvertFrom-Json
    $paramsJson.parameters.securityPolicyHash.value = $policyHash
    $paramsJson | ConvertTo-Json -Depth 20 | Set-Content -Path $paramsFile -Encoding UTF8

    Write-Step "Validate ARM deployment with what-if"
    az deployment group what-if --resource-group $cfg.resourceGroup --template-file "$ScriptRoot\deployment-template.json" --parameters @$paramsFile | Out-Null

    Write-Step "Deploy Confidential ACI"
    az deployment group create --resource-group $cfg.resourceGroup --template-file "$ScriptRoot\deployment-template.json" --parameters @$paramsFile | Out-Null

    $cgName = "$($cfg.prefix)-nor-citizen-cg"
    $fqdn = az container show --resource-group $cfg.resourceGroup --name $cgName --query ipAddress.fqdn -o tsv

    $cfg | Add-Member -NotePropertyName dbServer -NotePropertyValue $dbServer -Force
    $cfg | Add-Member -NotePropertyName dbName -NotePropertyValue $dbName -Force
    $cfg | Add-Member -NotePropertyName dbUser -NotePropertyValue $dbUser -Force
    $cfg | Add-Member -NotePropertyName dbPassword -NotePropertyValue $dbPassword -Force
    $cfg | Add-Member -NotePropertyName ccePolicyHash -NotePropertyValue $policyHash -Force
    Save-Config $cfg

    Write-Host "Deployment complete." -ForegroundColor Green
    Write-Host "Resource Group: $($cfg.resourceGroup)"
    Write-Host "Container Group: $cgName"
    Write-Host "Endpoint: https://$fqdn"
    Write-Host "Policy Hash: $policyHash"
}
