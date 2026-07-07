param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [Parameter(Mandatory = $true)]
    [string]$AzpUrl,

    [Parameter(Mandatory = $false)]
    [string]$AzpPool = "Default",

    [Parameter(Mandatory = $false)]
    [string]$AzpToken = "",

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$AcrName = "",

    [Parameter(Mandatory = $false)]
    [string]$ImageName = "ado-confidential-agent",

    [Parameter(Mandatory = $false)]
    [string]$ImageTag = "latest",

    [Parameter(Mandatory = $false)]
    [int]$AgentCount = 2,

    [Parameter(Mandatory = $false)]
    [string]$VnetName = "",

    [Parameter(Mandatory = $false)]
    [string]$VnetResourceGroup = "",

    [Parameter(Mandatory = $false)]
    [string]$AgentSubnetName = "aci-agents-subnet",

    [Parameter(Mandatory = $false)]
    [string]$AgentSubnetPrefix = "10.0.1.0/24",

    [Parameter(Mandatory = $false)]
    [string]$NatGatewayName = "",

    [Parameter(Mandatory = $false)]
    [string]$UserAssignedIdentityResourceId = "",

    [Parameter(Mandatory = $false)]
    [switch]$AllowStdio
)

$ErrorActionPreference = "Stop"

function Invoke-AzCli {
    param([string]$CommandText)
    Write-Host "-> $CommandText" -ForegroundColor DarkGray
    $result = Invoke-Expression $CommandText
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: $CommandText"
    }
    return $result
}

function New-SafeName {
    param(
        [string]$Raw,
        [int]$MaxLength,
        [string]$Fallback = "caci"
    )

    $value = ($Raw.ToLower() -replace "[^a-z0-9-]", "")
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $Fallback
    }
    if ($value.Length -gt $MaxLength) {
        $value = $value.Substring(0, $MaxLength)
    }
    return $value
}

if ([string]::IsNullOrWhiteSpace($AzpToken)) {
    if (-not [string]::IsNullOrWhiteSpace($env:AZP_TOKEN)) {
        $AzpToken = $env:AZP_TOKEN
    } else {
        throw "Provide -AzpToken (or set AZP_TOKEN env var) for Azure DevOps agent registration."
    }
}

Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

$prefixSafe = New-SafeName -Raw $Prefix -MaxLength 18 -Fallback "adocaci"
if ($AgentCount -lt 1) { throw "-AgentCount must be at least 1." }

$useVnet = -not [string]::IsNullOrWhiteSpace($VnetName)
if ($useVnet -and [string]::IsNullOrWhiteSpace($VnetResourceGroup)) { $VnetResourceGroup = $ResourceGroupName }
$subnetResourceId = ""
$useIdentity = -not [string]::IsNullOrWhiteSpace($UserAssignedIdentityResourceId)

if ([string]::IsNullOrWhiteSpace($AcrName)) {
    $AcrName = New-SafeName -Raw ("$prefixSafe" + "acr" + (Get-Random -Minimum 10000 -Maximum 99999)) -MaxLength 50 -Fallback "adocaciacr"
}

Write-Host "=== Step 1/7: Ensure resource group and ACR exist ===" -ForegroundColor Cyan

az group show --name $ResourceGroupName --only-show-errors --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-AzCli "az group create --name $ResourceGroupName --location $Location --output none"
}

az acr show --name $AcrName --resource-group $ResourceGroupName --only-show-errors --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-AzCli "az acr create --resource-group $ResourceGroupName --name $AcrName --sku Basic --admin-enabled true --location $Location --output none"
} else {
    Invoke-AzCli "az acr update --name $AcrName --resource-group $ResourceGroupName --admin-enabled true --output none"
}

$acrLoginServer = (Invoke-AzCli "az acr show --name $AcrName --resource-group $ResourceGroupName --query loginServer -o tsv").Trim()

if ($useVnet) {
    Write-Host "=== Step 1b/7: Ensure delegated ACI subnet + NAT gateway ===" -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($NatGatewayName)) {
        $NatGatewayName = (Invoke-AzCli "az network nat gateway list --resource-group $VnetResourceGroup --query `"[0].name`" -o tsv").Trim()
    }

    az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AgentSubnetName --only-show-errors --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        $subnetCreate = "az network vnet subnet create --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AgentSubnetName --address-prefixes $AgentSubnetPrefix --delegations Microsoft.ContainerInstance/containerGroups"
        if (-not [string]::IsNullOrWhiteSpace($NatGatewayName)) { $subnetCreate += " --nat-gateway $NatGatewayName" }
        Invoke-AzCli ($subnetCreate + " --output none")
    } else {
        $subnetUpdate = "az network vnet subnet update --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AgentSubnetName --delegations Microsoft.ContainerInstance/containerGroups"
        if (-not [string]::IsNullOrWhiteSpace($NatGatewayName)) { $subnetUpdate += " --nat-gateway $NatGatewayName" }
        Invoke-AzCli ($subnetUpdate + " --output none")
    }

    $subnetResourceId = (Invoke-AzCli "az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AgentSubnetName --query id -o tsv").Trim()
    Write-Host "ACI subnet: $subnetResourceId" -ForegroundColor DarkGray
}

Write-Host "=== Step 2/7: Build ADO agent container image ===" -ForegroundColor Cyan

$tempRoot = Join-Path $env:TEMP ("ado-caci-build-" + [Guid]::NewGuid().ToString("N"))
New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

$dockerfile = @"
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TARGETARCH=linux-x64

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    libicu70 \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /azp
COPY ./start.sh ./start.sh
RUN chmod +x ./start.sh \
    && useradd --create-home --home-dir /home/azp azp \
    && chown -R azp /azp

USER azp
ENTRYPOINT [ "./start.sh" ]
"@

# start.sh self-registers the agent using AZP_URL/AZP_TOKEN/AZP_POOL/AZP_AGENT_NAME.
# It downloads the matching agent package from the Azure DevOps (Server) instance.
$startSh = @'
#!/bin/bash
set -e

if [ -z "${AZP_URL}" ]; then
  echo 1>&2 "error: missing AZP_URL environment variable"
  exit 1
fi

if [ -z "${AZP_TOKEN_FILE}" ]; then
  if [ -z "${AZP_TOKEN}" ]; then
    echo 1>&2 "error: missing AZP_TOKEN environment variable"
    exit 1
  fi
  AZP_TOKEN_FILE=/azp/.token
  echo -n "${AZP_TOKEN}" > "${AZP_TOKEN_FILE}"
fi

unset AZP_TOKEN

if [ -n "${AZP_WORK}" ]; then
  mkdir -p "${AZP_WORK}"
fi

cd /azp

print_header() {
  lightcyan="\033[1;36m"
  nocolor="\033[0m"
  echo -e "${lightcyan}$1${nocolor}"
}

cleanup() {
  if [ -e config.sh ]; then
    print_header "Cleanup. Removing Azure Pipelines agent..."
    while true; do
      ./config.sh remove --unattended --auth PAT --token "$(cat "${AZP_TOKEN_FILE}")" && break
      echo "Retrying in 30 seconds..."
      sleep 30
    done
  fi
}

print_header "1. Determining matching Azure Pipelines agent..."

AZP_AGENT_PACKAGES=$(curl -LsSk \
  -u user:"$(cat "${AZP_TOKEN_FILE}")" \
  -H "Accept:application/json" \
  "${AZP_URL}/_apis/distributedtask/packages/agent?platform=${TARGETARCH}&top=1")

AZP_AGENT_PACKAGE_LATEST_URL=$(echo "${AZP_AGENT_PACKAGES}" | jq -r ".value[0].downloadUrl")

if [ -z "${AZP_AGENT_PACKAGE_LATEST_URL}" ] || [ "${AZP_AGENT_PACKAGE_LATEST_URL}" == "null" ]; then
  echo 1>&2 "error: could not determine a matching Azure Pipelines agent"
  echo 1>&2 "check that account "${AZP_URL}" is correct and the token is valid for that account"
  exit 1
fi

print_header "2. Downloading and extracting Azure Pipelines agent..."

curl -LsSk "${AZP_AGENT_PACKAGE_LATEST_URL}" | tar -xz & wait $!

source ./env.sh

print_header "3. Configuring Azure Pipelines agent..."

./config.sh --unattended \
  --agent "${AZP_AGENT_NAME:-$(hostname)}" \
  --url "${AZP_URL}" \
  --auth PAT \
  --token "$(cat "${AZP_TOKEN_FILE}")" \
  --pool "${AZP_POOL:-Default}" \
  --work "${AZP_WORK:-_work}" \
  --replace \
  --sslskipcertvalidation \
  --acceptTeeEula & wait $!

trap "cleanup; exit 0" EXIT
trap "cleanup; exit 130" INT
trap "cleanup; exit 143" TERM

print_header "4. Running Azure Pipelines agent..."

chmod +x ./run.sh

./run.sh "$@" & wait $!
'@

Set-Content -Path (Join-Path $tempRoot "Dockerfile") -Value $dockerfile -Encoding utf8

# Write start.sh with LF line endings and no BOM (CRLF/BOM would break the shebang).
$startSh = $startSh -replace "`r`n", "`n"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $tempRoot "start.sh"), $startSh, $utf8NoBom)

$imageRef = "$acrLoginServer/$ImageName`:$ImageTag"
Invoke-AzCli "az acr build --registry $AcrName --resource-group $ResourceGroupName --image $ImageName`:$ImageTag $tempRoot --output none"
Invoke-AzCli "az acr login --name $AcrName --output none"
& docker pull $imageRef | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to pull built image '$imageRef' into local Docker cache for confcom policy generation."
}

Write-Host "=== Step 3/7: Build ARM template for confidential ACI ===" -ForegroundColor Cyan

$templatePath = Join-Path $tempRoot "deployment-template.json"

if ($useVnet) {
    $subnetParamDef = '"subnetResourceId": { "type": "string" }, "agentSubnetName": { "type": "string" }, '
    $subnetPropBlock = "`"subnetIds`": [ { `"id`": `"[parameters('subnetResourceId')]`", `"name`": `"[parameters('agentSubnetName')]`" } ],`n        "
} else {
    $subnetParamDef = ""
    $subnetPropBlock = ""
}

if ($useIdentity) {
    $identityParamDef = '"userAssignedIdentityId": { "type": "string" }, '
    $identityBlock = "`"identity`": { `"type`": `"UserAssigned`", `"userAssignedIdentities`": { `"[parameters('userAssignedIdentityId')]`": {} } },`n      "
} else {
    $identityParamDef = ""
    $identityBlock = ""
}

$template = @"
{
  "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "containerGroupName": { "type": "string" },
    "location": { "type": "string" },
    "appImage": { "type": "string" },
    "registryServer": { "type": "string" },
    "registryUsername": { "type": "string" },
    "registryPassword": { "type": "securestring" },
    "azpUrl": { "type": "string" },
    "azpPool": { "type": "string" },
    "azpToken": { "type": "securestring" },
    $identityParamDef$subnetParamDef"azpAgentName": { "type": "string" }
  },
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2023-05-01",
      "name": "[parameters('containerGroupName')]",
      "location": "[parameters('location')]",
      $identityBlock"properties": {
        $subnetPropBlock"sku": "Confidential",
        "confidentialComputeProperties": {
          "ccePolicy": ""
        },
        "containers": [
          {
            "name": "ado-agent",
            "properties": {
              "image": "[parameters('appImage')]",
              "environmentVariables": [
                { "name": "AZP_URL", "value": "[parameters('azpUrl')]" },
                { "name": "AZP_POOL", "value": "[parameters('azpPool')]" },
                { "name": "AZP_AGENT_NAME", "value": "[parameters('azpAgentName')]" },
                { "name": "AZP_TOKEN", "secureValue": "[parameters('azpToken')]" },
                { "name": "AZP_WORK", "value": "/azp/_work" },
                { "name": "AGENT_ALLOW_RUNASROOT", "value": "1" }
              ],
              "resources": {
                "requests": {
                  "cpu": 2,
                  "memoryInGB": 4
                }
              }
            }
          }
        ],
        "imageRegistryCredentials": [
          {
            "server": "[parameters('registryServer')]",
            "username": "[parameters('registryUsername')]",
            "password": "[parameters('registryPassword')]"
          }
        ],
        "osType": "Linux",
        "restartPolicy": "Always"
      }
    }
  ]
}
"@
Set-Content -Path $templatePath -Value $template -Encoding utf8

$acrCreds = Invoke-AzCli "az acr credential show --name $AcrName --resource-group $ResourceGroupName --output json" | ConvertFrom-Json
$acrUsername = $acrCreds.username
$acrPassword = $acrCreds.passwords[0].value

function New-AgentParams {
    param(
        [string]$ContainerGroupName,
        [string]$AgentName
    )
    $p = @{
        '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        contentVersion = "1.0.0.0"
        parameters = @{
            containerGroupName = @{ value = $ContainerGroupName }
            location = @{ value = $Location }
            appImage = @{ value = $imageRef }
            registryServer = @{ value = $acrLoginServer }
            registryUsername = @{ value = $acrUsername }
            registryPassword = @{ value = $acrPassword }
            azpUrl = @{ value = $AzpUrl }
            azpPool = @{ value = $AzpPool }
            azpToken = @{ value = $AzpToken }
            azpAgentName = @{ value = $AgentName }
        }
    }
    if ($useVnet) {
        $p.parameters.subnetResourceId = @{ value = $subnetResourceId }
        $p.parameters.agentSubnetName = @{ value = $AgentSubnetName }
    }
    if ($useIdentity) {
        $p.parameters.userAssignedIdentityId = @{ value = $UserAssignedIdentityResourceId }
    }
    return $p
}

# The CCE policy is generated once with wildcard env-var rules (--approve-wildcards),
# so a single policy embedded in the template is valid for every agent instance
# (only the container-group name and agent name differ per agent).
$policyParamsPath = Join-Path $tempRoot "deployment-params-policy.json"
$policyContainerGroup = New-SafeName -Raw ("$prefixSafe-caci-agent-1") -MaxLength 63 -Fallback "adocaci-agent-1"
New-AgentParams -ContainerGroupName $policyContainerGroup -AgentName "$prefixSafe-agent-1" |
    ConvertTo-Json -Depth 20 | Set-Content -Path $policyParamsPath -Encoding utf8

Write-Host "=== Step 4/7: Generate confidential container policy ===" -ForegroundColor Cyan
Invoke-AzCli "az extension add --name confcom --upgrade --output none"
$stdioFlag = if ($AllowStdio) { "" } else { " --disable-stdio" }
Invoke-AzCli "az confcom acipolicygen -a $templatePath --parameters $policyParamsPath$stdioFlag --approve-wildcards"

Write-Host "=== Step 5/7: Deploy $AgentCount confidential ACI agent(s) ===" -ForegroundColor Cyan
$deployed = @()
for ($i = 1; $i -le $AgentCount; $i++) {
    $agentContainerGroup = New-SafeName -Raw ("$prefixSafe-caci-agent-$i") -MaxLength 63 -Fallback "adocaci-agent-$i"
    $agentName = "$prefixSafe-agent-$i"
    $agentParamsPath = Join-Path $tempRoot "deployment-params-$i.json"

    New-AgentParams -ContainerGroupName $agentContainerGroup -AgentName $agentName |
        ConvertTo-Json -Depth 20 | Set-Content -Path $agentParamsPath -Encoding utf8

    Write-Host "--- Deploying agent $i/$AgentCount ($agentName -> $agentContainerGroup) ---" -ForegroundColor Yellow
    Invoke-AzCli "az deployment group create --name $agentContainerGroup --resource-group $ResourceGroupName --template-file $templatePath --parameters @$agentParamsPath --output none"
    $deployed += $agentContainerGroup
}

Write-Host "=== Step 6/7: Show deployment state ===" -ForegroundColor Cyan
foreach ($cg in $deployed) {
    $state = Invoke-AzCli "az container show --resource-group $ResourceGroupName --name $cg --query `"{name:name,state:instanceView.state,sku:sku,image:containers[0].image}`" -o json"
    Write-Host $state
}

Write-Host "=== Step 7/7: Summary ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Confidential ACI ADO agent deployment complete." -ForegroundColor Green
Write-Host "Resource Group: $ResourceGroupName"
Write-Host "Agents deployed: $AgentCount"
foreach ($cg in $deployed) { Write-Host "  Container Group: $cg" }
Write-Host "Image: $imageRef"
Write-Host "Azure DevOps URL: $AzpUrl"
Write-Host "Pool: $AzpPool"
if ($useVnet) {
    Write-Host "VNet: $VnetName ($VnetResourceGroup)"
    Write-Host "ACI subnet: $AgentSubnetName ($AgentSubnetPrefix)"
}
