<#
.SYNOPSIS
Deploy Azure DevOps build agents as CONFIDENTIAL ACI on AKS virtual nodes.

.DESCRIPTION
This is the AKS virtual-nodes equivalent of Build-ConfidentialAciAdoAgent.ps1.
Instead of deploying standalone confidential ACI container groups, it:

  1. Reuses (or creates) an Azure Container Registry and builds the same
     self-registering Azure DevOps agent image.
  2. Adds an AKS node subnet and an ACI (virtual-node) subnet to the EXISTING
     Azure DevOps Server VNet, so the agents reach the server privately.
  3. Creates an AKS cluster with the virtual nodes add-on backed by Azure
     Container Instances.
  4. Grants the virtual-node connector identity network rights on the ACI
     subnet and the VNet.
  5. Deploys a Kubernetes Deployment that schedules the agent pods onto the
     virtual node as CONFIDENTIAL ACI (AMD SEV-SNP) using the
     microsoft.containerinstance.virtualnode.ccepolicy annotation.
  6. The agents self-register to the self-hosted Azure DevOps Server over the
     private VNet and appear in the target pool.

Confidentiality of the runners comes from the ACI CCE policy on the
virtual-node-backed container group, not from an AKS confidential node pool,
so a standard system node pool is sufficient to host the virtual node.

.PARAMETER SubscriptionId
Target Azure subscription ID.

.PARAMETER ResourceGroupName
Resource group that will host the AKS cluster (typically the same resource
group as the Azure DevOps Server CVM).

.PARAMETER Prefix
Prefix used for naming (AKS cluster, ACR fallback name, etc.).

.PARAMETER VnetName
Name of the EXISTING Azure DevOps Server VNet to attach the AKS/ACI subnets to.

.PARAMETER AzpUrl
Azure DevOps Server collection URL reachable privately from the VNet.
Default: https://10.0.0.4/DefaultCollection

.PARAMETER AzpPool
Azure DevOps agent pool the runners register into. Default: confidential-build-pool

.PARAMETER AzpToken
Personal Access Token for unattended agent registration. Falls back to the
AZP_TOKEN environment variable.

.PARAMETER PolicyMode
'debug-allow-all' (default) bakes the allow-all DEBUG CCE policy so the runners
start quickly as confidential ACI while you validate the plumbing.
'generated' runs `az confcom acipolicygen --virtual-node-yaml` to produce a
restrictive, image-bound policy. 'none' omits the annotation (standard ACI,
useful only for isolating network/registration issues).

.PARAMETER SkipImageBuild
Reuse an existing agent image in the registry instead of rebuilding it.

.PARAMETER SkipAksCreate
Reuse an existing AKS cluster and only (re)deploy the agent workload.

.EXAMPLE
./Build-AksVirtualNodesAdoAgent.ps1 -SubscriptionId <sub> -ResourceGroupName SGALLDHFAY `
  -Prefix sgall -VnetName sgalldhfayvnet -AzpPool confidential-build-pool
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [Parameter(Mandatory = $true)]
    [string]$VnetName,

    [Parameter(Mandatory = $false)]
    [string]$VnetResourceGroup = "",

    [Parameter(Mandatory = $false)]
    [string]$AzpUrl = "https://10.0.0.4/DefaultCollection",

    [Parameter(Mandatory = $false)]
    [string]$AzpPool = "confidential-build-pool",

    [Parameter(Mandatory = $false)]
    [string]$AzpToken = "",

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$AksName = "",

    [Parameter(Mandatory = $false)]
    [string]$AcrName = "",

    [Parameter(Mandatory = $false)]
    [string]$ImageName = "ado-confidential-agent",

    [Parameter(Mandatory = $false)]
    [string]$ImageTag = "latest",

    [Parameter(Mandatory = $false)]
    [int]$AgentCount = 2,

    [Parameter(Mandatory = $false)]
    [string]$RunnerSetName = "default",

    [Parameter(Mandatory = $false)]
    [string]$SystemVmSize = "Standard_D2as_v7",

    [Parameter(Mandatory = $false)]
    [int]$SystemNodeCount = 1,

    [Parameter(Mandatory = $false)]
    [string]$AksNodeSubnetName = "aks-node-subnet",

    [Parameter(Mandatory = $false)]
    [string]$AksNodeSubnetPrefix = "10.0.16.0/20",

    [Parameter(Mandatory = $false)]
    [string]$AciSubnetName = "aci-vnode-subnet",

    [Parameter(Mandatory = $false)]
    [string]$AciSubnetPrefix = "10.0.32.0/23",

    [Parameter(Mandatory = $false)]
    [string]$ServiceCidr = "10.2.0.0/24",

    [Parameter(Mandatory = $false)]
    [string]$DnsServiceIp = "10.2.0.10",

    [Parameter(Mandatory = $false)]
    [string]$NatGatewayName = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("debug-allow-all", "generated", "none")]
    [string]$PolicyMode = "debug-allow-all",

    [Parameter(Mandatory = $false)]
    [switch]$SkipImageBuild,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAksCreate
)

$ErrorActionPreference = "Stop"

# Allow-all DEBUG CCE policy (base64 Rego). Runs the pod as confidential ACI but
# does NOT enforce image/identity. Identical to the value used by the
# aks-samples/virtual nodes/virtual-node-confidential.yaml starter manifest.
$DebugAllowAllPolicy = "cGFja2FnZSBwb2xpY3kKYXBpX3ZlcnNpb24gOj0gIjAuMS4wIgppbXBvcnQgZnV0dXJlLmtleXdvcmRzLmV2ZXJ5CmltcG9ydCBmdXR1cmUua2V5d29yZHMuaW4KZnJhZ21lbnRzIDo9IFtdCmNvbnRhaW5lcnMgOj0gW10KYWxsb3dfcHJvcGVydGllc19hY2Nlc3MgOj0gdHJ1ZQphbGxvd19kdW1wX3N0YWNrcyA6PSB0cnVlCmFsbG93X3J1bnRpbWVfbG9nZ2luZyA6PSB0cnVlCmFsbG93X2Vudmlyb25tZW50X3ZhcmlhYmxlX2Ryb3BwaW5nIDo9IHRydWUKYWxsb3dfdW5lbmNyeXB0ZWRfc2NyYXRjaCA6PSB0cnVlCmFsbG93X2NhcGFiaWxpdHlfZHJvcHBpbmcgOj0gdHJ1ZQ=="

function Invoke-AzCli {
    param([string]$CommandText)
    Write-Host "-> $CommandText" -ForegroundColor DarkGray
    $result = Invoke-Expression $CommandText
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: $CommandText"
    }
    return $result
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function New-SafeName {
    param(
        [string]$Raw,
        [int]$MaxLength,
        [string]$Fallback = "vnode"
    )
    $value = ($Raw.ToLower() -replace "[^a-z0-9-]", "")
    $value = $value.Trim('-')
    if ([string]::IsNullOrWhiteSpace($value)) { $value = $Fallback }
    if ($value.Length -gt $MaxLength) { $value = $value.Substring(0, $MaxLength).Trim('-') }
    if ([string]::IsNullOrWhiteSpace($value)) { $value = $Fallback }
    return $value
}

function Wait-ForManagedIdentity {
    param(
        [string]$ResourceGroup,
        [string]$IdentityName,
        [int]$TimeoutSeconds = 600
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $principalId = (Invoke-AzCli "az identity show --resource-group $ResourceGroup --name $IdentityName --query principalId --output tsv").Trim()
            if ($principalId) { return $principalId }
        } catch {}
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)
    throw "Managed identity '$IdentityName' was not discoverable in resource group '$ResourceGroup' in time."
}

function Ensure-RoleAssignment {
    param(
        [string]$AssigneeObjectId,
        [string]$RoleName,
        [string]$Scope
    )
    $existing = ""
    try {
        $existing = (Invoke-AzCli "az role assignment list --assignee-object-id $AssigneeObjectId --scope $Scope --role `"$RoleName`" --query '[0].id' --output tsv").Trim()
    } catch {}
    if ($existing) { return }
    Invoke-AzCli "az role assignment create --assignee-object-id $AssigneeObjectId --assignee-principal-type ServicePrincipal --role `"$RoleName`" --scope $Scope --output none"
}

function Wait-ForVirtualNode {
    param([int]$TimeoutSeconds = 900)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $nodeNames = kubectl get nodes -l type=virtual-kubelet -o name 2>$null
            if ($LASTEXITCODE -eq 0 -and $nodeNames) {
                return ($nodeNames | Select-Object -First 1).Replace("node/", "")
            }
        } catch {}
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for the virtual node to become Ready in Kubernetes."
}

# --- Preflight -------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($AzpToken)) {
    if (-not [string]::IsNullOrWhiteSpace($env:AZP_TOKEN)) {
        $AzpToken = $env:AZP_TOKEN
    } else {
        throw "Provide -AzpToken (or set AZP_TOKEN env var) for Azure DevOps agent registration."
    }
}

if ($AgentCount -lt 1) { throw "-AgentCount must be at least 1." }
if ([string]::IsNullOrWhiteSpace($VnetResourceGroup)) { $VnetResourceGroup = $ResourceGroupName }

$prefixSafe = New-SafeName -Raw $Prefix -MaxLength 12 -Fallback "adovnode"
if ([string]::IsNullOrWhiteSpace($AksName)) { $AksName = New-SafeName -Raw "$prefixSafe-vnode-aks" -MaxLength 63 -Fallback "ado-vnode-aks" }

Write-Step "Preparing deployment"
Invoke-AzCli "az account set --subscription $SubscriptionId"

foreach ($cmd in @("az", "kubectl")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "'$cmd' is required on PATH before running this script."
    }
}

# aks-preview keeps virtual-nodes behavior consistent with the reference sample.
try { $null = Invoke-AzCli "az extension show --name aks-preview --output none" }
catch { Invoke-AzCli "az extension add --name aks-preview --upgrade --only-show-errors --output none" }

if ($PolicyMode -eq "generated") {
    Invoke-AzCli "az extension add --name confcom --upgrade --only-show-errors --output none"
}

Invoke-AzCli "az provider register --namespace Microsoft.ContainerService --output none"
Invoke-AzCli "az provider register --namespace Microsoft.ContainerInstance --output none"

# --- ACR + agent image ------------------------------------------------------

Write-Step "Step 1/8: Ensure Azure Container Registry"
if ([string]::IsNullOrWhiteSpace($AcrName)) {
    $existingAcr = ""
    try { $existingAcr = (Invoke-AzCli "az acr list --resource-group $ResourceGroupName --query `"[0].name`" -o tsv").Trim() } catch {}
    if (-not [string]::IsNullOrWhiteSpace($existingAcr)) {
        $AcrName = $existingAcr
        Write-Host "Reusing existing ACR: $AcrName" -ForegroundColor DarkGray
    } else {
        $AcrName = New-SafeName -Raw ("$prefixSafe" + "acr" + (Get-Random -Minimum 10000 -Maximum 99999)) -MaxLength 50 -Fallback "adovnodeacr"
    }
}

az acr show --name $AcrName --resource-group $ResourceGroupName --only-show-errors --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-AzCli "az acr create --resource-group $ResourceGroupName --name $AcrName --sku Basic --admin-enabled true --location $Location --output none"
} else {
    Invoke-AzCli "az acr update --name $AcrName --resource-group $ResourceGroupName --admin-enabled true --output none"
}
$acrLoginServer = (Invoke-AzCli "az acr show --name $AcrName --resource-group $ResourceGroupName --query loginServer -o tsv").Trim()
$imageRef = "$acrLoginServer/$ImageName`:$ImageTag"

if (-not $SkipImageBuild) {
    Write-Step "Step 2/8: Build self-registering ADO agent image"
    $tempRoot = Join-Path $env:TEMP ("ado-vnode-build-" + [Guid]::NewGuid().ToString("N"))
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
    $startSh = $startSh -replace "`r`n", "`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $tempRoot "start.sh"), $startSh, $utf8NoBom)

    Invoke-AzCli "az acr build --registry $AcrName --resource-group $ResourceGroupName --image $ImageName`:$ImageTag $tempRoot --output none"
    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Step "Step 2/8: Skipping image build (reusing $imageRef)"
}

# --- Networking: subnets on the existing ADO Server VNet --------------------

Write-Step "Step 3/8: Ensure AKS + ACI subnets on VNet '$VnetName'"

if ([string]::IsNullOrWhiteSpace($NatGatewayName)) {
    try { $NatGatewayName = (Invoke-AzCli "az network nat gateway list --resource-group $VnetResourceGroup --query `"[0].name`" -o tsv").Trim() } catch {}
}

az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AksNodeSubnetName --only-show-errors --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-AzCli "az network vnet subnet create --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AksNodeSubnetName --address-prefixes $AksNodeSubnetPrefix --output none"
}

az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AciSubnetName --only-show-errors --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    $aciCreate = "az network vnet subnet create --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AciSubnetName --address-prefixes $AciSubnetPrefix --delegations Microsoft.ContainerInstance/containerGroups"
    if (-not [string]::IsNullOrWhiteSpace($NatGatewayName)) { $aciCreate += " --nat-gateway $NatGatewayName" }
    Invoke-AzCli ($aciCreate + " --output none")
} else {
    $aciUpdate = "az network vnet subnet update --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AciSubnetName --delegations Microsoft.ContainerInstance/containerGroups"
    if (-not [string]::IsNullOrWhiteSpace($NatGatewayName)) { $aciUpdate += " --nat-gateway $NatGatewayName" }
    Invoke-AzCli ($aciUpdate + " --output none")
}

$aksSubnetId = (Invoke-AzCli "az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AksNodeSubnetName --query id -o tsv").Trim()
$aciSubnetId = (Invoke-AzCli "az network vnet subnet show --resource-group $VnetResourceGroup --vnet-name $VnetName --name $AciSubnetName --query id -o tsv").Trim()
$vnetId = (Invoke-AzCli "az network vnet show --resource-group $VnetResourceGroup --name $VnetName --query id -o tsv").Trim()

# --- AKS cluster + virtual nodes -------------------------------------------

if (-not $SkipAksCreate) {
    Write-Step "Step 4/8: Create AKS cluster '$AksName'"
    Invoke-AzCli @"
az aks create --resource-group $ResourceGroupName --name $AksName --location $Location --node-count $SystemNodeCount --nodepool-name syspool --node-vm-size $SystemVmSize --os-sku Ubuntu --enable-managed-identity --generate-ssh-keys --network-plugin azure --vnet-subnet-id $aksSubnetId --service-cidr $ServiceCidr --dns-service-ip $DnsServiceIp --tier standard --only-show-errors
"@

    Write-Step "Step 5/8: Enable virtual nodes add-on"
    Invoke-AzCli "az aks enable-addons --resource-group $ResourceGroupName --name $AksName --addons virtual-node --subnet-name $AciSubnetName --only-show-errors"
} else {
    Write-Step "Step 4-5/8: Skipping AKS create (reusing '$AksName')"
}

$nodeResourceGroup = (Invoke-AzCli "az aks show --resource-group $ResourceGroupName --name $AksName --query nodeResourceGroup --output tsv").Trim()

Write-Step "Step 6/8: Grant the virtual-node identity network + registry rights"
$aciConnectorIdentity = "aciconnectorlinux-$AksName"
$aciConnectorPrincipalId = Wait-ForManagedIdentity -ResourceGroup $nodeResourceGroup -IdentityName $aciConnectorIdentity
Ensure-RoleAssignment -AssigneeObjectId $aciConnectorPrincipalId -RoleName "Network Contributor" -Scope $aciSubnetId
Ensure-RoleAssignment -AssigneeObjectId $aciConnectorPrincipalId -RoleName "Network Contributor" -Scope $vnetId

# Let the AKS kubelet identity pull from ACR as well (belt and suspenders on top
# of the imagePullSecret used by the virtual-node pod spec).
try {
    $acrId = (Invoke-AzCli "az acr show --name $AcrName --resource-group $ResourceGroupName --query id -o tsv").Trim()
    $kubeletObjectId = (Invoke-AzCli "az aks show --resource-group $ResourceGroupName --name $AksName --query identityProfile.kubeletidentity.objectId -o tsv").Trim()
    if ($kubeletObjectId) { Ensure-RoleAssignment -AssigneeObjectId $kubeletObjectId -RoleName "AcrPull" -Scope $acrId }
} catch {
    Write-Host "Could not assign AcrPull to the kubelet identity; relying on imagePullSecret." -ForegroundColor Yellow
}

Write-Step "Step 7/8: Connect kubectl and wait for the virtual node"
Invoke-AzCli "az aks get-credentials --resource-group $ResourceGroupName --name $AksName --overwrite-existing --only-show-errors"
kubectl get nodes -o wide
if ($LASTEXITCODE -ne 0) { throw "kubectl could not reach the new AKS cluster." }

# Restart the connector so it refreshes network access after the RBAC grant.
kubectl delete pod -n kube-system -l app=aci-connector-linux --ignore-not-found | Out-Null
$virtualNodeName = Wait-ForVirtualNode
Write-Host "Virtual node detected: $virtualNodeName" -ForegroundColor Green

# --- Deploy the confidential ACI ADO agents onto the virtual node -----------

Write-Step "Step 8/8: Deploy confidential ACI ADO agents to the virtual node"

$namespace = "ado-agents"
kubectl create namespace $namespace --dry-run=client -o yaml | kubectl apply -f -

# PAT secret (kept out of any repo file; created directly in the cluster).
kubectl create secret generic ado-pat --namespace $namespace `
    --from-literal=AZP_TOKEN="$AzpToken" `
    --dry-run=client -o yaml | kubectl apply -f -

# ACR pull secret for the virtual-node-backed container group.
$acrUser = (Invoke-AzCli "az acr credential show --name $AcrName --query username -o tsv").Trim()
$acrPass = (Invoke-AzCli "az acr credential show --name $AcrName --query passwords[0].value -o tsv").Trim()
kubectl create secret docker-registry acr-pull --namespace $namespace `
    --docker-server="$acrLoginServer" `
    --docker-username="$acrUser" `
    --docker-password="$acrPass" `
    --dry-run=client -o yaml | kubectl apply -f -

# Resolve the CCE policy value.
switch ($PolicyMode) {
    "debug-allow-all" { $ccePolicy = $DebugAllowAllPolicy }
    "none"            { $ccePolicy = "" }
    "generated"       { $ccePolicy = "" }  # generated in-place below via confcom
}

# Build the concrete Deployment manifest from the template.
$templatePath = Join-Path $PSScriptRoot "ado-agent-virtualnode.yaml"
$manifest = Get-Content -Path $templatePath -Raw

# Drop the Namespace + Secret blocks from the template; we created those above.
$deploymentStart = $manifest.IndexOf("apiVersion: apps/v1")
if ($deploymentStart -ge 0) { $manifest = $manifest.Substring($deploymentStart) }

$manifest = $manifest.Replace("__ACR_IMAGE__", $imageRef)
$manifest = $manifest.Replace("__AZP_URL__", $AzpUrl)
$manifest = $manifest.Replace("__AZP_POOL__", $AzpPool)
$manifest = $manifest.Replace("__REPLICAS__", "$AgentCount")

# Runner-set name lets multiple independent agent pools coexist in the same
# cluster/namespace (distinct Deployment + labels per set).
$runnerSetSafe = ($RunnerSetName.ToLower() -replace "[^a-z0-9-]", "-").Trim("-")
if ([string]::IsNullOrWhiteSpace($runnerSetSafe)) { $runnerSetSafe = "default" }
$manifest = $manifest.Replace("__RUNNER_SET__", $runnerSetSafe)
$deploymentName = "ado-confidential-agent-$runnerSetSafe"

if ($PolicyMode -eq "none") {
    # Remove the ccepolicy annotation line entirely -> standard ACI on virtual node.
    $manifest = ($manifest -split "`n" | Where-Object { $_ -notmatch "microsoft\.containerinstance\.virtualnode\.ccepolicy" }) -join "`n"
} else {
    $manifest = $manifest.Replace("__CCE_POLICY__", $ccePolicy)
}

$manifestOut = Join-Path $env:TEMP ("ado-agent-vnode-" + [Guid]::NewGuid().ToString("N") + ".yaml")
Set-Content -Path $manifestOut -Value $manifest -Encoding utf8

if ($PolicyMode -eq "generated") {
    Write-Host "Generating restrictive CCE policy with confcom..." -ForegroundColor DarkGray
    Invoke-AzCli "az confcom acipolicygen --virtual-node-yaml `"$manifestOut`" -y"
}

try {
    kubectl apply -f $manifestOut
    if ($LASTEXITCODE -ne 0) { throw "Failed to apply the agent Deployment manifest." }

    Write-Host "Waiting for the agent pods to roll out (confidential ACI cold start can take several minutes)..." -ForegroundColor DarkGray
    kubectl rollout status deployment/$deploymentName -n $namespace --timeout=1200s
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Rollout did not complete in time. Inspect with:" -ForegroundColor Yellow
        Write-Host "  kubectl describe pods -n $namespace" -ForegroundColor Yellow
        Write-Host "  kubectl get pods -n $namespace -o wide" -ForegroundColor Yellow
    }
} finally {
    Remove-Item -Path $manifestOut -Force -ErrorAction SilentlyContinue
}

kubectl get pods -n $namespace -o wide

# --- Confidential-SKU validation gate ---------------------------------------
# Virtual-node scheduling of a confidential pod is only trustworthy if the
# backing Azure Container Instance actually came up as sku=Confidential. On some
# clusters/regions the virtual node has been observed to fall back to a Standard
# (non-SEV-SNP) container group, in which case there is NO hardware TEE and
# attestation would be impossible. Assert the SKU here and fail loudly.
if ($PolicyMode -ne "none") {
    Write-Step "Validating backing container groups are Confidential SKU"
    $podNames = @()
    try {
        $raw = kubectl get pods -n $namespace -l app=$deploymentName -o jsonpath='{.items[*].metadata.name}'
        $podNames = ($raw -split '\s+') | Where-Object { $_ }
    } catch { }
    $cgs = @()
    try { $cgs = Invoke-AzCli "az container list --resource-group $nodeResourceGroup -o json" | ConvertFrom-Json } catch { }
    $checked = @()
    $bad = @()
    foreach ($pod in $podNames) {
        foreach ($cg in ($cgs | Where-Object { $_.name -like "*$pod*" })) {
            $checked += "$($cg.name) (sku=$($cg.sku))"
            if ($cg.sku -ne "Confidential") { $bad += "$($cg.name) (sku=$($cg.sku))" }
        }
    }
    if ($checked.Count -eq 0) {
        Write-Host "WARNING: could not map any backing container group to the agent pods. Verify manually:" -ForegroundColor Yellow
        Write-Host "  az container list --resource-group $nodeResourceGroup --query `"[].{name:name,sku:sku}`" -o table" -ForegroundColor Yellow
    } elseif ($bad.Count -gt 0) {
        throw "Confidential-SKU validation FAILED: $($bad -join ', '). The virtual node did not produce a SEV-SNP confidential container group, so these runners have NO hardware TEE. Do not trust them with secrets; investigate confidential ACI capacity/region for this cluster."
    } else {
        Write-Host "Confidential-SKU validation passed: $($checked -join ', ')" -ForegroundColor Green
    }
}

Write-Step "Deployment summary"
Write-Host "Resource group:        $ResourceGroupName"
Write-Host "AKS cluster:           $AksName"
Write-Host "Node resource group:   $nodeResourceGroup"
Write-Host "Virtual node:          $virtualNodeName"
Write-Host "ACI subnet:            $aciSubnetId"
Write-Host "Registry image:        $imageRef"
Write-Host "Agent pool:            $AzpPool"
Write-Host "Runner set:            $runnerSetSafe (deployment $deploymentName)"
Write-Host "Agent replicas:        $AgentCount"
Write-Host "CCE policy mode:       $PolicyMode"
Write-Host ""
Write-Host "Inspect the runners:" -ForegroundColor Green
Write-Host "- Pods on the virtual node:   kubectl get pods -n $namespace -o wide"
Write-Host "- Backing ACI groups:         az container list --resource-group $nodeResourceGroup -o table"
Write-Host "- Confirm registration:       az vm run-command invoke -g $ResourceGroupName -n <ado-vm> --command-id RunPowerShellScript --scripts '@usecase-ado-server-iaas/check-ado-agents.ps1' --parameters 'PoolId=<id>' 'Pat=`$env:AZP_TOKEN' --query 'value[0].message' -o tsv"
if ($PolicyMode -eq "debug-allow-all") {
    Write-Host ""
    Write-Host "NOTE: PolicyMode 'debug-allow-all' runs the agents as confidential ACI but does not enforce the image/identity. Re-run with -PolicyMode generated (and -SkipAksCreate -SkipImageBuild) to bind a restrictive CCE policy." -ForegroundColor Yellow
}
