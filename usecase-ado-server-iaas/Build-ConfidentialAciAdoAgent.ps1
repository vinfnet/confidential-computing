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
    [string]$KeyVaultName = "",

    [Parameter(Mandatory = $false)]
    [string]$PatSecretName = "ado-agent-pat",

    [Parameter(Mandatory = $false)]
    [switch]$StorePatInKeyVault,

    # --- Secure Key Release (attestation-gated PAT) -------------------------
    # When set, the PAT is sealed under an HSM-backed wrap key whose AKV
    # release policy demands a fresh SEV-SNP MAA attestation (non-debuggable,
    # azure-compliant-uvm, hostdata == sha256(cce-policy)). The PAT is only
    # unsealed inside the attested TEE, so a leaked managed-identity token
    # cannot obtain it. Requires -KeyVaultName (Premium) + -UserAssignedIdentityResourceId + -MaaEndpoint.
    [Parameter(Mandatory = $false)]
    [switch]$UseSecureKeyRelease,

    [Parameter(Mandatory = $false)]
    [string]$MaaEndpoint = "",

    [Parameter(Mandatory = $false)]
    [string]$SkrKeyName = "ado-pat-wrap-key",

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

function New-SealedPatBundle {
    <#
        Seals a PAT into the versioned SEAL bundle consumed by skr-pat.py:
          [ 0..3 ]  magic     "SEAL"
          [ 4..7 ]  version   uint32 LE (=1)
          [u32 wrap_len][wrapped_dek RSA-OAEP-SHA256]
          [u32 nonce_len][nonce 12B]
          [u32 ct_len][AES-256-GCM(plaintext, aad="ado-pat/v1")]
        The plaintext is JSON {"pat":"<token>"}. The 32-byte DEK is wrapped to
        a fresh RSA-3072 key; that key's PRIVATE half is imported into AKV under
        an SKR release policy, so only an attested TEE can unwrap it.
        Returns @{ BundleB64; WrapPrivPem }.
    #>
    param([Parameter(Mandatory)] [string]$Pat)

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $dek = New-Object byte[] 32 ; $rng.GetBytes($dek)
    $nonce = New-Object byte[] 12 ; $rng.GetBytes($nonce)

    $plainBytes = [Text.Encoding]::UTF8.GetBytes((@{ pat = $Pat } | ConvertTo-Json -Compress))
    $aad = [Text.Encoding]::ASCII.GetBytes("ado-pat/v1")
    $aes = [System.Security.Cryptography.AesGcm]::new($dek)
    $ct  = New-Object byte[] $plainBytes.Length
    $tag = New-Object byte[] 16
    $aes.Encrypt($nonce, $plainBytes, $ct, $tag, $aad)
    $aes.Dispose()
    # The Python 'cryptography' AESGCM expects the tag appended to the ciphertext.
    $ctTag = New-Object byte[] ($ct.Length + 16)
    [Array]::Copy($ct, 0, $ctTag, 0, $ct.Length)
    [Array]::Copy($tag, 0, $ctTag, $ct.Length, 16)

    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    $wrapped = $rsa.Encrypt($dek, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $privPem = $rsa.ExportRSAPrivateKeyPem()
    $rsa.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter $ms
    $bw.Write([byte[]]([Text.Encoding]::ASCII.GetBytes("SEAL")))
    $bw.Write([uint32]1)
    $bw.Write([uint32]$wrapped.Length); $bw.Write($wrapped)
    $bw.Write([uint32]$nonce.Length);   $bw.Write($nonce)
    $bw.Write([uint32]$ctTag.Length);   $bw.Write($ctTag)
    $bw.Flush()
    $bundleBytes = $ms.ToArray()
    $bw.Dispose(); $ms.Dispose()

    # Wipe the DEK from managed memory now that it is wrapped.
    [Array]::Clear($dek, 0, $dek.Length)

    return @{
        BundleB64   = [Convert]::ToBase64String($bundleBytes)
        WrapPrivPem = $privPem
    }
}

$useKeyVault = -not [string]::IsNullOrWhiteSpace($KeyVaultName)
$useSkr = [bool]$UseSecureKeyRelease

if ($useSkr) {
    if ([string]::IsNullOrWhiteSpace($KeyVaultName)) {
        throw "-UseSecureKeyRelease requires -KeyVaultName (a Premium vault that can host an HSM-backed, exportable wrap key)."
    }
    if ([string]::IsNullOrWhiteSpace($UserAssignedIdentityResourceId)) {
        throw "-UseSecureKeyRelease requires -UserAssignedIdentityResourceId so the confidential agent can call Key Vault /release via managed identity from inside the TEE."
    }
    if ([string]::IsNullOrWhiteSpace($MaaEndpoint)) {
        throw "-UseSecureKeyRelease requires -MaaEndpoint (regional Microsoft Azure Attestation host, e.g. sharedneu.neu.attest.azure.net)."
    }
    # Normalise the MAA endpoint to a bare host (the release policy pins https://<host>).
    $MaaEndpoint = ($MaaEndpoint -replace '^https://', '').TrimEnd('/')
    # SKR is the strongest mode; it supersedes the plain Key Vault secret fetch.
    $useKeyVault = $false
}

# The PAT is required when it is passed directly to the container (non-Key Vault mode),
# when we are asked to seed it into Key Vault, or when it must be sealed for SKR.
# In pure Key Vault-retrieval mode the secret is assumed to already exist in the vault.
if ($useSkr -or (-not $useKeyVault) -or $StorePatInKeyVault) {
    if ([string]::IsNullOrWhiteSpace($AzpToken)) {
        if (-not [string]::IsNullOrWhiteSpace($env:AZP_TOKEN)) {
            $AzpToken = $env:AZP_TOKEN
        } else {
            throw "Provide -AzpToken (or set AZP_TOKEN env var) for Azure DevOps agent registration."
        }
    }
}

Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

$prefixSafe = New-SafeName -Raw $Prefix -MaxLength 18 -Fallback "adocaci"
if ($AgentCount -lt 1) { throw "-AgentCount must be at least 1." }

$useVnet = -not [string]::IsNullOrWhiteSpace($VnetName)
if ($useVnet -and [string]::IsNullOrWhiteSpace($VnetResourceGroup)) { $VnetResourceGroup = $ResourceGroupName }
$subnetResourceId = ""
$useIdentity = -not [string]::IsNullOrWhiteSpace($UserAssignedIdentityResourceId)

# --- Key Vault-backed PAT retrieval (PAT never enters the ARM template or container env) ---
# When -KeyVaultName is supplied, the agent fetches the PAT at runtime from Key Vault using
# its user-assigned managed identity, so the token only ever exists in-memory inside the
# confidential (SEV-SNP) TEE. This requires the managed identity to be attached to the ACI.
$miClientId = ""
if ($useKeyVault) {
    if (-not $useIdentity) {
        throw "Key Vault PAT retrieval (-KeyVaultName) requires -UserAssignedIdentityResourceId so the confidential agent can authenticate to Key Vault via managed identity."
    }

    Write-Host "=== Step 0/7: Configure Key Vault-backed PAT retrieval ===" -ForegroundColor Cyan

    $identity = Invoke-AzCli "az identity show --ids $UserAssignedIdentityResourceId --output json" | ConvertFrom-Json
    $miClientId = $identity.clientId
    $miPrincipalId = $identity.principalId
    Write-Host "Managed identity clientId=$miClientId principalId=$miPrincipalId" -ForegroundColor DarkGray

    $kv = Invoke-AzCli "az keyvault show --name $KeyVaultName --output json" | ConvertFrom-Json
    $kvId = $kv.id

    if ($StorePatInKeyVault) {
        Write-Host "Storing PAT in Key Vault '$KeyVaultName' as secret '$PatSecretName'..." -ForegroundColor DarkGray
        Invoke-AzCli "az keyvault secret set --vault-name $KeyVaultName --name $PatSecretName --value $AzpToken --output none"
        # Drop the plaintext PAT from this process now that it lives in the vault.
        $AzpToken = ""
    }

    # Grant the managed identity read-only access to the secret, honouring the vault's
    # authorization model (RBAC vs. classic access policies).
    if ($kv.properties.enableRbacAuthorization) {
        Write-Host "Vault uses RBAC; assigning 'Key Vault Secrets User' to the managed identity..." -ForegroundColor DarkGray
        az role assignment create --assignee-object-id $miPrincipalId --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope $kvId --output none 2>$null
    } else {
        Write-Host "Vault uses access policies; granting secret 'get' to the managed identity..." -ForegroundColor DarkGray
        Invoke-AzCli "az keyvault set-policy --name $KeyVaultName --object-id $miPrincipalId --secret-permissions get --output none"
    }
}

# --- Secure Key Release: attestation-gated PAT --------------------------------
# The PAT is sealed under an HSM-backed wrap key. AKV only releases that key to a
# container that presents a fresh SEV-SNP MAA token satisfying the release policy
# (sevsnpvm + azure-compliant-uvm + is-debuggable=false + hostdata==sha256(cce-policy)).
# The wrap key is imported LATER (after the CCE policy hash is known); here we only
# resolve the identity, ensure a Premium vault, grant get+release, and seal the PAT.
$sealedPatB64 = ""
$wrapPrivPem = ""
$akvEndpoint = ""
if ($useSkr) {
    Write-Host "=== Step 0/7: Configure Secure Key Release (attestation-gated PAT) ===" -ForegroundColor Cyan

    $identity = Invoke-AzCli "az identity show --ids $UserAssignedIdentityResourceId --output json" | ConvertFrom-Json
    $miClientId = $identity.clientId
    $miPrincipalId = $identity.principalId
    Write-Host "Managed identity clientId=$miClientId principalId=$miPrincipalId" -ForegroundColor DarkGray

    az keyvault show --name $KeyVaultName --only-show-errors --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Creating Premium Key Vault '$KeyVaultName' (required for HSM-backed SKR keys)..." -ForegroundColor DarkGray
        Invoke-AzCli "az keyvault create --name $KeyVaultName --resource-group $ResourceGroupName --location $Location --sku premium --enabled-for-deployment false --output none"
    }
    $kv = Invoke-AzCli "az keyvault show --name $KeyVaultName --output json" | ConvertFrom-Json
    $kvId = $kv.id
    if ($kv.properties.sku.name -ne "premium") {
        throw "Key Vault '$KeyVaultName' is SKU '$($kv.properties.sku.name)'. Secure Key Release requires a Premium vault (HSM-backed keys). Use a Premium vault or Managed HSM."
    }
    $akvEndpoint = "$KeyVaultName.vault.azure.net"

    # Grant the managed identity get + release on keys, honouring the vault's auth model.
    if ($kv.properties.enableRbacAuthorization) {
        Write-Host "Vault uses RBAC; assigning key get + release roles to the managed identity..." -ForegroundColor DarkGray
        az role assignment create --assignee-object-id $miPrincipalId --assignee-principal-type ServicePrincipal --role "Key Vault Crypto User" --scope $kvId --output none 2>$null
        az role assignment create --assignee-object-id $miPrincipalId --assignee-principal-type ServicePrincipal --role "Key Vault Crypto Service Release User" --scope $kvId --output none 2>$null
    } else {
        Write-Host "Vault uses access policies; granting key 'get' + 'release' to the managed identity..." -ForegroundColor DarkGray
        Invoke-AzCli "az keyvault set-policy --name $KeyVaultName --object-id $miPrincipalId --key-permissions get release --output none"
    }

    Write-Host "Sealing PAT into SEAL bundle (RSA-OAEP-SHA256 + AES-256-GCM)..." -ForegroundColor DarkGray
    $sealed = New-SealedPatBundle -Pat $AzpToken
    $sealedPatB64 = $sealed.BundleB64
    $wrapPrivPem = $sealed.WrapPrivPem
    # Drop the plaintext PAT from this process now that it is sealed.
    $AzpToken = ""
}

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

if ($useSkr) {
    # SKR image: multi-stage. Stage 1 builds get-snp-report from the pinned
    # confidential-sidecar-containers tag; stage 2 adds Python + the release
    # helper so the agent can attest and unseal the PAT inside the TEE.
    $dockerfile = @"
FROM mcr.microsoft.com/mirror/docker/library/debian:bookworm-slim AS snp-build
ARG SIDECAR_TAG=v2.14
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make gcc libc6-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch `${SIDECAR_TAG} https://github.com/microsoft/confidential-sidecar-containers.git /src
WORKDIR /src/tools/get-snp-report
RUN make bin/get-snp-report

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV TARGETARCH=linux-x64
ENV GET_SNP_REPORT=/usr/local/bin/get-snp-report

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    libicu70 \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir cryptography requests \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /azp
COPY --from=snp-build /src/tools/get-snp-report/bin/get-snp-report /usr/local/bin/get-snp-report
COPY ./skr-pat.py /azp/skr-pat.py
COPY ./start.sh ./start.sh
RUN chmod +x ./start.sh /usr/local/bin/get-snp-report \
    && useradd --create-home --home-dir /home/azp azp \
    && chown -R azp /azp

USER azp
ENTRYPOINT [ "./start.sh" ]
"@

    # Ship the release helper into the build context (maintained as a single file in the repo).
    Copy-Item -Path (Join-Path $PSScriptRoot "skr-pat.py") -Destination (Join-Path $tempRoot "skr-pat.py") -Force
}

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
    if [ -n "${AZP_KEYVAULT_NAME}" ] && [ -n "${AZP_TOKEN_SECRET_NAME}" ]; then
      # Confidential retrieval: pull the PAT from Key Vault using this container's
      # user-assigned managed identity. The token only ever lives in-memory inside
      # the SEV-SNP TEE; it is never baked into the image or the ARM deployment.
      echo "Retrieving PAT from Key Vault ${AZP_KEYVAULT_NAME} via managed identity..."
      if [ -n "${AZP_MI_CLIENT_ID}" ]; then
        az login --identity --client-id "${AZP_MI_CLIENT_ID}" --allow-no-subscriptions --output none
      else
        az login --identity --allow-no-subscriptions --output none
      fi
      AZP_TOKEN="$(az keyvault secret show --vault-name "${AZP_KEYVAULT_NAME}" --name "${AZP_TOKEN_SECRET_NAME}" --query value -o tsv)"
      az logout --output none 2>/dev/null || true
      if [ -z "${AZP_TOKEN}" ]; then
        echo 1>&2 "error: failed to retrieve PAT from Key Vault ${AZP_KEYVAULT_NAME} (secret ${AZP_TOKEN_SECRET_NAME})"
        exit 1
      fi
    else
      echo 1>&2 "error: missing AZP_TOKEN environment variable"
      exit 1
    fi
  fi
  AZP_TOKEN_FILE=/azp/.token
  echo -n "${AZP_TOKEN}" > "${AZP_TOKEN_FILE}"
fi

unset AZP_TOKEN AZP_MI_CLIENT_ID

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

if ($useSkr) {
    # Attestation-gated PAT release runs FIRST, before any registration. skr-pat.py
    # attests to MAA, releases the wrap key, unseals the PAT to AZP_TOKEN_FILE (tmpfs),
    # and fails closed. We inject it ahead of the existing token-resolution block so
    # that AZP_TOKEN_FILE is already populated and the KV/direct branches are skipped.
    $skrBlock = @'
if [ -n "${SEALED_PAT_B64}" ]; then
  echo "Performing attestation-gated PAT release (Secure Key Release)..."
  export AZP_TOKEN_FILE="${AZP_TOKEN_FILE:-/azp/.token}"
  python3 /azp/skr-pat.py || { echo 1>&2 "error: attestation-gated PAT release failed"; exit 1; }
  if [ ! -s "${AZP_TOKEN_FILE}" ]; then
    echo 1>&2 "error: attestation-gated PAT release produced no token"
    exit 1
  fi
fi
unset SEALED_PAT_B64

'@
    # Literal .Replace (no regex/$ substitution) to prepend the SKR step to the
    # token-resolution block.
    $anchor = 'if [ -z "${AZP_TOKEN_FILE}" ]; then'
    $startSh = $startSh.Replace($anchor, $skrBlock + $anchor)
}

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

if ($useSkr) {
    # SKR mode: the sealed PAT bundle is passed as a SECURE env var (excluded from the
    # CCE policy), together with the non-secret MAA/AKV/key-name coordinates and the
    # managed-identity clientId. The plaintext PAT is only ever produced inside the TEE
    # after a successful attestation-gated Key Vault release.
    $tokenParamDef = '"sealedPatB64": { "type": "securestring" }, "maaEndpoint": { "type": "string" }, "akvEndpoint": { "type": "string" }, "skrKeyName": { "type": "string" }, "azpMiClientId": { "type": "string" }, '
    $tokenEnvBlock = "{ `"name`": `"SEALED_PAT_B64`", `"secureValue`": `"[parameters('sealedPatB64')]`" },`n                { `"name`": `"MAA_ENDPOINT`", `"value`": `"[parameters('maaEndpoint')]`" },`n                { `"name`": `"AKV_ENDPOINT`", `"value`": `"[parameters('akvEndpoint')]`" },`n                { `"name`": `"SKR_KEY_NAME`", `"value`": `"[parameters('skrKeyName')]`" },`n                { `"name`": `"AZP_MI_CLIENT_ID`", `"value`": `"[parameters('azpMiClientId')]`" },`n                { `"name`": `"AZP_TOKEN_FILE`", `"value`": `"/azp/.token`" },"
} elseif ($useKeyVault) {
    # Key Vault mode: no PAT is placed in the template. Only the (non-secret) vault name,
    # secret name and managed-identity clientId are passed so the agent can fetch the PAT
    # itself at runtime inside the TEE.
    $tokenParamDef = '"azpKeyVaultName": { "type": "string" }, "azpTokenSecretName": { "type": "string" }, "azpMiClientId": { "type": "string" }, '
    $tokenEnvBlock = "{ `"name`": `"AZP_KEYVAULT_NAME`", `"value`": `"[parameters('azpKeyVaultName')]`" },`n                { `"name`": `"AZP_TOKEN_SECRET_NAME`", `"value`": `"[parameters('azpTokenSecretName')]`" },`n                { `"name`": `"AZP_MI_CLIENT_ID`", `"value`": `"[parameters('azpMiClientId')]`" },"
} else {
    $tokenParamDef = '"azpToken": { "type": "securestring" }, '
    $tokenEnvBlock = "{ `"name`": `"AZP_TOKEN`", `"secureValue`": `"[parameters('azpToken')]`" },"
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
    $tokenParamDef$identityParamDef$subnetParamDef"azpAgentName": { "type": "string" }
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
                $tokenEnvBlock
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
            azpAgentName = @{ value = $AgentName }
        }
    }
    if ($useSkr) {
        $p.parameters.sealedPatB64 = @{ value = $sealedPatB64 }
        $p.parameters.maaEndpoint = @{ value = $MaaEndpoint }
        $p.parameters.akvEndpoint = @{ value = $akvEndpoint }
        $p.parameters.skrKeyName = @{ value = $SkrKeyName }
        $p.parameters.azpMiClientId = @{ value = $miClientId }
    } elseif ($useKeyVault) {
        $p.parameters.azpKeyVaultName = @{ value = $KeyVaultName }
        $p.parameters.azpTokenSecretName = @{ value = $PatSecretName }
        $p.parameters.azpMiClientId = @{ value = $miClientId }
    } else {
        $p.parameters.azpToken = @{ value = $AzpToken }
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

if ($useSkr) {
    # Print mode: emit the RAW CCE policy so we can hash it (= SEV-SNP HOST_DATA)
    # and bind the wrap key's release policy to that exact hash, then base64 it into
    # the template ourselves. --approve-wildcards keeps a single policy valid for
    # every agent despite the per-agent AZP_AGENT_NAME env value.
    $cceRawPath = Join-Path $tempRoot "cce-policy.rego"
    Invoke-AzCli "az confcom acipolicygen --template-file $templatePath --parameters $policyParamsPath --save-to-file $cceRawPath --outraw --approve-wildcards$stdioFlag -y"
    if (-not (Test-Path $cceRawPath)) { throw "confcom did not produce $cceRawPath" }

    $cceBytes = [System.IO.File]::ReadAllBytes($cceRawPath)
    $cceSha = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($cceBytes))).Replace('-', '').ToLower()
    $cceB64 = [Convert]::ToBase64String($cceBytes)
    Write-Host "CCE policy sha256 (HOST_DATA) = $cceSha" -ForegroundColor DarkGray

    # Inject the base64 policy into the template's ccePolicy (literal replace; base64 has no regex metachars).
    $templateContent = [System.IO.File]::ReadAllText($templatePath)
    $templateContent = $templateContent.Replace('"ccePolicy": ""', '"ccePolicy": "' + $cceB64 + '"')
    [System.IO.File]::WriteAllText($templatePath, $templateContent)

    # Render the AKV release policy bound to this MAA endpoint + CCE hash.
    $releasePolicy = [ordered]@{
        version = "1.0.0"
        anyOf = @(
            [ordered]@{
                authority = "https://$MaaEndpoint"
                allOf = @(
                    [ordered]@{ claim = "x-ms-attestation-type"; equals = "sevsnpvm" }
                    [ordered]@{ claim = "x-ms-compliance-status"; equals = "azure-compliant-uvm" }
                    [ordered]@{ claim = "x-ms-sevsnpvm-is-debuggable"; equals = "false" }
                    [ordered]@{ claim = "x-ms-sevsnpvm-hostdata"; equals = $cceSha }
                )
            }
        )
    }
    $releasePolicyPath = Join-Path $tempRoot "skr-release-policy.json"
    $releasePolicy | ConvertTo-Json -Depth 20 | Set-Content -Path $releasePolicyPath -Encoding utf8

    # Import the wrap key (private half) into the Premium vault with the release policy.
    Write-Host "Importing wrap key '$SkrKeyName' into '$KeyVaultName' with SKR release policy..." -ForegroundColor DarkGray
    $wrapPemPath = Join-Path $tempRoot ("wrap-key-" + [Guid]::NewGuid().ToString("N") + ".pem")
    $utf8NoBomPem = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($wrapPemPath, $wrapPrivPem, $utf8NoBomPem)
    try {
        Invoke-AzCli "az keyvault key import --vault-name $KeyVaultName --name $SkrKeyName --pem-file `"$wrapPemPath`" --protection hsm --ops decrypt unwrapKey --exportable true --policy `"$releasePolicyPath`" --output none"
    } finally {
        Remove-Item $wrapPemPath -Force -ErrorAction SilentlyContinue
        $wrapPrivPem = ""
    }
    Write-Host "Wrap key imported and bound to attestation release policy." -ForegroundColor DarkGray
} else {
    Invoke-AzCli "az confcom acipolicygen -a $templatePath --parameters $policyParamsPath$stdioFlag --approve-wildcards"
}

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
$skuFailures = @()
foreach ($cg in $deployed) {
    $state = Invoke-AzCli "az container show --resource-group $ResourceGroupName --name $cg --query `"{name:name,state:instanceView.state,sku:sku,cce:confidentialComputeProperties}`" -o json"
    Write-Host $state
    # Validation gate: assert the backing container group is genuinely Confidential.
    # A Standard SKU (or missing confidentialComputeProperties) means no SEV-SNP TEE,
    # so attestation would fail and (in SKR mode) the PAT would never release.
    $stateObj = $state | ConvertFrom-Json
    if ($stateObj.sku -ne "Confidential" -or $null -eq $stateObj.cce) {
        $skuFailures += "$cg (sku=$($stateObj.sku))"
    }
}
if ($skuFailures.Count -gt 0) {
    $joined = $skuFailures -join ", "
    throw "Confidential-SKU validation FAILED for: $joined. These container groups are not running as SEV-SNP confidential VMs (sku != Confidential / no confidentialComputeProperties), so hardware attestation is unavailable. Investigate confidential capacity/region before trusting these agents."
}
Write-Host "Confidential-SKU validation passed: all $($deployed.Count) agent(s) report sku=Confidential." -ForegroundColor Green

Write-Host "=== Step 7/7: Summary ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Confidential ACI ADO agent deployment complete." -ForegroundColor Green
Write-Host "Resource Group: $ResourceGroupName"
Write-Host "Agents deployed: $AgentCount"
foreach ($cg in $deployed) { Write-Host "  Container Group: $cg" }
Write-Host "Image: $imageRef"
Write-Host "Azure DevOps URL: $AzpUrl"
Write-Host "Pool: $AzpPool"
if ($useSkr) {
    Write-Host "PAT source: Secure Key Release — sealed under HSM wrap key '$SkrKeyName' in Premium vault '$KeyVaultName'."
    Write-Host "            Released only to an attested SEV-SNP TEE (MAA '$MaaEndpoint', hostdata bound to the CCE policy)."
}
if ($useKeyVault) {
    Write-Host "PAT source: Key Vault '$KeyVaultName' secret '$PatSecretName' (fetched at runtime via managed identity inside the TEE)"
}
if ($useVnet) {
    Write-Host "VNet: $VnetName ($VnetResourceGroup)"
    Write-Host "ACI subnet: $AgentSubnetName ($AgentSubnetPrefix)"
}
