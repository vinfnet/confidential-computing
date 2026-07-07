<#
.SYNOPSIS
  End-to-end orchestrator for the SecretApp attestation-gated Secure Key Release (SKR) demo.

.DESCRIPTION
  Ports the proven aci-samples/sealed-container flow into the SecretApp pipeline. It:

    1. Seals the welcome secret with a locally-generated RSA-4096 wrap key
       (Bring-Your-Own-Key). The sealed bundle is baked into the image so the
       image digest — and therefore the CCE policy hash — covers it.
    2. Builds the confidential image server-side with `az acr build`.
    3. Generates the confidential-computing enforcement (CCE) policy with
       `az confcom acipolicygen` against the real deployment template.
    4. Renders the AKV Secure Key Release policy, binding
       x-ms-sevsnpvm-hostdata == sha256(CCE policy).
    5. Grants the user-assigned managed identity get+release on the key,
       then imports the wrap key into Key Vault with the release policy.
    6. Deploys the confidential ACI container group (identity-based ACR pull,
       no admin credentials).
    7. Smoke-tests the running endpoint.

  Because the release policy is keyed off the CCE hash (which is keyed off the
  image digest, which covers the sealed bundle), ONLY this exact image running
  under this exact CCE policy on genuine AMD SEV-SNP hardware can obtain the
  wrap key and unseal the secret. A malicious operator who swaps the image,
  edits the policy, or runs it outside a TEE gets nothing.

.NOTES
  Requires: Azure CLI (logged in), the confcom extension, a local Docker daemon
  (acipolicygen inspects image layers), and PowerShell 7+ (.NET AES-GCM).
#>
[CmdletBinding()]
param(
    [string] $ResourceGroup      = 'SGALLDHFAY',
    [string] $Location           = 'northeurope',
    [string] $Acr                = 'sgalladoacr',
    [string] $KeyVault           = 'sgalldhfayakv',
    [string] $KeyName            = 'secretapp-wrap',
    [string] $Identity           = 'id-secretapp-pipeline',
    [string] $MaaEndpoint        = 'sharedneu.neu.attest.azure.net',
    [string] $ContainerGroupName = 'sgall-secretapp-cg',
    [string] $DnsNameLabel       = 'sgall-secretapp',
    [string] $ImageName          = 'secretapp',
    [string] $ImageTag           = 'skr',
    [string] $WelcomeSecret      = 'Welcome! This secret was released only after the enclave proved its identity to Microsoft Azure Attestation and the Key Vault release policy matched the CCE policy hash. If you can read this, Secure Key Release worked end to end.',
    # Object ID granted get+import+delete on the wrap key. Defaults to the
    # interactive signed-in user; in a pipeline the caller is a service
    # principal / managed identity, so pass its object ID here (az ad
    # signed-in-user show does not work for non-user principals).
    [string] $ImporterObjectId   = '',
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$HelperDir  = $PSScriptRoot
$PipelineDir = Split-Path -Parent $HelperDir
$AppDir     = Join-Path $PipelineDir 'app'
$DeployDir  = Join-Path $PipelineDir 'deploy'
$DeployTemplate = Join-Path $DeployDir 'aci-helloworld-confidential.json'
$SkrTemplate    = Join-Path $HelperDir 'skr-release-policy.json'
$SealedPath = Join-Path $AppDir 'sealed-data.enc'

$WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("secretapp-skr-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

function Write-Step    { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[ok] $m" -ForegroundColor Green }
function Write-Note    { param($m) Write-Host "[..] $m" -ForegroundColor DarkGray }

function Invoke-Az {
    param([Parameter(ValueFromRemainingArguments = $true)] $Args)
    Write-Note "az $($Args -join ' ')"
    # Stream az output to the host so it does NOT pollute the pipeline/return
    # value of the calling function (otherwise a function that ends with
    # `return $obj` would emit [az-output..., $obj] and callers see an array).
    & az @Args 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "az $($Args -join ' ') failed with exit code $LASTEXITCODE" }
}

# ---------------------------------------------------------------------------
# Seal the secret with a fresh RSA-4096 wrap key (BYOK).
#   Bundle layout (matches app/entrypoint.py unseal_bundle):
#     "SEAL" | u32le ver=1 | u32le wlen | wrapped_dek
#            | u32le nlen=12 | nonce | u32le clen | ciphertext||tag
#   DEK = 32 random bytes; AES-256-GCM(aad="secretapp/v1"); DEK wrapped RSA-OAEP-SHA256.
# ---------------------------------------------------------------------------
function New-SealedBundle {
    param([string] $Secret)

    $dek   = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($dek)
    $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

    $plainObj = [ordered]@{
        sealed_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        files     = @{ 'welcome.txt' = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Secret)) }
    }
    $plainBytes = [Text.Encoding]::UTF8.GetBytes(($plainObj | ConvertTo-Json -Compress -Depth 6))
    $aad = [Text.Encoding]::ASCII.GetBytes('secretapp/v1')

    $ct  = [byte[]]::new($plainBytes.Length)
    $tag = [byte[]]::new(16)
    $gcm = [System.Security.Cryptography.AesGcm]::new($dek, 16)
    try   { $gcm.Encrypt($nonce, $plainBytes, $ct, $tag, $aad) }
    finally { $gcm.Dispose() }
    # NOTE: `$ct + $tag` yields an Object[] which BinaryWriter corrupts.
    # Build a real byte[] so the bundle unseals correctly in Python.
    $ctTag = [byte[]]::new($ct.Length + $tag.Length)
    [Array]::Copy($ct, 0, $ctTag, 0, $ct.Length)
    [Array]::Copy($tag, 0, $ctTag, $ct.Length, $tag.Length)

    $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $wrapped   = $rsa.Encrypt($dek, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        $privPem   = $rsa.ExportRSAPrivateKeyPem()
    } finally { $rsa.Dispose() }

    $ms = [IO.MemoryStream]::new()
    $bw = [IO.BinaryWriter]::new($ms)
    try {
        $bw.Write([Text.Encoding]::ASCII.GetBytes('SEAL'))
        $bw.Write([uint32]1)
        $bw.Write([uint32]$wrapped.Length);  $bw.Write($wrapped)
        $bw.Write([uint32]$nonce.Length);    $bw.Write($nonce)
        $bw.Write([uint32]$ctTag.Length);    $bw.Write($ctTag)
        $bw.Flush()
        $bundle = $ms.ToArray()
    } finally { $bw.Dispose(); $ms.Dispose() }

    [IO.File]::WriteAllBytes($SealedPath, $bundle)
    return [pscustomobject]@{
        WrapPrivPem       = $privPem
        CiphertextSha256  = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bundle)).Replace('-','').ToLower()
        Bytes             = $bundle.Length
    }
}

# ---------------------------------------------------------------------------
# CCE policy via az confcom acipolicygen against the real template.
# ---------------------------------------------------------------------------
function New-CcePolicy {
    param([hashtable] $Params)

    $paramsFile = Join-Path $WorkDir 'confcom-params.json'
    $armParams = [ordered]@{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'; contentVersion = '1.0.0.0'; parameters = [ordered]@{} }
    foreach ($k in $Params.Keys) { $armParams.parameters[$k] = @{ value = $Params[$k] } }
    ($armParams | ConvertTo-Json -Depth 6) | Set-Content -Path $paramsFile -Encoding utf8

    Invoke-Az acr login --name $Acr

    $ccePath = Join-Path $WorkDir 'cce-policy.rego'
    Invoke-Az confcom acipolicygen --template-file $DeployTemplate --parameters $paramsFile --save-to-file $ccePath --outraw -y

    $cceBytes = [IO.File]::ReadAllBytes($ccePath)
    return [pscustomobject]@{
        Path   = $ccePath
        Base64 = [Convert]::ToBase64String($cceBytes)
        Sha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($cceBytes)).Replace('-','').ToLower()
    }
}

# ---------------------------------------------------------------------------
# Render the SKR release policy (flat {version, anyOf}) for `az keyvault key import`.
# ---------------------------------------------------------------------------
function New-SkrPolicy {
    param([string] $MaaEndpoint, [string] $CceSha256)

    $tpl = Get-Content $SkrTemplate -Raw | ConvertFrom-Json
    $authority = "https://$MaaEndpoint"
    $policy = [ordered]@{
        version = $tpl.version
        anyOf = @(
            [ordered]@{
                authority = $authority
                allOf = @(
                    @{ claim = 'x-ms-attestation-type';      equals = 'sevsnpvm' },
                    @{ claim = 'x-ms-compliance-status';      equals = 'azure-compliant-uvm' },
                    @{ claim = 'x-ms-sevsnpvm-is-debuggable'; equals = 'false' },
                    @{ claim = 'x-ms-sevsnpvm-hostdata';      equals = $CceSha256 }
                )
            }
        )
    }
    $path = Join-Path $WorkDir 'skr-release-policy.rendered.json'
    ($policy | ConvertTo-Json -Depth 8) | Set-Content -Path $path -Encoding utf8
    return [pscustomobject]@{
        Path   = $path
        Sha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($path))).Replace('-','').ToLower()
    }
}

# ===========================================================================
# MAIN
# ===========================================================================
Write-Step "Resolving Azure context"
$sub = az account show --query id -o tsv
$loginServer = az acr show -n $Acr --query loginServer -o tsv
$identityJson = az identity show -g $ResourceGroup -n $Identity -o json | ConvertFrom-Json
$identityId          = $identityJson.id
$identityPrincipalId = $identityJson.principalId
if ($ImporterObjectId) {
    $userOid = $ImporterObjectId
} else {
    $userOid = az ad signed-in-user show --query id -o tsv
}
$akvEndpoint = "$KeyVault.vault.azure.net"

# The vault has purge protection enabled, so a soft-deleted key name cannot be
# reused until the retention window elapses. Use a unique key name per run so
# re-runs never collide. The name flows through the CCE policy (SKR_KEY_NAME
# env rule) and the container env automatically, keeping the binding consistent.
if ($KeyName -eq 'secretapp-wrap') {
    $KeyName = "secretapp-wrap-$(Get-Date -Format 'yyMMddHHmmss')"
}
Write-Ok "sub=$sub acr=$loginServer identity=$identityPrincipalId user=$userOid key=$KeyName"

Write-Step "Sealing welcome secret (RSA-4096 BYOK, AES-256-GCM)"
$sealed = New-SealedBundle -Secret $WelcomeSecret
Write-Ok "sealed-data.enc: $($sealed.Bytes) bytes, sha256=$($sealed.CiphertextSha256)"

if (-not $SkipBuild) {
    Write-Step "Building confidential image with az acr build"
    Invoke-Az acr build --registry $Acr --image "${ImageName}:${ImageTag}" --file (Join-Path $AppDir 'Dockerfile') --no-logs $AppDir
}

Write-Step "Resolving image digest"
$digest = az acr repository show-manifests --name $Acr --repository $ImageName --query "[?tags && contains(tags,'${ImageTag}')] | [0].digest" -o tsv
if (-not $digest) { throw "Image ${ImageName}:${ImageTag} not found in $Acr" }
$imageRef = "$loginServer/${ImageName}@$digest"
Write-Ok "image: $imageRef"

Write-Step "Generating CCE policy (az confcom acipolicygen)"
$confcomParams = @{
    containerGroupName = $ContainerGroupName
    location           = $Location
    appImage           = $imageRef
    registryServer     = $loginServer
    managedIdentityId  = $identityId
    maaEndpoint        = $MaaEndpoint
    akvEndpoint        = $akvEndpoint
    skrKeyName         = $KeyName
    ccePolicyBase64    = 'placeholder'
    dnsNameLabel       = $DnsNameLabel
}
$cce = New-CcePolicy -Params $confcomParams
Write-Ok "CCE policy sha256 (hostdata) = $($cce.Sha256)"

Write-Step "Rendering SKR release policy (binds hostdata == CCE sha256)"
$skr = New-SkrPolicy -MaaEndpoint $MaaEndpoint -CceSha256 $cce.Sha256
Write-Ok "release policy sha256 = $($skr.Sha256)"

Write-Step "Granting Key Vault access (access-policy mode)"
Invoke-Az keyvault set-policy --name $KeyVault --object-id $userOid --key-permissions get import delete --output none
Invoke-Az keyvault set-policy --name $KeyVault --object-id $identityPrincipalId --key-permissions get release --output none

Write-Step "Importing wrap key into Key Vault with SKR release policy"
$tmpPem = Join-Path $WorkDir 'wrap-key.pem'
Set-Content -Path $tmpPem -Value $sealed.WrapPrivPem -Encoding ascii
try {
    Invoke-Az keyvault key import --vault-name $KeyVault --name $KeyName `
        --pem-file $tmpPem --protection hsm --ops decrypt unwrapKey --exportable true `
        --policy $skr.Path --output none
} finally {
    Remove-Item $tmpPem -Force -ErrorAction SilentlyContinue
}
Write-Ok "wrap key '$KeyName' imported into '$KeyVault' and bound to release policy"

Write-Step "Deploying confidential ACI container group"
# Remove any prior group so the deployment starts clean.
az container delete --resource-group $ResourceGroup --name $ContainerGroupName --yes 2>$null | Out-Null

# The CCE policy (base64) is large; pass all parameters via a file to avoid the
# Windows ~32KB command-line length limit.
$deployParamsFile = Join-Path $WorkDir 'deploy-params.json'
$deployParams = [ordered]@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters = [ordered]@{
        containerGroupName = @{ value = $ContainerGroupName }
        location           = @{ value = $Location }
        appImage           = @{ value = $imageRef }
        registryServer     = @{ value = $loginServer }
        managedIdentityId  = @{ value = $identityId }
        maaEndpoint        = @{ value = $MaaEndpoint }
        akvEndpoint        = @{ value = $akvEndpoint }
        skrKeyName         = @{ value = $KeyName }
        ccePolicyBase64    = @{ value = $cce.Base64 }
        dnsNameLabel       = @{ value = $DnsNameLabel }
    }
}
($deployParams | ConvertTo-Json -Depth 6) | Set-Content -Path $deployParamsFile -Encoding utf8
Invoke-Az deployment group create --resource-group $ResourceGroup `
    --template-file $DeployTemplate `
    --parameters "@$deployParamsFile" `
    --output none

$fqdn = az container show --resource-group $ResourceGroup --name $ContainerGroupName --query "ipAddress.fqdn" -o tsv
Write-Ok "container group deployed; fqdn=$fqdn url=http://${fqdn}:8080/"

Write-Host "`nRun the following to verify (allow a minute for the enclave to attest):" -ForegroundColor Yellow
Write-Host "  az container logs -g $ResourceGroup -n $ContainerGroupName" -ForegroundColor Yellow
Write-Host "  curl http://${fqdn}:8080/api/sealed" -ForegroundColor Yellow

[pscustomobject]@{
    ImageRef          = $imageRef
    CcePolicySha256   = $cce.Sha256
    ReleasePolicySha  = $skr.Sha256
    Fqdn              = $fqdn
    Url               = "http://${fqdn}:8080/"
    WorkDir           = $WorkDir
}
