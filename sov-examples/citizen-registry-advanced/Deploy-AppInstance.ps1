<#
.SYNOPSIS
    Deploy App Instance for Citizen Registry Advanced Demo.

.DESCRIPTION
    Stage 2: Creates app instance resource group containing:
    - NCC40ads H100 Confidential GPU VM with an AMD SEV-SNP CPU TEE
    - Database on ACC (private subnet)
    - Bastion host for secure access
    - Azure Attestation Service
    - Private Link to shared Managed HSM
    
    Requires Stage 1 (shared infrastructure) to be deployed first.

.PARAMETER Prefix
    REQUIRED. Short unique identifier (3-12 chars) for resource naming.
    Combined with random 5-digit suffix: {prefix}{random}app

.PARAMETER Location
    Azure region for the H100 app tier. Defaults to "westeurope".

.PARAMETER SqlLocation
    Azure region for the SQL confidential VM. Defaults to "northeurope".

.PARAMETER SharedInfraRg
    REQUIRED. Name of the shared infrastructure resource group from Stage 1.
    Example: "yourprefixsharedinfra"

.PARAMETER AppCvmSize
    Confidential GPU VM SKU. Defaults to "Standard_NCC40ads_H100_v5".

.PARAMETER SqlCvmSize
    SQL Server Confidential VM SKU. Defaults to "Standard_DC2as_v5".

.PARAMETER PkiMode
    TLS private-key mode. FileBackedDemo preserves the current generated demo keys.
    ManagedHsm provisions a dedicated identity for Managed HSM TLS offload.

.PARAMETER Deploy
    Execute the deployment.

.PARAMETER ValidateOnly
    Validate Bicep templates without deployment.

.PARAMETER Cleanup
    Delete the app instance resource group and all resources.

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "yourprefix" `
      -SharedInfraRg "yourprefixsharedinfra" `
    -Location "westeurope" `
      -Deploy

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "yourprefix" `
      -SharedInfraRg "yourprefixsharedinfra" `
      -ValidateOnly

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "yourprefix" -Cleanup

.NOTES
    Author: Autonomous AI-Assisted Development
    Requires: Azure CLI, PowerShell 7+, Bicep
    Prerequisite: Deploy-SharedInfra.ps1 must be run first
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [string]$SharedInfraRg,

    [ValidateSet("westeurope")]
    [string]$Location = "westeurope",

    [string]$SqlLocation = "northeurope",

    [ValidateRange(0, 255)]
    [int]$NetworkSecondOctet = 20,

    [ValidateRange(0, 255)]
    [int]$SqlNetworkSecondOctet = 21,

    [ValidatePattern('^\d{5}$')]
    [string]$DeploymentSuffix,

    [ValidateSet("Standard_NCC40ads_H100_v5")]
    [string]$AppCvmSize = "Standard_NCC40ads_H100_v5",

    [ValidateSet("Standard_DC1as_v5", "Standard_DC2as_v5", "Standard_DC1as_v6", "Standard_DC2as_v6", "Standard_DC4as_v6")]
    [string]$SqlCvmSize = "Standard_DC2as_v5",

    [ValidateSet("FileBackedDemo", "ManagedHsm")]
    [string]$PkiMode = "FileBackedDemo",

    [switch]$Deploy,
    [switch]$ResumePostDeploy,
    [switch]$ValidateOnly,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# Generate a 5-digit suffix, or reuse one to repair an existing deployment.
if (-not $Cleanup) {
    # Check if outputs from Stage 1 exist
    if (-not $SharedInfraRg) {
        Write-Host "ERROR: -SharedInfraRg is required (from Stage 1 deployment)" -ForegroundColor Red
        Write-Host "Example: .\Deploy-AppInstance.ps1 -Prefix `"yourprefix`" -SharedInfraRg `"yourprefixsharedinfra`" -Deploy" -ForegroundColor Yellow
        exit 1
    }
}

$randomSuffix = if ($DeploymentSuffix) { $DeploymentSuffix } else { Get-Random -Minimum 10000 -Maximum 99999 }
$RgName = "$($Prefix)$($randomSuffix)app"
$CvmName = "$($Prefix)-citizen-cvm"
$sqlVmName = "$Prefix-sql-cvm"
$DbName = "$($Prefix)-citizendb"
$BastionName = "$($Prefix)-$($randomSuffix)-bastion"
$AttestationName = "$($Prefix)attest$(Get-Random -Minimum 100 -Maximum 999)"
$VnetName = "$($Prefix)-$($randomSuffix)-vnet"
$SqlVnetName = "$($Prefix)-$($randomSuffix)-sql-vnet"
$managedHsmTlsEnabled = $PkiMode -eq 'ManagedHsm'
if ($DeploymentSuffix) {
    $existingAttestationName = az resource list `
        --resource-group $RgName `
        --resource-type Microsoft.Attestation/attestationProviders `
        --query '[0].name' `
        --output tsv `
        --only-show-errors 2>$null
    if ($LASTEXITCODE -eq 0 -and $existingAttestationName) {
        $AttestationName = $existingAttestationName
    }
}

if ($NetworkSecondOctet -eq $SqlNetworkSecondOctet -or $NetworkSecondOctet -eq 10 -or $SqlNetworkSecondOctet -eq 10) {
    throw "App, SQL, and shared VNet address spaces must not overlap. Use distinct second octets other than 10."
}

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Citizen Registry Advanced — Stage 2: App Instance           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prefix:              $Prefix"
Write-Host "Resource Group:      $RgName"
Write-Host "App location:        $Location"
Write-Host "SQL location:        $SqlLocation"
Write-Host "Shared Infra RG:     $SharedInfraRg"
Write-Host "App GPU CVM:         $CvmName ($AppCvmSize)"
Write-Host "SQL CPU CVM:         $sqlVmName ($SqlCvmSize, $SqlLocation)"
Write-Host "PKI mode:            $PkiMode"
Write-Host "Bastion:             $BastionName"
Write-Host "Attestation:         $AttestationName"
Write-Host ""

# Check if cleanup requested
if ($Cleanup) {
    Write-Host "Cleaning up app instance..." -ForegroundColor Yellow
    
    # Find resource groups matching pattern
    $rgs = az group list --query "[?starts_with(name, '$Prefix') && ends_with(name, 'app')].name" -o tsv
    
    if ($rgs) {
        Write-Host "Found resource groups:" -ForegroundColor Yellow
        $rgs | ForEach-Object { Write-Host "  - $_" }
        
        $rgs | ForEach-Object {
            Write-Host "Deleting: $_" -ForegroundColor Yellow
            az group delete --name $_ --yes --no-wait
        }
        Write-Host "Resource group deletions initiated (running in background)" -ForegroundColor Green
    } else {
        Write-Host "No app instance resource groups found with prefix: $Prefix" -ForegroundColor Yellow
    }
    
    exit 0
}

# Verify shared infrastructure exists
Write-Host "Verifying shared infrastructure resource group: $SharedInfraRg" -ForegroundColor Yellow
$sharedRg = az group show --name $SharedInfraRg --query "{id:id,location:location}" -o json --only-show-errors 2>$null | ConvertFrom-Json

if (-not $sharedRg.id) {
    Write-Host "✗ Shared infrastructure resource group not found: $SharedInfraRg" -ForegroundColor Red
    Write-Host "Please run Deploy-SharedInfra.ps1 first" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Shared infrastructure RG found" -ForegroundColor Green
if ($sharedRg.location -ne $Location) {
    throw "Shared infrastructure is in '$($sharedRg.location)', but the confidential GPU deployment requires '$Location'. Deploy shared infrastructure in $Location first."
}

# Get Managed HSM info from shared infrastructure
Write-Host "Retrieving Managed HSM details from shared infrastructure..." -ForegroundColor Yellow
$hsmId = az resource list --resource-group $SharedInfraRg `
    --resource-type "Microsoft.KeyVault/managedHSMs" `
    --query "[0].id" -o tsv 2>$null

if (-not $hsmId) {
    Write-Host "✗ Managed HSM not found in shared infrastructure RG" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Managed HSM ID: $hsmId" -ForegroundColor Green

$sharedVnetName = az network vnet list --resource-group $SharedInfraRg --query "[0].name" -o tsv
if (-not $sharedVnetName) {
    Write-Host "✗ Shared virtual network not found in shared infrastructure RG" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Shared virtual network: $sharedVnetName" -ForegroundColor Green

# Fail before creating billable resources if either VM SKU is restricted or lacks quota.
function Test-VmSkuCapacity {
    param(
        [Parameter(Mandatory)] [string]$VmSize,
        [Parameter(Mandatory)] [string]$VmLocation,
        [string]$ExistingVmName
    )

    $skuInfo = az vm list-skus `
        --location $VmLocation `
        --size $VmSize `
        --all `
        --query "[?name=='$VmSize'] | [0]" `
        --output json `
        --only-show-errors | ConvertFrom-Json
    if (-not $skuInfo -or $skuInfo.restrictions.Count -gt 0) {
        throw "VM SKU '$VmSize' is unavailable or restricted in '$VmLocation' for the active subscription."
    }
    $requiredVcpus = [int](($skuInfo.capabilities | Where-Object name -eq 'vCPUs' | Select-Object -First 1).value)
    $quota = az vm list-usage `
        --location $VmLocation `
        --query "[?name.value=='$($skuInfo.family)'] | [0].{current:currentValue,limit:limit}" `
        --output json `
        --only-show-errors | ConvertFrom-Json
    if (-not $quota) {
        throw "Could not find quota for VM family '$($skuInfo.family)' in '$VmLocation'."
    }
    $availableVcpus = [int]$quota.limit - [int]$quota.current
    if ($ExistingVmName) {
        $existingVmSize = az vm show `
            --resource-group $RgName `
            --name $ExistingVmName `
            --query hardwareProfile.vmSize `
            --output tsv `
            --only-show-errors 2>$null
        if ($LASTEXITCODE -eq 0 -and $existingVmSize -eq $VmSize) {
            Write-Host "✓ $VmSize already provisioned in $VmLocation; quota is committed to this deployment" -ForegroundColor Green
            return
        }
    }
    if ($availableVcpus -lt $requiredVcpus) {
        throw "Insufficient '$($skuInfo.family)' quota in '$VmLocation': $availableVcpus vCPUs available, $requiredVcpus required."
    }
    Write-Host "✓ $VmSize available in $VmLocation; $availableVcpus family vCPUs free ($requiredVcpus required)" -ForegroundColor Green
}

Write-Host "Checking app and SQL VM availability and quota in their regions..." -ForegroundColor Yellow
Test-VmSkuCapacity -VmSize $AppCvmSize -VmLocation $Location -ExistingVmName $CvmName
Test-VmSkuCapacity -VmSize $SqlCvmSize -VmLocation $SqlLocation -ExistingVmName $sqlVmName

# Ensure app instance resource group exists
Write-Host "Creating app instance resource group: $RgName" -ForegroundColor Yellow
az group create --name $RgName --location $Location | Out-Null
Write-Host "✓ App instance resource group ready" -ForegroundColor Green

# Get current user info for tagging
$userUpn = az ad signed-in-user show --query "userPrincipalName" -o tsv
Write-Host "Current user: $userUpn" -ForegroundColor Yellow

function Set-HsmRoleAssignment {
    param(
        [Parameter(Mandatory)] [string]$HsmName,
        [Parameter(Mandatory)] [string]$Role,
        [Parameter(Mandatory)] [string]$PrincipalId,
        [Parameter(Mandatory)] [string]$Scope
    )

    $PSNativeCommandUseErrorActionPreference = $false
    $roleOutput = az keyvault role assignment create `
        --hsm-name $HsmName `
        --role $Role `
        --assignee-object-id $PrincipalId `
        --scope $Scope `
        --output none 2>&1
    if ($LASTEXITCODE -eq 0 -or "$roleOutput" -match 'MatchingRoleAssignmentExists') {
        return
    }
    throw "Failed to ensure HSM role '$Role' for '$PrincipalId': $roleOutput"
}

# Policy may attach additional identities to the VM. Select this application
# identity explicitly so IMDS can issue the token used to read CMK evidence.
$appIdentity = az identity create `
    --resource-group $RgName `
    --name "$Prefix-cvm-identity" `
    --location $Location `
    --query '{clientId:clientId, principalId:principalId}' `
    --output json | ConvertFrom-Json
if (-not $appIdentity.clientId) { throw 'Failed to provision the app managed identity.' }
$appIdentityClientId = $appIdentity.clientId

# Generate a temporary key for the deployment if one is not already available.
$sshKeyPath = Join-Path $env:TEMP "citizen-registry-$Prefix"
if (-not (Test-Path "$sshKeyPath.pub")) {
    ssh-keygen -t rsa -b 4096 -f $sshKeyPath -N "" -q
}
$sshPublicKey = (Get-Content "$sshKeyPath.pub" -Raw).Trim()
$sqlSaPassword = "Cvm$(Get-Random -Minimum 100000 -Maximum 999999)!A"
$sqlAppPassword = "App$(Get-Random -Minimum 100000 -Maximum 999999)!A"
$existingSqlCustomData = az deployment group show `
    --resource-group $RgName `
    --name app-instance `
    --query properties.parameters.sqlCustomData.value `
    --output tsv `
    --only-show-errors 2>$null
if ($LASTEXITCODE -eq 0 -and $existingSqlCustomData) {
    $existingSqlCloudConfig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($existingSqlCustomData))
    $innerSqlBase64 = [regex]::Match($existingSqlCloudConfig, "echo '([^']+)' \| base64").Groups[1].Value
    $existingSqlScript = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($innerSqlBase64))
    $sqlSaPassword = [regex]::Match($existingSqlScript, "MSSQL_SA_PASSWORD='([^']+)' ").Groups[1].Value
    $sqlAppPassword = [regex]::Match($existingSqlScript, "CREATE LOGIN \[registryadmin\] WITH PASSWORD = '([^']+)'", 'IgnoreCase').Groups[1].Value
    if (-not $sqlSaPassword -or -not $sqlAppPassword) {
        throw "Could not recover SQL credentials for existing deployment '$RgName'."
    }
    Write-Host "Reusing SQL credentials from existing deployment" -ForegroundColor Green
}
$appPrivateIp = "10.$NetworkSecondOctet.3.4"
$sqlPrivateIp = "10.$SqlNetworkSecondOctet.4.5"
$hsmName = $hsmId.Split('/')[-1]
$osDiskKeyName = "$Prefix-cvm-os-key"
$diskEncryptionSetName = "$Prefix-cvm-os-des"

# Provision the customer-managed key and DES before creating either CVM.
Write-Host "Provisioning Managed HSM-backed confidential disk encryption..." -ForegroundColor Yellow
$hsmBootstrapComplete = $false
try {
    az resource update --ids $hsmId --set properties.publicNetworkAccess=Enabled properties.networkAcls.defaultAction=Allow properties.networkAcls.bypass=AzureServices | Out-Null
    $keyUrl = ''
    try { $keyUrl = az keyvault key show --hsm-name $hsmName --name $osDiskKeyName --query key.kid -o tsv 2>$null } catch { $keyUrl = '' }
    if (-not $keyUrl) {
        $keyUrl = az keyvault key create --hsm-name $hsmName --name $osDiskKeyName --kty RSA-HSM --size 3072 --ops wrapKey unwrapKey --default-cvm-policy --exportable --query key.kid -o tsv
    }
    $diskEncryptionSetId = ''
    try { $diskEncryptionSetId = az disk-encryption-set show --resource-group $RgName --name $diskEncryptionSetName --query id -o tsv 2>$null } catch { $diskEncryptionSetId = '' }
    if (-not $diskEncryptionSetId) {
        az disk-encryption-set create --resource-group $RgName --name $diskEncryptionSetName --location $Location --encryption-type ConfidentialVmEncryptedWithCustomerKey --key-url $keyUrl --source-vault $hsmId --mi-system-assigned | Out-Null
        $diskEncryptionSetId = az disk-encryption-set show --resource-group $RgName --name $diskEncryptionSetName --query id -o tsv
    }
    $desPrincipalId = az disk-encryption-set show --resource-group $RgName --name $diskEncryptionSetName --query identity.principalId -o tsv
    Set-HsmRoleAssignment -HsmName $hsmName -Role 'Managed HSM Crypto Service Encryption User' -PrincipalId $desPrincipalId -Scope "/keys/$osDiskKeyName"
    $cvmOrchestratorPrincipalId = az ad sp show --id 'bf7b6499-ff71-4aa2-97a4-f372087be7f0' --query id -o tsv
    if (-not $cvmOrchestratorPrincipalId) { throw 'Azure CVM Orchestrator service principal was not found.' }
    Set-HsmRoleAssignment -HsmName $hsmName -Role 'Managed HSM Crypto Service Release User' -PrincipalId $cvmOrchestratorPrincipalId -Scope "/keys/$osDiskKeyName"
    $hsmBootstrapComplete = $true
    Write-Host "Managed HSM key and DES ready: $diskEncryptionSetName" -ForegroundColor Green
} finally {
    # Managed disks use the trusted-services bypass; app traffic uses Private Link.
    az resource update --ids $hsmId --set properties.publicNetworkAccess=Disabled properties.networkAcls.defaultAction=Deny properties.networkAcls.bypass=AzureServices | Out-Null
    Write-Host "Managed HSM locked to Private Link and trusted Azure services" -ForegroundColor Green
}
if (-not $hsmBootstrapComplete) { throw 'Managed HSM CMK bootstrap did not complete; no CVM was deployed.' }

# Embed the local application source in cloud-init so the app VM is usable after deployment.
$archivePath = Join-Path $env:TEMP "citizen-registry-$Prefix.tar.gz"
tar --exclude='app-src/__pycache__' --exclude='app-src/test_media_generator.py' --exclude='app-src/test_video_anonymizer.py' -czf $archivePath -C "./app-instance" app-src
$archiveBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($archivePath))
$appBootstrapScript = @"
#!/bin/bash
set -e
mkdir -p /opt/citizen-registry /etc/citizen-registry/certs /var/log/citizen-registry
echo '$archiveBase64' | base64 -d | tar -xzf - -C /opt/citizen-registry
mkdir -p /opt/citizen-registry/source-media /opt/citizen-registry/app-src/static/vendor
CCTV_VIDEO_SOURCE=/opt/citizen-registry/source-media/london-marathon-2026-upper-thames-street.webm
CCTV_VIDEO=/opt/citizen-registry/source-media/london-marathon-2026-close-faces.mp4
CCTV_VIDEO_URL='https://upload.wikimedia.org/wikipedia/commons/d/d9/2026_London_Marathon_Upper_Thames_Street_from_Blackfriars_Bridge_and_Queenhithe.webm'
CCTV_VIDEO_SHA256='9b2463093a0769414234137a31b70d3dd919179a66d37576b77fce283379e655'
curl -fL --retry 5 --retry-delay 5 "`$CCTV_VIDEO_URL" -o "`$CCTV_VIDEO_SOURCE.tmp"
echo "`$CCTV_VIDEO_SHA256  `$CCTV_VIDEO_SOURCE.tmp" | sha256sum --check
mv "`$CCTV_VIDEO_SOURCE.tmp" "`$CCTV_VIDEO_SOURCE"
HLS_JS=/opt/citizen-registry/app-src/static/vendor/hls.min.js
HLS_LICENSE=/opt/citizen-registry/app-src/static/vendor/HLS-LICENSE.txt
curl -fL --retry 5 --retry-delay 5 'https://cdn.jsdelivr.net/npm/hls.js@1.6.13/dist/hls.min.js' -o "`$HLS_JS.tmp"
echo '7c47cd97d7a6e7b98d9623dd8ed9a6d45af4be4085e0c2001cd7175c2b4cfb07  '"`$HLS_JS.tmp" | sha256sum --check
mv "`$HLS_JS.tmp" "`$HLS_JS"
curl -fL --retry 5 --retry-delay 5 'https://raw.githubusercontent.com/video-dev/hls.js/v1.6.13/LICENSE' -o "`$HLS_LICENSE.tmp"
echo 'ca8773cf798c7ed997d4dd7c8e23c348699f8d5b7462636694cc14de6cda12db  '"`$HLS_LICENSE.tmp" | sha256sum --check
mv "`$HLS_LICENSE.tmp" "`$HLS_LICENSE"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ffmpeg nginx openssl python3-flask python3-requests libodbc2
CCTV_VIDEO_RECIPE='close-faces-v3|source=9b2463093a0769414234137a31b70d3dd919179a66d37576b77fce283379e655|start=85|end=118.5|1280x720|24fps|h264-crf18-faststart'
ffmpeg -hide_banner -loglevel warning -ss 85 -to 118.5 -i "`$CCTV_VIDEO_SOURCE" -an -vf 'scale=1280:720:flags=lanczos,fps=24,format=yuv420p' -c:v libx264 -preset medium -crf 18 -movflags +faststart -map_metadata -1 -f mp4 -y "`$CCTV_VIDEO.tmp"
mv "`$CCTV_VIDEO.tmp" "`$CCTV_VIDEO"
printf '%s\n' "`$CCTV_VIDEO_RECIPE" > "`$CCTV_VIDEO.recipe"
(cd "`$(dirname "`$CCTV_VIDEO")" && sha256sum "`$(basename "`$CCTV_VIDEO")" > "`$(basename "`$CCTV_VIDEO").sha256")
DATA_DEVICE=`$(readlink -f /dev/disk/azure/scsi1/lun0)
if ! blkid `$DATA_DEVICE >/dev/null 2>&1; then mkfs.ext4 `$DATA_DEVICE; fi
mkdir -p /var/lib/citizen-registry
DATA_UUID=`$(blkid -s UUID -o value `$DATA_DEVICE)
grep -q "UUID=`$DATA_UUID" /etc/fstab || printf 'UUID=%s /var/lib/citizen-registry ext4 defaults,nofail 0 2\n' "`$DATA_UUID" >> /etc/fstab
mount /var/lib/citizen-registry
mkdir -p /var/lib/citizen-registry/media /var/lib/citizen-registry/cctv/hls
chmod 755 /var/lib/citizen-registry/cctv /var/lib/citizen-registry/cctv/hls
printf '%s\n' 'msodbcsql18 msodbcsql/ACCEPT_EULA boolean true' | debconf-set-selections
export ACCEPT_EULA=Y
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y msodbcsql18
python3 -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', '/tmp/get-pip.py')"
python3 /tmp/get-pip.py --break-system-packages
pip3 install --break-system-packages --no-cache-dir azure-identity pyodbc gunicorn Pillow diffusers transformers accelerate safetensors
pip3 install --break-system-packages --no-cache-dir torch torchvision --index-url https://download.pytorch.org/whl/cu128
pip3 install --break-system-packages --no-cache-dir --no-deps facenet-pytorch==2.6.0
openssl req -x509 -nodes -newkey rsa:3072 -days 365 -keyout /etc/citizen-registry/certs/client-ca.key -out /etc/citizen-registry/certs/client-ca.crt -subj '/C=NL/O=Norland IT Department/OU=Registry PKI/CN=Norland Registry Demo CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign'
if [ '$PkiMode' = 'FileBackedDemo' ]; then
    openssl req -nodes -newkey rsa:2048 -keyout /etc/citizen-registry/certs/citizen-registry.key -out /tmp/citizen-registry.csr -subj '/C=NL/O=Norland IT Department/OU=Citizen Registry/CN=citizen-registry.internal'
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:citizen-registry.internal,IP:$appPrivateIp' > /tmp/server-ext.cnf
    openssl x509 -req -in /tmp/citizen-registry.csr -CA /etc/citizen-registry/certs/client-ca.crt -CAkey /etc/citizen-registry/certs/client-ca.key -CAcreateserial -out /etc/citizen-registry/certs/citizen-registry.crt -days 365 -sha256 -extfile /tmp/server-ext.cnf
fi
openssl req -nodes -newkey rsa:2048 -keyout /etc/citizen-registry/certs/citizen.key -out /tmp/citizen.csr -subj '/C=NL/O=Norland IT Department/OU=Registry Clients/CN=citizen-registry-demo-client'
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' > /tmp/client-ext.cnf
openssl x509 -req -in /tmp/citizen.csr -CA /etc/citizen-registry/certs/client-ca.crt -CAkey /etc/citizen-registry/certs/client-ca.key -CAcreateserial -out /etc/citizen-registry/certs/citizen.crt -days 365 -sha256 -extfile /tmp/client-ext.cnf
chmod 600 /etc/citizen-registry/certs/*.key
cp /opt/citizen-registry/app-src/nginx.conf /etc/nginx/nginx.conf
printf 'MTLS_ENABLED=true\nPKI_MODE=$PkiMode\nAZURE_CLIENT_ID=$appIdentityClientId\nATTESTATION_ENDPOINT=https://$AttestationName.weu.attest.azure.net\nHSM_ENDPOINT=https://$hsmName.managedhsm.azure.net\nHSM_NAME=$hsmName\nOS_DISK_KEY_NAME=$osDiskKeyName\nKEY_RELEASE_STATUS=azure-cvm-attestation-bound\nAPP_CVM_IP=$appPrivateIp\nSQL_CVM_IP=$sqlPrivateIp\nDB_HOST=$sqlPrivateIp\nDB_NAME=$DbName\nDB_USER=registryadmin\nDB_PASSWORD=$sqlAppPassword\nDB_SA_PASSWORD=$sqlSaPassword\nCITIZEN_MEDIA_ROOT=/var/lib/citizen-registry/media\nGPU_ATTESTATION_PATH=/var/lib/citizen-registry/gpu-attestation.json\nCCTV_VIDEO_PATH=/opt/citizen-registry/source-media/london-marathon-2026-upper-thames-street.webm\nCCTV_PROCESSING_ROOT=/var/lib/citizen-registry/cctv\nCCTV_OUTPUT_FPS=24\nCCTV_FACE_DETECTION_FPS=12\nCCTV_FACE_DETECTION_BATCH_SIZE=4\nCCTV_H264_PRESET=fast\nCCTV_H264_CRF=20\nPORTRAIT_MODEL_ID=stabilityai/sdxl-turbo\n' > /etc/citizen-registry/environment
sed -i 's|^CCTV_VIDEO_PATH=.*|CCTV_VIDEO_PATH=/opt/citizen-registry/source-media/london-marathon-2026-close-faces.mp4|' /etc/citizen-registry/environment
cat > /etc/systemd/system/citizen-registry.service <<'SERVICE'
[Unit]
After=network-online.target var-lib-citizen\x2dregistry.mount
RequiresMountsFor=/var/lib/citizen-registry
[Service]
WorkingDirectory=/opt/citizen-registry/app-src
EnvironmentFile=/etc/citizen-registry/environment
ExecStart=/usr/local/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 app:app
Restart=always
[Install]
WantedBy=multi-user.target
SERVICE
cat > /etc/systemd/system/citizen-cctv-anonymizer.service <<'SERVICE'
[Unit]
Description=Confidential H100 CCTV face anonymizer
After=network-online.target citizen-gpu-attestation.service
Requires=citizen-gpu-attestation.service
RequiresMountsFor=/var/lib/citizen-registry
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/citizen-registry/app-src
EnvironmentFile=/etc/citizen-registry/environment
ExecStart=/usr/bin/python3 /opt/citizen-registry/app-src/video_anonymizer.py
UMask=0022
[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable --now citizen-registry
if [ '$PkiMode' = 'FileBackedDemo' ]; then
    systemctl enable nginx
    systemctl restart nginx
else
    systemctl disable --now nginx || true
fi
"@
$appBootstrapScript = $appBootstrapScript -replace "`r`n", "`n" -replace "`r", ""
$appBootstrapScriptIndented = ($appBootstrapScript -split "`n" | ForEach-Object { "      $_" }) -join "`n"
$appBootstrap = @"
#cloud-config
write_files:
    - path: /tmp/citizen-registry-bootstrap.sh
        permissions: '0700'
        content: |
$appBootstrapScriptIndented
runcmd:
    - /tmp/citizen-registry-bootstrap.sh
"@

$sqlBootstrapScript = @"
#!/bin/bash
set -e
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/mssql-server-2022.list -o /etc/apt/sources.list.d/mssql-server-2022.list
apt-get update
ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive apt-get install -y mssql-server mssql-tools18 unixodbc-dev
MSSQL_PID=Developer ACCEPT_EULA=Y MSSQL_SA_PASSWORD='$sqlSaPassword' /opt/mssql/bin/mssql-conf -n setup
systemctl enable --now mssql-server
for attempt in `$(seq 1 60); do /opt/mssql-tools18/bin/sqlcmd -S 127.0.0.1 -U sa -P '$sqlSaPassword' -C -Q 'SELECT 1' >/dev/null 2>&1 && break; sleep 2; done
/opt/mssql-tools18/bin/sqlcmd -S 127.0.0.1 -U sa -P '$sqlSaPassword' -C -Q "IF DB_ID(N'$DbName') IS NULL CREATE DATABASE [$DbName]; IF SUSER_ID(N'registryadmin') IS NULL CREATE LOGIN [registryadmin] WITH PASSWORD = '$sqlAppPassword'; ELSE ALTER LOGIN [registryadmin] WITH PASSWORD = '$sqlAppPassword';"
/opt/mssql-tools18/bin/sqlcmd -S 127.0.0.1 -U sa -P '$sqlSaPassword' -C -d '$DbName' -Q "IF USER_ID(N'registryadmin') IS NULL CREATE USER [registryadmin] FOR LOGIN [registryadmin]; ALTER ROLE db_datareader ADD MEMBER [registryadmin]; ALTER ROLE db_datawriter ADD MEMBER [registryadmin]; IF OBJECT_ID(N'dbo.citizen_registry', N'U') IS NULL CREATE TABLE dbo.citizen_registry (id INT IDENTITY(1,1) PRIMARY KEY, national_id NVARCHAR(20) NOT NULL UNIQUE, first_name NVARCHAR(100) NOT NULL, last_name NVARCHAR(100) NOT NULL, date_of_birth DATE NOT NULL, sex NVARCHAR(10), region NVARCHAR(100), municipality NVARCHAR(100), address_line NVARCHAR(200), postal_code NVARCHAR(10), household_size INT DEFAULT 1, marital_status NVARCHAR(20) DEFAULT N'Single', employment_status NVARCHAR(30) DEFAULT N'Employed', tax_bracket NVARCHAR(10) DEFAULT N'B', registered_voter BIT DEFAULT 1, socioeconomic_group NVARCHAR(40), tax_paid_last_year DECIMAL(12,2), created_date DATETIME DEFAULT GETUTCDATE(), modified_date DATETIME DEFAULT GETUTCDATE());"
"@
$sqlBootstrapScript = $sqlBootstrapScript -replace "`r`n", "`n" -replace "`r", ""
$sqlBootstrapScriptBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sqlBootstrapScript))
$sqlBootstrap = @"
#cloud-config
runcmd:
    - echo '$sqlBootstrapScriptBase64' | base64 -d | bash
"@
$customData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($appBootstrap))
$sqlCustomData = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sqlBootstrap))
if ($customData.Length -gt 87380) {
    throw "Application custom data is $($customData.Length) characters; Azure allows at most 87380."
}

# Prepare Bicep parameters in a file to avoid Windows command-line length limits.
$parametersFile = Join-Path $env:TEMP "citizen-registry-$Prefix.parameters.json"
@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters = @{
        prefix = @{ value = $Prefix }
        cvmName = @{ value = $CvmName }
        appCvmSize = @{ value = $AppCvmSize }
        sqlCvmSize = @{ value = $SqlCvmSize }
        bastionName = @{ value = $BastionName }
        attestationName = @{ value = $AttestationName }
        vnetName = @{ value = $VnetName }
        sqlVnetName = @{ value = $SqlVnetName }
        networkSecondOctet = @{ value = $NetworkSecondOctet }
        sqlNetworkSecondOctet = @{ value = $SqlNetworkSecondOctet }
        location = @{ value = $Location }
        sqlLocation = @{ value = $SqlLocation }
        ownerTag = @{ value = $userUpn }
        sharedInfraRgName = @{ value = $SharedInfraRg }
        sharedVnetName = @{ value = $sharedVnetName }
        diskEncryptionSetId = @{ value = $diskEncryptionSetId }
        managedHsmTlsEnabled = @{ value = $managedHsmTlsEnabled }
        confidentialOsDisk = @{ value = $true }
        attestationEnabled = @{ value = $true }
        sshPublicKey = @{ value = $sshPublicKey }
        customData = @{ value = $customData }
        sqlVmName = @{ value = $sqlVmName }
        sqlCustomData = @{ value = $sqlCustomData }
    }
} | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 $parametersFile

Write-Host "Deploying Bicep template: app-instance.bicep" -ForegroundColor Yellow

if ($ValidateOnly) {
    Write-Host "Running template validation only..." -ForegroundColor Cyan
    
    $validation = az deployment group validate `
        --resource-group $RgName `
        --template-file "./bicep/app-instance.bicep" `
        --parameters "@$parametersFile" `
        --query "properties.validationResult" `
        2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Template validation passed" -ForegroundColor Green
        Write-Host $validation
    } else {
        Write-Host "✗ Template validation failed" -ForegroundColor Red
        Write-Host $validation
        exit 1
    }
    
    exit 0
}

if ($Deploy -or $ResumePostDeploy) {
    Write-Host "Starting deployment..." -ForegroundColor Cyan
    
    try {
        if ($ResumePostDeploy) {
            $existingCvmId = az vm show --resource-group $RgName --name $CvmName --query id --output tsv --only-show-errors
            $appVnetId = az network vnet show --resource-group $RgName --name $VnetName --query id --output tsv --only-show-errors
            if (-not $existingCvmId -or -not $appVnetId) {
                throw "Cannot resume: app VM or VNet is missing from '$RgName'."
            }
            $deploymentOutputs = [pscustomobject]@{
                cvmId = [pscustomobject]@{ value = $existingCvmId }
                vnetId = [pscustomobject]@{ value = $appVnetId }
            }
            $deployment = $deploymentOutputs | ConvertTo-Json -Depth 10
            Write-Host "✓ Existing infrastructure found; resuming post-deployment configuration" -ForegroundColor Green
        } else {
            $deployment = az deployment group create `
                --resource-group $RgName `
                --template-file "./bicep/app-instance.bicep" `
                --parameters "@$parametersFile" `
                --only-show-errors `
                --query "properties.outputs" `
                2>&1

            Write-Host "✓ Deployment completed successfully" -ForegroundColor Green
            Write-Host ""
            Write-Host "Deployment Outputs:" -ForegroundColor Cyan
            $deploymentOutputs = $deployment | ConvertFrom-Json
            Write-Host ($deploymentOutputs | ConvertTo-Json -Depth 10)
        }

        function Invoke-GpuRunCommand {
            param(
                [Parameter(Mandatory)] [string]$Label,
                [Parameter(Mandatory)] [string]$Script,
                [Parameter(Mandatory)] [string]$SuccessMarker
            )

            $scriptPath = Join-Path $env:TEMP "citizen-registry-$Prefix-$($Label -replace '[^a-zA-Z0-9]', '-').sh"
            [IO.File]::WriteAllText($scriptPath, $Script, [Text.UTF8Encoding]::new($false))
            try {
                for ($attempt = 1; $attempt -le 10; $attempt++) {
                    $text = az vm run-command invoke `
                        --resource-group $RgName `
                        --name $CvmName `
                        --command-id RunShellScript `
                        --scripts "@$scriptPath" `
                        --query "value[].message" `
                        --output tsv `
                        --only-show-errors 2>&1
                    $textValue = $text -join "`n"
                    if ($LASTEXITCODE -eq 0 -and $textValue -match [regex]::Escape($SuccessMarker)) {
                        Write-Host $textValue
                        return $textValue
                    }
                    if ($attempt -eq 10) {
                        throw "$Label failed or did not produce '$SuccessMarker': $textValue"
                    }
                    Write-Host "$Label not ready (attempt $attempt of 10); retrying in 45 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 45
                }
            } finally {
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            }
        }

        function Set-AppHsmNetwork {
            $script:appVnetId = $deploymentOutputs.vnetId.value
            $sharedPeeringId = ''
            try {
                $sharedPeeringId = az network vnet peering show `
                    --resource-group $SharedInfraRg `
                    --vnet-name $sharedVnetName `
                    --name "shared-to-$VnetName" `
                    --query id --output tsv 2>$null
            } catch { $sharedPeeringId = '' }
            if (-not $sharedPeeringId) {
                az network vnet peering create --resource-group $SharedInfraRg --vnet-name $sharedVnetName --name "shared-to-$VnetName" --remote-vnet $script:appVnetId --allow-vnet-access | Out-Null
            }
            $hsmDnsLinkExists = ''
            try {
                $hsmDnsLinkExists = az network private-dns link vnet show --resource-group $SharedInfraRg --zone-name privatelink.managedhsm.azure.net --name "$VnetName-link" --query id -o tsv 2>$null
            } catch { $hsmDnsLinkExists = '' }
            if (-not $hsmDnsLinkExists) {
                az network private-dns link vnet create --resource-group $SharedInfraRg --zone-name privatelink.managedhsm.azure.net --name "$VnetName-link" --virtual-network $script:appVnetId --registration-enabled false | Out-Null
            }
            Write-Host "Bidirectional VNet peering and HSM private DNS link ready" -ForegroundColor Green
        }

        Set-AppHsmNetwork
        if ($ResumePostDeploy) {
            $existingTlsIdentityId = ''
            try {
                $existingTlsIdentityId = az identity show --resource-group $RgName --name "$Prefix-tls-identity" --query id --output tsv --only-show-errors 2>$null
            } catch { $existingTlsIdentityId = '' }
            if ([bool]$existingTlsIdentityId -ne $managedHsmTlsEnabled) {
                $requiredMode = if ($existingTlsIdentityId) { 'ManagedHsm' } else { 'FileBackedDemo' }
                throw "Resume mode does not match the deployed identities. Run again with -PkiMode $requiredMode."
            }
        }

        Write-Host "Refreshing the application and CCTV source footage..." -ForegroundColor Magenta
        $appRefreshScript = @"
#!/bin/bash
set -euo pipefail
cloud-init status --wait
systemctl stop citizen-cctv-anonymizer.service 2>/dev/null || true
mkdir -p /opt/citizen-registry/source-media /opt/citizen-registry/app-src/static/vendor /var/lib/citizen-registry/cctv/hls
echo '$archiveBase64' | base64 -d | tar -xzf - -C /opt/citizen-registry
CCTV_VIDEO_SOURCE=/opt/citizen-registry/source-media/london-marathon-2026-upper-thames-street.webm
CCTV_VIDEO=/opt/citizen-registry/source-media/london-marathon-2026-close-faces.mp4
CCTV_VIDEO_URL='https://upload.wikimedia.org/wikipedia/commons/d/d9/2026_London_Marathon_Upper_Thames_Street_from_Blackfriars_Bridge_and_Queenhithe.webm'
CCTV_VIDEO_SHA256='9b2463093a0769414234137a31b70d3dd919179a66d37576b77fce283379e655'
if ! echo "`$CCTV_VIDEO_SHA256  `$CCTV_VIDEO_SOURCE" | sha256sum --check --status; then
    curl -fL --retry 5 --retry-delay 5 "`$CCTV_VIDEO_URL" -o "`$CCTV_VIDEO_SOURCE.tmp"
    echo "`$CCTV_VIDEO_SHA256  `$CCTV_VIDEO_SOURCE.tmp" | sha256sum --check
    mv "`$CCTV_VIDEO_SOURCE.tmp" "`$CCTV_VIDEO_SOURCE"
fi
HLS_JS=/opt/citizen-registry/app-src/static/vendor/hls.min.js
HLS_LICENSE=/opt/citizen-registry/app-src/static/vendor/HLS-LICENSE.txt
if ! echo '7c47cd97d7a6e7b98d9623dd8ed9a6d45af4be4085e0c2001cd7175c2b4cfb07  '"`$HLS_JS" | sha256sum --check --status; then
    curl -fL --retry 5 --retry-delay 5 'https://cdn.jsdelivr.net/npm/hls.js@1.6.13/dist/hls.min.js' -o "`$HLS_JS.tmp"
    echo '7c47cd97d7a6e7b98d9623dd8ed9a6d45af4be4085e0c2001cd7175c2b4cfb07  '"`$HLS_JS.tmp" | sha256sum --check
    mv "`$HLS_JS.tmp" "`$HLS_JS"
fi
if ! echo 'ca8773cf798c7ed997d4dd7c8e23c348699f8d5b7462636694cc14de6cda12db  '"`$HLS_LICENSE" | sha256sum --check --status; then
    curl -fL --retry 5 --retry-delay 5 'https://raw.githubusercontent.com/video-dev/hls.js/v1.6.13/LICENSE' -o "`$HLS_LICENSE.tmp"
    echo 'ca8773cf798c7ed997d4dd7c8e23c348699f8d5b7462636694cc14de6cda12db  '"`$HLS_LICENSE.tmp" | sha256sum --check
    mv "`$HLS_LICENSE.tmp" "`$HLS_LICENSE"
fi
if ! command -v ffmpeg >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ffmpeg
fi
CCTV_VIDEO_RECIPE='close-faces-v3|source=9b2463093a0769414234137a31b70d3dd919179a66d37576b77fce283379e655|start=85|end=118.5|1280x720|24fps|h264-crf18-faststart'
if ! test -s "`$CCTV_VIDEO" || ! test "`$(cat "`$CCTV_VIDEO.recipe" 2>/dev/null || true)" = "`$CCTV_VIDEO_RECIPE" || ! (cd "`$(dirname "`$CCTV_VIDEO")" && sha256sum --check --status "`$(basename "`$CCTV_VIDEO").sha256"); then
    ffmpeg -hide_banner -loglevel warning -ss 85 -to 118.5 -i "`$CCTV_VIDEO_SOURCE" -an -vf 'scale=1280:720:flags=lanczos,fps=24,format=yuv420p' -c:v libx264 -preset medium -crf 18 -movflags +faststart -map_metadata -1 -f mp4 -y "`$CCTV_VIDEO.tmp"
    mv "`$CCTV_VIDEO.tmp" "`$CCTV_VIDEO"
    printf '%s\n' "`$CCTV_VIDEO_RECIPE" > "`$CCTV_VIDEO.recipe"
    (cd "`$(dirname "`$CCTV_VIDEO")" && sha256sum "`$(basename "`$CCTV_VIDEO")" > "`$(basename "`$CCTV_VIDEO").sha256")
fi
if ! python3 -c 'import torchvision, facenet_pytorch' >/dev/null 2>&1; then
    pip3 install --break-system-packages --no-cache-dir torchvision --index-url https://download.pytorch.org/whl/cu128
    pip3 install --break-system-packages --no-cache-dir --no-deps facenet-pytorch==2.6.0
fi
if grep -q '^CCTV_VIDEO_PATH=' /etc/citizen-registry/environment; then
    sed -i "s|^CCTV_VIDEO_PATH=.*|CCTV_VIDEO_PATH=`$CCTV_VIDEO|" /etc/citizen-registry/environment
else
    echo "CCTV_VIDEO_PATH=`$CCTV_VIDEO" >> /etc/citizen-registry/environment
fi
grep -q '^CCTV_PROCESSING_ROOT=' /etc/citizen-registry/environment || echo 'CCTV_PROCESSING_ROOT=/var/lib/citizen-registry/cctv' >> /etc/citizen-registry/environment
sed -i '/^CCTV_OUTPUT_FPS=/d; /^CCTV_FACE_DETECTION_FPS=/d; /^CCTV_FACE_DETECTION_BATCH_SIZE=/d; /^CCTV_H264_PRESET=/d; /^CCTV_H264_CRF=/d' /etc/citizen-registry/environment
printf '%s\n' 'CCTV_OUTPUT_FPS=24' 'CCTV_FACE_DETECTION_FPS=12' 'CCTV_FACE_DETECTION_BATCH_SIZE=4' 'CCTV_H264_PRESET=fast' 'CCTV_H264_CRF=20' >> /etc/citizen-registry/environment
chmod 755 /var/lib/citizen-registry/cctv /var/lib/citizen-registry/cctv/hls
cp /opt/citizen-registry/app-src/nginx.conf /etc/nginx/nginx.conf
cat > /etc/systemd/system/citizen-cctv-anonymizer.service <<'SERVICE'
[Unit]
Description=Confidential H100 CCTV face anonymizer
After=network-online.target citizen-gpu-attestation.service
Requires=citizen-gpu-attestation.service
RequiresMountsFor=/var/lib/citizen-registry
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/citizen-registry/app-src
EnvironmentFile=/etc/citizen-registry/environment
ExecStart=/usr/bin/python3 /opt/citizen-registry/app-src/video_anonymizer.py
UMask=0022
[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
if [ '$PkiMode' = 'FileBackedDemo' ]; then
    nginx -t
    systemctl restart nginx
else
    systemctl disable --now nginx || true
fi
systemctl restart citizen-registry.service
if systemctl is-active --quiet citizen-gpu-attestation.service; then
    systemctl enable citizen-cctv-anonymizer.service
    systemctl restart --no-block citizen-cctv-anonymizer.service
fi
for attempt in `$(seq 1 30); do
    if curl -fsS http://127.0.0.1:8000/cctv >/dev/null 2>&1; then break; fi
    if [ "`$attempt" -eq 30 ]; then exit 1; fi
    sleep 2
done
curl -fsS --range 0-1023 --dump-header /tmp/cctv-video.headers http://127.0.0.1:8000/cctv/video -o /tmp/cctv-video.range
grep -q '^HTTP/1.[01] 206' /tmp/cctv-video.headers
test "`$(wc -c < /tmp/cctv-video.range)" -eq 1024
rm -f /tmp/cctv-video.headers /tmp/cctv-video.range
echo 'CCTV_APP_REFRESHED=1'
"@
    Invoke-GpuRunCommand -Label 'application refresh' -Script $appRefreshScript -SuccessMarker 'CCTV_APP_REFRESHED=1' | Out-Null

        if ($managedHsmTlsEnabled) {
            Write-Host "Configuring non-exportable Managed HSM nginx TLS key..." -ForegroundColor Magenta
            $tlsIdentity = az identity show `
                --resource-group $RgName `
                --name "$Prefix-tls-identity" `
                --query '{clientId:clientId,principalId:principalId}' `
                --output json --only-show-errors | ConvertFrom-Json
            if (-not $tlsIdentity.clientId -or -not $tlsIdentity.principalId) {
                throw 'The dedicated Managed HSM TLS identity was not found.'
            }
            $tlsKeyLabel = "$Prefix-nginx-tls"
            az resource update --ids $hsmId --set properties.publicNetworkAccess=Enabled properties.networkAcls.defaultAction=Allow properties.networkAcls.bypass=AzureServices | Out-Null
            try {
                Set-HsmRoleAssignment `
                    -HsmName $hsmName `
                    -Role 'Managed HSM Crypto User' `
                    -PrincipalId $tlsIdentity.principalId `
                    -Scope '/keys'
                try {
                    $managedHsmTlsScript = @"
#!/bin/bash
set -euo pipefail
sed -i 's/\r$//' /opt/citizen-registry/app-src/setup-managed-hsm-tls.sh
chmod 750 /opt/citizen-registry/app-src/setup-managed-hsm-tls.sh
/opt/citizen-registry/app-src/setup-managed-hsm-tls.sh '$hsmName' '$($tlsIdentity.clientId)' '$tlsKeyLabel' '$appPrivateIp'
"@
                    $tlsOutput = Invoke-GpuRunCommand -Label 'Managed HSM TLS setup' -Script $managedHsmTlsScript -SuccessMarker 'MANAGED_HSM_TLS_READY=1'
                    $tlsKeyName = [regex]::Match($tlsOutput, 'MANAGED_HSM_TLS_KEY_NAME=([0-9a-fA-F-]+)').Groups[1].Value
                    if (-not $tlsKeyName) {
                        throw 'Managed HSM TLS setup did not return the generated key name.'
                    }
                    Set-HsmRoleAssignment `
                        -HsmName $hsmName `
                        -Role 'Managed HSM Crypto User' `
                        -PrincipalId $tlsIdentity.principalId `
                        -Scope "/keys/$tlsKeyName"
                } finally {
                    az keyvault role assignment delete `
                        --hsm-name $hsmName `
                        --role 'Managed HSM Crypto User' `
                        --assignee-object-id $tlsIdentity.principalId `
                        --scope '/keys' `
                        --output none
                }
            } finally {
                az resource update --ids $hsmId --set properties.publicNetworkAccess=Disabled properties.networkAcls.defaultAction=Deny properties.networkAcls.bypass=AzureServices --remove properties.networkAcls.ipRules | Out-Null
            }
                    $managedHsmTlsValidationScript = @'
            #!/bin/bash
            set -euo pipefail
            test ! -e /etc/citizen-registry/certs/citizen-registry.key
            systemctl is-active --quiet nginx
            curl -kfsS --resolve citizen-registry.internal:443:127.0.0.1 https://citizen-registry.internal/health >/dev/null
            echo 'MANAGED_HSM_SCOPED_TLS_READY=1'
            '@
                    Invoke-GpuRunCommand -Label 'key-scoped Managed HSM TLS validation' -Script $managedHsmTlsValidationScript -SuccessMarker 'MANAGED_HSM_SCOPED_TLS_READY=1' | Out-Null
            Write-Host "nginx TLS signing uses Managed HSM key $tlsKeyName" -ForegroundColor Green
        }

        $gpuInstallComplete = $false
        if ($ResumePostDeploy) {
            $gpuProbe = az vm run-command invoke `
                --resource-group $RgName `
                --name $CvmName `
                --command-id RunShellScript `
                --scripts "nvidia-smi >/dev/null 2>&1 && test -f /opt/cgpu-onboarding/cgpu-onboarding-package/step-2-attestation.sh && echo GPU_INSTALL_COMPLETE=1" `
                --query "value[].message" `
                --output tsv `
                --only-show-errors 2>&1
            $gpuInstallComplete = $LASTEXITCODE -eq 0 -and $gpuProbe -match 'GPU_INSTALL_COMPLETE=1'
        }

        if (-not $gpuInstallComplete) {
            Write-Host "GPU step 1/5: preparing the Azure CGPU V4.3.3 kernel..." -ForegroundColor Magenta
        $gpuKernelScript = @'
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait
PACKAGE=/tmp/cgpu-onboarding-package.tar.gz
INSTALL_DIR=/opt/cgpu-onboarding
URL=https://github.com/Azure/az-cgpu-onboarding/releases/download/V4.3.3/cgpu-onboarding-package.tar.gz
SHA256=297a9ebbb2228a4ef26c0e9d3b7917a0d9e90bfb52bcb4713c50cd6a3658d8f3
curl -fsSL --retry 5 --retry-connrefused --retry-delay 10 "$URL" -o "$PACKAGE"
echo "$SHA256  $PACKAGE" | sha256sum --check --strict
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
tar -xzf "$PACKAGE" -C "$INSTALL_DIR"
cd "$INSTALL_DIR/cgpu-onboarding-package"
test -f step-0-prepare-kernel.sh
sed '/^[[:space:]]*sudo reboot[[:space:]]*$/d' step-0-prepare-kernel.sh > step-0-prepare-kernel-no-reboot.sh
bash ./step-0-prepare-kernel-no-reboot.sh --enable-snapshot 20260827T120000Z
echo 'GPU_KERNEL_PREPARED=1'
'@
            Invoke-GpuRunCommand -Label 'GPU kernel preparation' -Script $gpuKernelScript -SuccessMarker 'GPU_KERNEL_PREPARED=1' | Out-Null

            Write-Host "GPU step 2/5: rebooting into the supported kernel..." -ForegroundColor Magenta
            az vm restart --resource-group $RgName --name $CvmName --only-show-errors --output none
            if ($LASTEXITCODE -ne 0) { throw 'App CVM failed to restart after GPU kernel preparation.' }

            Write-Host "GPU step 3/5: installing the NVIDIA 595 open driver..." -ForegroundColor Magenta
        $gpuDriverScript = @'
#!/bin/bash
set -euo pipefail
cd /opt/cgpu-onboarding/cgpu-onboarding-package
test -f step-1-install-gpu-driver.sh
printf '%s\n%s\n' '6.8.0-1025-azure' "$(uname -r)" | sort --check=quiet --version-sort
bash ./step-1-install-gpu-driver.sh
nvidia-smi
echo 'GPU_DRIVER_INSTALLED=1'
'@
            Invoke-GpuRunCommand -Label 'GPU driver installation' -Script $gpuDriverScript -SuccessMarker 'GPU_DRIVER_INSTALLED=1' | Out-Null

            Write-Host "GPU step 4/5: rebooting after driver installation..." -ForegroundColor Magenta
            az vm restart --resource-group $RgName --name $CvmName --only-show-errors --output none
            if ($LASTEXITCODE -ne 0) { throw 'App CVM failed to restart after GPU driver installation.' }
        } else {
            Write-Host "GPU steps 1-4/5 already complete; keeping the installed kernel and NVIDIA driver" -ForegroundColor Green
        }

        Write-Host "GPU step 5/5: verifying production CC mode and GPU attestation..." -ForegroundColor Magenta
        $gpuAttestScript = @'
#!/bin/bash
set -euo pipefail
cat > /usr/local/sbin/attest-confidential-gpu <<'GPUATTEST'
#!/bin/bash
set -euo pipefail
cd /opt/cgpu-onboarding/cgpu-onboarding-package
for attempt in $(seq 1 30); do
    if nvidia-smi >/dev/null 2>&1; then break; fi
    if [ "$attempt" -eq 30 ]; then exit 1; fi
    sleep 10
done
CC_STATUS=$(nvidia-smi conf-compute -f)
CC_ENVIRONMENT=$(nvidia-smi conf-compute -e)
test "$CC_STATUS" = 'CC status: ON'
test "$CC_ENVIRONMENT" = 'CC Environment: PRODUCTION'
set +e
bash ./step-2-attestation.sh --gpu-only 2>&1 | tee /tmp/gpu-attestation.log
ATTEST_EXIT=${PIPESTATUS[0]}
set -e
test "$ATTEST_EXIT" -eq 0
grep -F 'GPU Attestation is Successful.' /tmp/gpu-attestation.log
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)
ATTESTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REPORT_SHA256=$(sha256sum /tmp/gpu-attestation.log | cut -d' ' -f1)
printf '{"verified":true,"boot_id":"%s","cc_status":"ON","environment":"PRODUCTION","gpu":"NVIDIA H100","verifier":"NVIDIA nvtrust","result":"GPU Attestation is Successful.","report_sha256":"%s","onboarding_release":"Azure CGPU V4.3.3","attested_at":"%s"}\n' "$BOOT_ID" "$REPORT_SHA256" "$ATTESTED_AT" > /var/lib/citizen-registry/gpu-attestation.json
chmod 600 /var/lib/citizen-registry/gpu-attestation.json
echo "$CC_STATUS"
echo "$CC_ENVIRONMENT"
echo 'GPU_ATTEST_EXIT=0'
GPUATTEST
chmod 750 /usr/local/sbin/attest-confidential-gpu
cat > /etc/systemd/system/citizen-gpu-attestation.service <<'SERVICE'
[Unit]
Description=Attest the confidential H100 for the current VM boot
After=network-online.target
RequiresMountsFor=/var/lib/citizen-registry
Before=citizen-registry.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/attest-confidential-gpu
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SERVICE
mkdir -p /etc/systemd/system/citizen-registry.service.d
cat > /etc/systemd/system/citizen-registry.service.d/confidential-gpu.conf <<'DROPIN'
[Unit]
Requires=citizen-gpu-attestation.service
After=citizen-gpu-attestation.service
DROPIN
systemctl daemon-reload
systemctl enable citizen-gpu-attestation.service
systemctl restart citizen-gpu-attestation.service
systemctl restart citizen-registry.service
test -s /var/lib/citizen-registry/gpu-attestation.json
systemctl enable citizen-cctv-anonymizer.service
systemctl restart citizen-cctv-anonymizer.service
cat > /usr/local/sbin/attest-confidential-cpu <<'CPUATTEST'
#!/bin/bash
set -euo pipefail
WORKDIR=/opt/cvm-attestation-tools
mkdir -p "$WORKDIR"
cd "$WORKDIR"
if [ ! -x ./attest ]; then
    curl -fsSL --retry 5 --retry-delay 10 https://github.com/Azure/cvm-attestation-tools/releases/latest/download/attest-lin.zip -o attest-lin.zip
    python3 -c "import zipfile; zipfile.ZipFile('attest-lin.zip').extractall('.')"
    chmod 750 attest read_report 2>/dev/null || true
fi
./attest --c config_snp.json > /tmp/cpu-attestation.log 2>&1
chmod 600 /tmp/cpu-attestation.log
python3 - <<'PY'
import base64
import datetime
import hashlib
import json
import pathlib
import re

log_path = pathlib.Path('/tmp/cpu-attestation.log')
tokens = re.findall(
    r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    log_path.read_text(errors='replace'),
)
if not tokens:
    raise SystemExit('No MAA JWT found in CPU attestation output')
token = max(tokens, key=len)
payload_segment = token.split('.')[1]
payload = json.loads(base64.urlsafe_b64decode(
    payload_segment + '=' * (-len(payload_segment) % 4)
))
runtime = payload.get('x-ms-runtime', {}).get('vm-configuration', {})
isolation = payload.get('x-ms-isolation-tee', {})
claims = {
    'issuer': payload.get('iss'),
    'attestation_type': payload.get('x-ms-attestation-type') or isolation.get('x-ms-attestation-type'),
    'compliance_status': payload.get('x-ms-compliance-status') or isolation.get('x-ms-compliance-status'),
    'secure_boot': runtime.get('secure-boot'),
    'tpm_enabled': runtime.get('tpm-enabled'),
    'issued_at': payload.get('iat'),
    'expires_at': payload.get('exp'),
}
if claims['compliance_status'] != 'azure-compliant-cvm':
    raise SystemExit(f"Unexpected compliance status: {claims['compliance_status']}")
if claims['attestation_type'] != 'sevsnpvm':
    raise SystemExit(f"Unexpected attestation type: {claims['attestation_type']}")
if claims['secure_boot'] is not True or claims['tpm_enabled'] is not True:
    raise SystemExit('CPU attestation did not prove secure boot and vTPM')
evidence = {
    'verified': True,
    'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'verifier': 'Microsoft Azure Attestation',
    'result': 'Azure CVM attestation succeeded.',
    'attested_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
    'claims': claims,
}
evidence_path = pathlib.Path('/var/lib/citizen-registry/cpu-attestation.json')
evidence_path.write_text(json.dumps(evidence))
evidence_path.chmod(0o600)
PY
rm -f /tmp/cpu-attestation.log
echo 'CPU_ATTESTATION_VERIFIED=1'
CPUATTEST
chmod 750 /usr/local/sbin/attest-confidential-cpu
cat > /etc/systemd/system/citizen-cpu-attestation.service <<'SERVICE'
[Unit]
Description=Attest the confidential CPU and vTPM for the current VM boot
After=network-online.target
RequiresMountsFor=/var/lib/citizen-registry
Before=citizen-registry.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/attest-confidential-cpu
[Install]
WantedBy=multi-user.target
SERVICE
cat > /etc/systemd/system/citizen-cpu-attestation.timer <<'TIMER'
[Unit]
Description=Refresh the Microsoft Azure Attestation token
[Timer]
OnBootSec=5min
OnUnitActiveSec=4h
Persistent=true
[Install]
WantedBy=timers.target
TIMER
cat > /etc/systemd/system/citizen-registry.service.d/confidential-cpu.conf <<'DROPIN'
[Unit]
Requires=citizen-cpu-attestation.service
After=citizen-cpu-attestation.service
DROPIN
systemctl daemon-reload
systemctl enable citizen-cpu-attestation.service citizen-cpu-attestation.timer
systemctl restart citizen-cpu-attestation.service
systemctl start citizen-cpu-attestation.timer
test -s /var/lib/citizen-registry/cpu-attestation.json
echo 'CC status: ON'
echo 'CC Environment: PRODUCTION'
echo 'GPU Attestation is Successful.'
echo 'CPU_ATTESTATION_VERIFIED=1'
echo 'GPU_ATTEST_EXIT=0'
'@
        $gpuOutput = Invoke-GpuRunCommand -Label 'GPU attestation' -Script $gpuAttestScript -SuccessMarker 'GPU_ATTEST_EXIT=0'
        foreach ($requiredEvidence in @('CC status: ON', 'CC Environment: PRODUCTION', 'GPU Attestation is Successful.')) {
            if ($gpuOutput -notmatch [regex]::Escape($requiredEvidence)) {
                throw "GPU attestation output did not contain '$requiredEvidence'."
            }
        }
        Write-Host "Confidential H100 onboarding and attestation succeeded" -ForegroundColor Green

        Write-Host "Verifying the live confidential CCTV pipeline..." -ForegroundColor Magenta
        $cctvValidationScript = @'
#!/bin/bash
set -euo pipefail
trap 'systemctl status citizen-cctv-anonymizer.service --no-pager || true; journalctl -u citizen-cctv-anonymizer.service -n 80 --no-pager || true' ERR
systemctl is-active --quiet citizen-cctv-anonymizer.service
for attempt in $(seq 1 60); do
    if STATUS=$(curl -fsS http://127.0.0.1:8000/cctv/status 2>/dev/null) && printf '%s' "$STATUS" | python3 -c "import json,sys; assert json.load(sys.stdin)['state'] in ('processing', 'completed')"; then
        break
    fi
    if [ "$attempt" -eq 60 ]; then exit 1; fi
    sleep 5
done
test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/cctv)" = '200'
curl -fsS --range 0-1023 --dump-header /tmp/cctv-video.headers http://127.0.0.1:8000/cctv/video -o /tmp/cctv-video.range
grep -q '^HTTP/1.[01] 206' /tmp/cctv-video.headers
test "$(wc -c < /tmp/cctv-video.range)" -eq 1024
curl -kfsS --dump-header /tmp/cctv-hls.headers https://127.0.0.1/cctv/processed/index.m3u8 -o /tmp/cctv-index.m3u8
grep -qi '^content-type: application/vnd.apple.mpegurl' /tmp/cctv-hls.headers
grep -q '^#EXTM3U' /tmp/cctv-index.m3u8
SEGMENT=$(grep -E '^segment-[0-9]+\.ts$' /tmp/cctv-index.m3u8 | tail -1)
test -n "$SEGMENT"
curl -kfsS "https://127.0.0.1/cctv/processed/$SEGMENT" -o /tmp/cctv-segment.ts
test -s /tmp/cctv-segment.ts
test "$(curl -ksS -o /dev/null -w '%{http_code}' https://127.0.0.1/static/vendor/hls.min.js)" = '200'
rm -f /tmp/cctv-video.headers /tmp/cctv-video.range /tmp/cctv-hls.headers /tmp/cctv-index.m3u8 /tmp/cctv-segment.ts
echo 'CCTV_APP_READY=1'
'@
        Invoke-GpuRunCommand -Label 'CCTV pipeline validation' -Script $cctvValidationScript -SuccessMarker 'CCTV_APP_READY=1' | Out-Null
        Write-Host "Confidential CCTV face anonymization is live" -ForegroundColor Green

        # Managed HSM key metadata is data-plane protected. Crypto Auditor lets
        # the app display this key's attributes and SKR policy, but cannot
        # release, wrap, unwrap, export, delete, rotate, or modify the CMK.
        $appIdentityPrincipalId = az identity show --resource-group $RgName --name "$Prefix-cvm-identity" --query principalId -o tsv
        az resource update --ids $hsmId --set properties.publicNetworkAccess=Enabled properties.networkAcls.defaultAction=Allow properties.networkAcls.bypass=AzureServices | Out-Null
        try {
            Set-HsmRoleAssignment `
                -HsmName $hsmName `
                -Role 'Managed HSM Crypto Auditor' `
                -PrincipalId $appIdentityPrincipalId `
                -Scope "/keys/$osDiskKeyName"
        } finally {
            az resource update --ids $hsmId --set properties.publicNetworkAccess=Disabled properties.networkAcls.defaultAction=Deny properties.networkAcls.bypass=AzureServices --remove properties.networkAcls.ipRules | Out-Null
        }
        Write-Host "App identity can read CMK and SKR policy metadata" -ForegroundColor Green

        # Save outputs to file
        $outputFile = "./app-instance-outputs-$randomSuffix.json"
        $deployment | Out-File -FilePath $outputFile
        Write-Host ""
        Write-Host "Outputs saved to: $outputFile" -ForegroundColor Green
        
        # Next steps
        Write-Host ""
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Access via Bastion:"
        Write-Host "   az network bastion ssh -g $RgName -n $BastionName --target-resource-id {CVM_ID}"
        Write-Host ""
        Write-Host "2. Verify mTLS + Attestation:"
        Write-Host "   curl -v --cert citizen.crt --key citizen.key https://citizen-registry-internal.local:8443/health"
        Write-Host ""
        Write-Host "3. View app logs:"
        Write-Host "   az vm run-command invoke -g $RgName -n $CvmName --command-id RunShellScript --scripts 'tail -100 /var/log/citizen-registry.log'"
        Write-Host ""
        
    } catch {
        Write-Host "✗ Deployment failed: $_" -ForegroundColor Red
        exit 1
    }
    
    exit 0
}

# If no action specified
Write-Host "No action specified. Use one of: -Deploy, -ValidateOnly, or -Cleanup" -ForegroundColor Yellow
Write-Host "Example: .\Deploy-AppInstance.ps1 -Prefix `"yourprefix`" -SharedInfraRg `"yourprefixsharedinfra`" -Deploy" -ForegroundColor Cyan
