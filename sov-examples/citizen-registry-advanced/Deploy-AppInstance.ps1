<#
.SYNOPSIS
    Deploy App Instance for Citizen Registry Advanced Demo.

.DESCRIPTION
    Stage 2: Creates app instance resource group containing:
    - Confidential VM (C-vn2 with SEV-SNP TEE)
    - Database on ACC (private subnet)
    - Bastion host for secure access
    - Azure Attestation Service
    - Private Link to shared Managed HSM
    
    Requires Stage 1 (shared infrastructure) to be deployed first.

.PARAMETER Prefix
    REQUIRED. Short unique identifier (3-12 chars) for resource naming.
    Combined with random 5-digit suffix: {prefix}{random}app

.PARAMETER Location
    Azure region for resources. Defaults to "northeurope".

.PARAMETER SharedInfraRg
    REQUIRED. Name of the shared infrastructure resource group from Stage 1.
    Example: "sgallsharedinfra"

.PARAMETER CvmSize
    Confidential VM SKU. Defaults to "Standard_DC2as_v6".
    Options: DC1as_v6, DC2as_v6, DC4as_v6 (Azure Compute C-vn2 line)

.PARAMETER Deploy
    Execute the deployment.

.PARAMETER ValidateOnly
    Validate Bicep templates without deployment.

.PARAMETER Cleanup
    Delete the app instance resource group and all resources.

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "sgall" `
      -SharedInfraRg "sgallsharedinfra" `
    -Location "northeurope" `
      -Deploy

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "sgall" `
      -SharedInfraRg "sgallsharedinfra" `
      -ValidateOnly

.EXAMPLE
    .\Deploy-AppInstance.ps1 -Prefix "sgall" -Cleanup

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

    [string]$Location = "northeurope",

    [ValidateSet("Standard_DC1as_v5", "Standard_DC2as_v5", "Standard_DC1as_v6", "Standard_DC2as_v6", "Standard_DC4as_v6")]
    [string]$CvmSize = "Standard_DC2as_v5",

    [switch]$Deploy,
    [switch]$ValidateOnly,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# Generate random 5-digit suffix for resource group
if (-not $Cleanup) {
    # Check if outputs from Stage 1 exist
    if (-not $SharedInfraRg) {
        Write-Host "ERROR: -SharedInfraRg is required (from Stage 1 deployment)" -ForegroundColor Red
        Write-Host "Example: .\Deploy-AppInstance.ps1 -Prefix `"sgall`" -SharedInfraRg `"sgallsharedinfra`" -Deploy" -ForegroundColor Yellow
        exit 1
    }
}

$randomSuffix = Get-Random -Minimum 10000 -Maximum 99999
$RgName = "$($Prefix)$($randomSuffix)app"
$CvmName = "$($Prefix)-citizen-cvm"
$DbName = "$($Prefix)-citizendb"
$BastionName = "$($Prefix)-$($randomSuffix)-bastion"
$AttestationName = "$($Prefix)attest$(Get-Random -Minimum 100 -Maximum 999)"
$VnetName = "$($Prefix)-$($randomSuffix)-vnet"

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Citizen Registry Advanced — Stage 2: App Instance           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prefix:              $Prefix"
Write-Host "Resource Group:      $RgName"
Write-Host "Location:            $Location"
Write-Host "Shared Infra RG:     $SharedInfraRg"
Write-Host "Confidential VM:     $CvmName ($CvmSize)"
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
$sharedRg = az group show --name $SharedInfraRg --query "id" -o tsv 2>$null

if (-not $sharedRg) {
    Write-Host "✗ Shared infrastructure resource group not found: $SharedInfraRg" -ForegroundColor Red
    Write-Host "Please run Deploy-SharedInfra.ps1 first" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Shared infrastructure RG found" -ForegroundColor Green

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

# Ensure app instance resource group exists
Write-Host "Creating app instance resource group: $RgName" -ForegroundColor Yellow
az group create --name $RgName --location $Location | Out-Null
Write-Host "✓ App instance resource group ready" -ForegroundColor Green

# Get current user info for tagging
$userUpn = az ad signed-in-user show --query "userPrincipalName" -o tsv
Write-Host "Current user: $userUpn" -ForegroundColor Yellow

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
$sqlVmName = "$Prefix-sql-cvm"
$sqlPrivateIp = '10.0.3.5'
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
    az keyvault role assignment create --hsm-name $hsmName --role 'Managed HSM Crypto Service Encryption User' --assignee-object-id $desPrincipalId --scope "/keys/$osDiskKeyName" | Out-Null
    $cvmOrchestratorPrincipalId = az ad sp show --id 'bf7b6499-ff71-4aa2-97a4-f372087be7f0' --query id -o tsv
    if (-not $cvmOrchestratorPrincipalId) { throw 'Azure CVM Orchestrator service principal was not found.' }
    az keyvault role assignment create --hsm-name $hsmName --role 'Managed HSM Crypto Service Release User' --assignee-object-id $cvmOrchestratorPrincipalId --scope "/keys/$osDiskKeyName" | Out-Null
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
tar -czf $archivePath -C "./app-instance" app-src
$archiveBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($archivePath))
$appBootstrapScript = @"
#!/bin/bash
set -e
mkdir -p /opt/citizen-registry /etc/citizen-registry/certs /var/log/citizen-registry
echo '$archiveBase64' | base64 -d | tar -xzf - -C /opt/citizen-registry
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl python3-flask python3-requests libodbc2
printf '%s\n' 'msodbcsql18 msodbcsql/ACCEPT_EULA boolean true' | debconf-set-selections
export ACCEPT_EULA=Y
curl -fsSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y msodbcsql18
python3 -c "import urllib.request; urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', '/tmp/get-pip.py')"
python3 /tmp/get-pip.py --break-system-packages
pip3 install --break-system-packages --no-cache-dir azure-identity pyodbc gunicorn
openssl req -x509 -nodes -newkey rsa:3072 -days 365 -keyout /etc/citizen-registry/certs/client-ca.key -out /etc/citizen-registry/certs/client-ca.crt -subj '/C=NL/O=Norland IT Department/OU=Registry PKI/CN=Norland Registry Demo CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -nodes -newkey rsa:2048 -keyout /etc/citizen-registry/certs/citizen-registry.key -out /tmp/citizen-registry.csr -subj '/C=NL/O=Norland IT Department/OU=Citizen Registry/CN=citizen-registry.internal'
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:citizen-registry.internal,IP:10.0.3.4' > /tmp/server-ext.cnf
openssl x509 -req -in /tmp/citizen-registry.csr -CA /etc/citizen-registry/certs/client-ca.crt -CAkey /etc/citizen-registry/certs/client-ca.key -CAcreateserial -out /etc/citizen-registry/certs/citizen-registry.crt -days 365 -sha256 -extfile /tmp/server-ext.cnf
openssl req -nodes -newkey rsa:2048 -keyout /etc/citizen-registry/certs/citizen.key -out /tmp/citizen.csr -subj '/C=NL/O=Norland IT Department/OU=Registry Clients/CN=citizen-registry-demo-client'
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=clientAuth' > /tmp/client-ext.cnf
openssl x509 -req -in /tmp/citizen.csr -CA /etc/citizen-registry/certs/client-ca.crt -CAkey /etc/citizen-registry/certs/client-ca.key -CAcreateserial -out /etc/citizen-registry/certs/citizen.crt -days 365 -sha256 -extfile /tmp/client-ext.cnf
chmod 600 /etc/citizen-registry/certs/*.key
chmod 600 /etc/citizen-registry/certs/citizen-registry.key
cp /opt/citizen-registry/app-src/nginx.conf /etc/nginx/nginx.conf
printf 'MTLS_ENABLED=true\nAZURE_CLIENT_ID=$appIdentityClientId\nATTESTATION_ENDPOINT=https://$AttestationName.neu.attest.azure.net\nHSM_ENDPOINT=https://$hsmName.managedhsm.azure.net\nHSM_NAME=$hsmName\nOS_DISK_KEY_NAME=$osDiskKeyName\nKEY_RELEASE_STATUS=azure-cvm-attestation-bound\nAPP_CVM_IP=10.0.3.4\nSQL_CVM_IP=$sqlPrivateIp\nDB_HOST=$sqlPrivateIp\nDB_NAME=$DbName\nDB_USER=registryadmin\nDB_PASSWORD=$sqlAppPassword\nDB_SA_PASSWORD=$sqlSaPassword\n' > /etc/citizen-registry/environment
cat > /etc/systemd/system/citizen-registry.service <<'SERVICE'
[Unit]
After=network-online.target
[Service]
WorkingDirectory=/opt/citizen-registry/app-src
EnvironmentFile=/etc/citizen-registry/environment
ExecStart=/usr/local/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 app:app
Restart=always
[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable --now citizen-registry
systemctl enable nginx
systemctl restart nginx
"@
$appBootstrapScript = $appBootstrapScript -replace "`r`n", "`n" -replace "`r", ""
$appBootstrapScriptBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($appBootstrapScript))
$appBootstrap = @"
#cloud-config
runcmd:
    - echo '$appBootstrapScriptBase64' | base64 -d | bash
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

# Prepare Bicep parameters in a file to avoid Windows command-line length limits.
$parametersFile = Join-Path $env:TEMP "citizen-registry-$Prefix.parameters.json"
@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters = @{
        prefix = @{ value = $Prefix }
        cvmName = @{ value = $CvmName }
        cvmSize = @{ value = $CvmSize }
        bastionName = @{ value = $BastionName }
        attestationName = @{ value = $AttestationName }
        vnetName = @{ value = $VnetName }
        location = @{ value = $Location }
        ownerTag = @{ value = $userUpn }
        sharedInfraRgName = @{ value = $SharedInfraRg }
        diskEncryptionSetId = @{ value = $diskEncryptionSetId }
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

if ($Deploy) {
    Write-Host "Starting deployment..." -ForegroundColor Cyan
    
    try {
        $deployment = az deployment group create `
            --resource-group $RgName `
            --template-file "./bicep/app-instance.bicep" `
            --parameters "@$parametersFile" `
            --query "properties.outputs" `
            2>&1
        
        Write-Host "✓ Deployment completed successfully" -ForegroundColor Green
        Write-Host ""
        Write-Host "Deployment Outputs:" -ForegroundColor Cyan
        $deploymentOutputs = $deployment | ConvertFrom-Json
        Write-Host ($deploymentOutputs | ConvertTo-Json -Depth 10)

        # Managed HSM key metadata is data-plane protected. Crypto Auditor lets
        # the app display this key's attributes and SKR policy, but cannot
        # release, wrap, unwrap, export, delete, rotate, or modify the CMK.
        $appIdentityPrincipalId = az identity show --resource-group $RgName --name "$Prefix-cvm-identity" --query principalId -o tsv
        az resource update --ids $hsmId --set properties.publicNetworkAccess=Enabled properties.networkAcls.defaultAction=Allow properties.networkAcls.bypass=AzureServices | Out-Null
        try {
            az keyvault role assignment create `
                --hsm-name $hsmName `
                --role 'Managed HSM Crypto Auditor' `
                --assignee-object-id $appIdentityPrincipalId `
                --scope "/keys/$osDiskKeyName" `
                --output none
        } finally {
            az resource update --ids $hsmId --set properties.publicNetworkAccess=Disabled properties.networkAcls.defaultAction=Deny properties.networkAcls.bypass=AzureServices --remove properties.networkAcls.ipRules | Out-Null
        }
        Write-Host "App identity can read CMK and SKR policy metadata" -ForegroundColor Green

        # Complete cross-resource-group networking from the shared-infrastructure side.
        $appVnetId = $deploymentOutputs.vnetId.value
        az network vnet peering create --resource-group $SharedInfraRg --vnet-name "$Prefix-shared-vnet" --name shared-to-app --remote-vnet $appVnetId --allow-vnet-access | Out-Null
        az network private-dns link vnet create --resource-group $SharedInfraRg --zone-name privatelink.managedhsm.azure.net --name "$VnetName-link" --virtual-network $appVnetId --registration-enabled false | Out-Null
        Write-Host "Bidirectional VNet peering and HSM private DNS link ready" -ForegroundColor Green
        
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
Write-Host "Example: .\Deploy-AppInstance.ps1 -Prefix `"sgall`" -SharedInfraRg `"sgallsharedinfra`" -Deploy" -ForegroundColor Cyan
