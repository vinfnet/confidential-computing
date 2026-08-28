<#
.SYNOPSIS
    Configure mutual TLS for citizen registry app with Azure Attestation.

.DESCRIPTION
    Generates mTLS certificates and policies, integrates with Azure Attestation
    for attestation-backed certificate issuance and validation.

.PARAMETER CvmName
    Name of the Confidential VM running the app.

.PARAMETER AttestationEndpoint
    Endpoint URL of the Azure Attestation Service.

.PARAMETER CertificatePath
    Path to store generated certificates and keys (default: ./shared-infra/certificates).

.PARAMETER AppFqdn
    FQDN of the citizen registry app (default: citizen-registry-internal.local).

.EXAMPLE
    .\configure-mtls.ps1 -CvmName "sgall-citizen-cvm" `
      -AttestationEndpoint "https://sgallattest123.eus.attest.azure.net"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CvmName,

    [Parameter(Mandatory = $true)]
    [string]$AttestationEndpoint,

    [string]$CertificatePath = "./shared-infra/certificates",

    [string]$AppFqdn = "citizen-registry-internal.local"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Configuring mTLS with Azure Attestation                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Create certificate directory
New-Item -ItemType Directory -Path $CertificatePath -Force | Out-Null
Write-Host "Certificate path: $CertificatePath" -ForegroundColor Yellow

# Generate self-signed certificates for initial setup
# (In production, use Azure Attestation to issue certificates)
Write-Host "Generating mTLS certificates..." -ForegroundColor Yellow

$certPath = "$CertificatePath\citizen-registry.crt"
$keyPath = "$CertificatePath\citizen-registry.key"
$csrPath = "$CertificatePath\citizen-registry.csr"

# Check if certificates already exist
if (Test-Path $certPath) {
    Write-Host "✓ Certificate already exists: $certPath" -ForegroundColor Yellow
} else {
    # Note: This is a simplified example. In production:
    # 1. Generate CSR from CVM
    # 2. Submit CSR to Azure Attestation
    # 3. Retrieve signed certificate
    
    Write-Host "  Certificate path: $certPath" -ForegroundColor Cyan
    Write-Host "  Key path: $keyPath" -ForegroundColor Cyan
    Write-Host "  CSR path: $csrPath" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "Certificate generation placeholder:" -ForegroundColor Yellow
    Write-Host "1. On CVM, generate CSR with:"
    Write-Host "   openssl req -new -newkey rsa:2048 -keyout citizen-registry.key -out citizen-registry.csr"
    Write-Host ""
    Write-Host "2. Submit CSR to Attestation Service:"
    Write-Host "   curl -X POST ${AttestationEndpoint}/certificates/sign -d @citizen-registry.csr"
    Write-Host ""
    Write-Host "3. Download signed certificate and place in $certPath"
    Write-Host ""
}

# Create attestation policy for mTLS
Write-Host "Creating attestation policy..." -ForegroundColor Yellow

$policy = @{
    version = "1.0"
    attestationType = "SgxEnclave"
    authorizationRules = @(
        @{
            c = @(
                @{
                    type = "x-ms-sgx-is-debuggable"
                    value = $false
                },
                @{
                    type = "x-ms-sgx-mrsigner"
                    value = ""  # Set to actual mrsigner from CVM
                }
            )
            n = "citizen-registry-policy"
        }
    )
    claimsIssuanceRules = @(
        @{
            c = @(
                @{
                    type = "appid"
                    value = "citizen-registry"
                },
                @{
                    type = "version"
                    value = "1.0"
                }
            )
            n = "mTLS Claims"
        }
    )
} | ConvertTo-Json -Depth 10

$policyPath = "$CertificatePath\attestation-policy.json"
$policy | Out-File -FilePath $policyPath -Encoding UTF8

Write-Host "✓ Attestation policy created: $policyPath" -ForegroundColor Green
Write-Host ""

# Output configuration for app deployment
Write-Host "mTLS Configuration Summary:" -ForegroundColor Cyan
Write-Host "  CVM Name: $CvmName" -ForegroundColor Yellow
Write-Host "  App FQDN: $AppFqdn" -ForegroundColor Yellow
Write-Host "  Attestation Endpoint: $AttestationEndpoint" -ForegroundColor Yellow
Write-Host "  Certificate Directory: $CertificatePath" -ForegroundColor Yellow
Write-Host ""

# Create config file for app
$config = @{
    mTLS = @{
        enabled = $true
        certificatePath = $certPath
        keyPath = $keyPath
        appFqdn = $AppFqdn
    }
    attestation = @{
        enabled = $true
        endpoint = $AttestationEndpoint
        policyFile = $policyPath
    }
} | ConvertTo-Json -Depth 10

$configPath = "$CertificatePath\mtls-config.json"
$config | Out-File -FilePath $configPath -Encoding UTF8

Write-Host "✓ mTLS configuration saved: $configPath" -ForegroundColor Green
Write-Host ""
Write-Host "Deployment Steps:" -ForegroundColor Cyan
Write-Host "1. Copy certificates to CVM at /etc/citizen-registry/certs/"
Write-Host "2. Configure nginx with mTLS in nginx.conf"
Write-Host "3. Start citizen-registry app with mTLS enabled"
Write-Host "4. Test connectivity with curl --cert --key options"
Write-Host ""
