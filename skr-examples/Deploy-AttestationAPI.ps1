<#
.SYNOPSIS
    Deploy a Confidential VM with an Attestation API web server.

.DESCRIPTION
    Creates an Azure Confidential VM that runs a web server exposing an
    attestation API. When called with a user-supplied nonce, the server
    performs MAA guest attestation from inside the CVM's vTPM and returns
    a richly-formatted HTML page explaining every claim in the MAA token.

    Supports both AMD SEV-SNP and Intel TDX hardware (controlled by -TeeType).

    Deployment flow:
    1. Resource Group with random suffix (from -Prefix)
    2. VNet with public IP + NSG (HTTP 8080 + SSH locked to deployer's IP)
    3. Ubuntu 24.04 Confidential VM (Platform Managed Keys — no Key Vault)
       – AMD SEV-SNP: DCas_v5 series (default)
       – Intel TDX:   DCes_v6 series (-TeeType Intel)
    4. SSH into the CVM to install cvm-attestation-tools and start a
       Flask web server on port 8080

    Endpoints:
      http://<public-ip>:8080/           Landing page with usage instructions
      http://<public-ip>:8080/attest?nonce=<value>   Perform attestation

    The /attest endpoint:
    1. Receives the caller's nonce (any string up to 256 chars)
    2. Performs MAA guest attestation via the local vTPM, embedding the
       nonce as runtime data so the relying party can verify freshness
    3. Decodes the resulting MAA JWT token
    4. Returns an HTML page with:
       - The raw JWT token (compact form)
       - Every claim decoded and formatted in a table
       - Technical explanations of each claim's meaning
       - The nonce echoed back for verification

    After deployment, the script prints the URL and leaves the VM running.
    Use -Cleanup to tear everything down.

.PARAMETER Prefix
    3-8 character lowercase alphanumeric prefix for resource naming.
    A random 5-character suffix is appended automatically.

.PARAMETER Location
    Azure region (default: northeurope). Must support the chosen VM series.

.PARAMETER VMSize
    VM SKU override. If omitted, defaults based on -TeeType:
      AMD   → Standard_DC2as_v5
      Intel → Standard_DC2es_v6

.PARAMETER TeeType
    Trusted Execution Environment hardware platform (default: AMD).
      AMD   — AMD SEV-SNP (DCas_v5 series, attestation-type "sevsnpvm")
      Intel — Intel TDX   (DCes_v6 series, attestation-type "tdxvm")

.PARAMETER Cleanup
    Remove all resources created by a previous deployment.

.EXAMPLE
    .\Deploy-AttestationAPI.ps1 -Prefix "attest"
    Deploy on AMD SEV-SNP with attestation API web server.

.EXAMPLE
    .\Deploy-AttestationAPI.ps1 -Prefix "attest" -TeeType Intel
    Deploy on Intel TDX with attestation API web server.

.EXAMPLE
    .\Deploy-AttestationAPI.ps1 -Cleanup
    Remove all deployed resources.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z][a-z0-9]{2,7}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory = $false)]
    [string]$VMSize,

    [Parameter(Mandatory = $false)]
    [ValidateSet('AMD', 'Intel')]
    [string]$TeeType = "AMD",

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "attest-api-config.json"

# ---- TEE-specific settings (AMD SEV-SNP vs Intel TDX) ----
if ($TeeType -eq "Intel") {
    $attestationType = "tdxvm"
    $teeDisplay      = "Intel TDX"
    $isolationType   = "TDX"
    $defaultVMSize   = "Standard_DC2es_v6"
} else {
    $attestationType = "sevsnpvm"
    $teeDisplay      = "AMD SEV-SNP"
    $isolationType   = "SEV_SNP"
    $defaultVMSize   = "Standard_DC2as_v5"
}
if (-not $VMSize) { $VMSize = $defaultVMSize }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-SharedMaaEndpoint {
    param([string]$Location)
    $maaEndpoints = @{
        "eastus"             = "sharedeus.eus"
        "eastus2"            = "sharedeus2.eus2"
        "westus"             = "sharedwus.wus"
        "westus2"            = "sharedwus2.wus2"
        "westus3"            = "sharedwus3.wus3"
        "centralus"          = "sharedcus.cus"
        "northcentralus"     = "sharedncus.ncus"
        "southcentralus"     = "sharedscus.scus"
        "westcentralus"      = "sharedwcus.wcus"
        "canadacentral"      = "sharedcac.cac"
        "canadaeast"         = "sharedcae.cae"
        "northeurope"        = "sharedneu.neu"
        "westeurope"         = "sharedweu.weu"
        "uksouth"            = "shareduks.uks"
        "ukwest"             = "sharedukw.ukw"
        "francecentral"      = "sharedfrc.frc"
        "germanywestcentral" = "shareddewc.dewc"
        "switzerlandnorth"   = "sharedswn.swn"
        "swedencentral"      = "sharedsec.sec"
        "norwayeast"         = "sharednoe.noe"
        "eastasia"           = "sharedeasia.easia"
        "southeastasia"      = "sharedsasia.sasia"
        "japaneast"          = "sharedjpe.jpe"
        "australiaeast"      = "sharedeau.eau"
        "koreacentral"       = "sharedkrc.krc"
        "centralindia"       = "sharedcin.cin"
        "uaenorth"           = "shareduaen.uaen"
        "brazilsouth"        = "sharedsbr.sbr"
    }
    $ep = $maaEndpoints[$Location.ToLower()]
    if (-not $ep) {
        throw "No shared MAA endpoint for region '$Location'. Supported: $($maaEndpoints.Keys -join ', ')"
    }
    return "$ep.attest.azure.net"
}


function New-RandomCredential {
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $username = "cvm" + -join ((0..7) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $passChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = -join ((0..39) | ForEach-Object { $passChars[(Get-Random -Maximum $passChars.Length)] })
    return @{ Username = $username; Password = $password }
}


# ============================================================================
# CLEANUP
# ============================================================================
if ($Cleanup) {
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Yellow
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        $rg = $config.resourceGroup
        $bn = $config.basename
        Write-Host "Removing resource group: $rg ..." -ForegroundColor Yellow
        Remove-AzResourceGroup -Name $rg -Force -AsJob | Out-Null
        Remove-Item $configFile -Force -ErrorAction SilentlyContinue
        $cleanSshDir = Join-Path $scriptDir ".ssh"
        if (Test-Path $cleanSshDir) {
            Remove-Item "$cleanSshDir/$bn*" -Force -ErrorAction SilentlyContinue
            if (-not (Get-ChildItem $cleanSshDir -ErrorAction SilentlyContinue)) {
                Remove-Item $cleanSshDir -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Cleanup job submitted. Deletion continues in background." -ForegroundColor Green
        Write-Host "Check status: Get-Job | Where-Object Command -like '*Remove-AzResourceGroup*'" -ForegroundColor Gray
    }
    else {
        Write-Host "No config file found. Nothing to clean up." -ForegroundColor Yellow
    }
    exit
}


# ============================================================================
# VALIDATE
# ============================================================================
if (-not $Prefix) {
    Write-Host "`n=== Attestation API — MAA Guest Attestation from a Confidential VM ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\$scriptName -Prefix <name>                   Deploy on AMD SEV-SNP (default)"
    Write-Host "  .\$scriptName -Prefix <name> -TeeType Intel    Deploy on Intel TDX"
    Write-Host "  .\$scriptName -Cleanup                         Remove all resources"
    Write-Host ""
    Write-Host "  Deploys a CVM with a web server on port 8080 that performs" -ForegroundColor Gray
    Write-Host "  MAA guest attestation with a caller-supplied nonce." -ForegroundColor Gray
    Write-Host ""
    if (Test-Path $configFile) {
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        Write-Host "Current deployment:" -ForegroundColor Cyan
        Write-Host "  Resource Group: $($config.resourceGroup)"
        Write-Host "  Location:       $($config.location)"
        Write-Host "  Attest URL:     http://$($config.vmIp):8080/attest?nonce=test123"
    }
    exit
}

# Prerequisites
Write-Host "`nChecking prerequisites..." -ForegroundColor Cyan
$azModule = Get-Module -ListAvailable -Name Az.Accounts | Select-Object -First 1
if (-not $azModule) { throw "Azure PowerShell (Az) not installed. Run: Install-Module -Name Az -Force" }
Write-Host "  Az module: $($azModule.Version)" -ForegroundColor Green
$context = Get-AzContext
if (-not $context) { throw "Not logged in to Azure. Run: Connect-AzAccount" }
Write-Host "  Logged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "  Subscription: $($context.Subscription.Name)" -ForegroundColor Green


# ============================================================================
# GENERATE NAMES
# ============================================================================
$suffix = -join ((97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
$basename = $Prefix + $suffix
$resgrp = "$basename-attest-rg"
$vnetName = "$basename-vnet"
$pipName = "$basename-pip"
$nsgName = "$basename-nsg"
$vmName = "$basename-cvm"
$sshKeyDir = Join-Path $scriptDir ".ssh"
$sshKeyPath = Join-Path $sshKeyDir "$basename"
$cred = New-RandomCredential
$maaEndpoint = Get-SharedMaaEndpoint -Location $Location

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Attestation API — MAA Guest Attestation Web Server" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  TEE Platform:   $teeDisplay ($attestationType)"
Write-Host "  Basename:       $basename"
Write-Host "  Resource Group: $resgrp"
Write-Host "  Location:       $Location"
Write-Host "  VM:             $vmName ($VMSize)"
Write-Host "  MAA Endpoint:   $maaEndpoint"
Write-Host "  Disk Encryption: Platform Managed Keys (PMK)"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""


try {

# ============================================================================
# PHASE 1: RESOURCE GROUP + NETWORKING
# ============================================================================
Write-Host "Phase 1: Creating resource group and networking..." -ForegroundColor White

$tags = @{
    owner   = (Get-AzContext).Account.Id
    BuiltBy = $scriptName
    demo    = "attestation-api"
}
New-AzResourceGroup -Name $resgrp -Location $Location -Tag $tags -Force | Out-Null
Write-Host "  Resource group: $resgrp" -ForegroundColor Green

$subnetConfig = New-AzVirtualNetworkSubnetConfig -Name "VMSubnet" -AddressPrefix "10.0.1.0/24"
$vnet = New-AzVirtualNetwork `
    -Name $vnetName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AddressPrefix "10.0.0.0/16" `
    -Subnet $subnetConfig
Write-Host "  VNet: $vnetName (10.0.0.0/16)" -ForegroundColor Green

$pip = New-AzPublicIpAddress `
    -Name $pipName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -AllocationMethod Static `
    -Sku Standard
Write-Host "  Public IP: $pipName ($($pip.IpAddress))" -ForegroundColor Green

# NSG — allow SSH + HTTP 8080 from deployer's IP only
$myIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
$sshRule = New-AzNetworkSecurityRuleConfig `
    -Name "AllowSSH" `
    -Protocol Tcp -Direction Inbound -Priority 1000 `
    -SourceAddressPrefix $myIp -SourcePortRange * `
    -DestinationAddressPrefix * -DestinationPortRange 22 `
    -Access Allow
$httpRule = New-AzNetworkSecurityRuleConfig `
    -Name "AllowHTTP8080" `
    -Protocol Tcp -Direction Inbound -Priority 1010 `
    -SourceAddressPrefix $myIp -SourcePortRange * `
    -DestinationAddressPrefix * -DestinationPortRange 8080 `
    -Access Allow
$nsg = New-AzNetworkSecurityGroup `
    -Name $nsgName `
    -ResourceGroupName $resgrp `
    -Location $Location `
    -SecurityRules $sshRule, $httpRule
Write-Host "  NSG: $nsgName (SSH + HTTP 8080 from $myIp)" -ForegroundColor Green

# Ephemeral SSH key pair
if (-not (Test-Path $sshKeyDir)) { New-Item -ItemType Directory -Path $sshKeyDir -Force | Out-Null }
if (Test-Path $sshKeyPath) { Remove-Item "$sshKeyPath*" -Force }
ssh-keygen -t rsa -b 4096 -f $sshKeyPath -P "" -q 2>$null
$sshPubKey = Get-Content "$sshKeyPath.pub" -Raw
Write-Host "  SSH key pair generated" -ForegroundColor Green

Write-Host "Phase 1 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 2: DEPLOY CONFIDENTIAL VM (PMK — no Key Vault needed)
# ============================================================================
Write-Host "Phase 2: Deploying Confidential VM (Platform Managed Keys)..." -ForegroundColor White

$vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resgrp
$vmSubnet = $vnet.Subnets | Where-Object { $_.Name -eq "VMSubnet" }

$nicName = "$vmName-nic"
$pip = Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resgrp
$nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $resgrp
$ipConfig = New-AzNetworkInterfaceIpConfig -Name "ipconfig1" -Subnet $vmSubnet -PrivateIpAddress "10.0.1.4" -PublicIpAddress $pip
$nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $resgrp -Location $Location `
    -IpConfiguration $ipConfig -NetworkSecurityGroup $nsg
Write-Host "  NIC: $nicName (public IP $($pip.IpAddress))" -ForegroundColor Green

$securePassword = ConvertTo-SecureString -String $cred.Password -AsPlainText -Force
$vmCred = New-Object System.Management.Automation.PSCredential ($cred.Username, $securePassword)

$vm = New-AzVMConfig -VMName $vmName -VMSize $VMSize
$vm = Set-AzVMOperatingSystem -VM $vm -Linux -ComputerName $vmName -Credential $vmCred -DisablePasswordAuthentication
$vm = Add-AzVMSshPublicKey -VM $vm -KeyData $sshPubKey -Path "/home/$($cred.Username)/.ssh/authorized_keys"
$vm = Set-AzVMSourceImage -VM $vm `
    -PublisherName 'Canonical' -Offer 'ubuntu-24_04-lts' -Skus 'cvm' -Version "latest"
$vm = Add-AzVMNetworkInterface -VM $vm -Id $nic.Id

# Confidential OS disk — Platform Managed Keys (no DES)
$vm = Set-AzVMOSDisk -VM $vm `
    -StorageAccountType "StandardSSD_LRS" `
    -CreateOption "FromImage" `
    -SecurityEncryptionType "DiskWithVMGuestState" `
    -Linux

$vm = Set-AzVmSecurityProfile -VM $vm -SecurityType "ConfidentialVM"
$vm = Set-AzVmUefi -VM $vm -EnableVtpm $true -EnableSecureBoot $true
$vm = Set-AzVMBootDiagnostic -VM $vm -Disable

Write-Host "  Creating VM: $vmName (this takes 2-5 minutes)..." -ForegroundColor Cyan
New-AzVM -ResourceGroupName $resgrp -Location $Location -VM $vm | Out-Null
Write-Host "  VM created: $vmName" -ForegroundColor Green

$vmObj = Get-AzVM -ResourceGroupName $resgrp -Name $vmName
Write-Host "  VmId: $($vmObj.VmId)" -ForegroundColor Gray

Write-Host "Phase 2 complete.`n" -ForegroundColor Green


# ============================================================================
# PHASE 3: BOOTSTRAP — INSTALL TOOLS + START ATTESTATION WEB SERVER
# ============================================================================
Write-Host "Phase 3: Setting up attestation API web server via SSH..." -ForegroundColor White

$bootstrapScript = @'
#!/bin/bash
set -euo pipefail

echo ""
echo "================================================================"
echo " Attestation API — Installing tools and starting web server"
echo "================================================================"
echo " MAA: __MAA_ENDPOINT__"
echo " TEE: __TEE_DISPLAY__"
echo "================================================================"
echo ""

export DEBIAN_FRONTEND=noninteractive

# ---- System packages ----
echo "[1/4] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl tpm2-tools 2>&1 | tail -3

# ---- cvm-attestation-tools ----
echo "[2/4] Installing cvm-attestation-tools..."
CVM_ATTEST_DIR="/opt/cvm-attestation-tools"
git clone --depth 1 https://github.com/Azure/cvm-attestation-tools.git "$CVM_ATTEST_DIR" 2>&1 | tail -2
git clone --depth 1 https://github.com/microsoft/TSS.MSR.git "$CVM_ATTEST_DIR/cvm-attestation/TSS_MSR" 2>&1 | tail -2

if [ -e "/dev/tpmrm0" ]; then
    echo "  vTPM: /dev/tpmrm0 PRESENT"
else
    echo "  ERROR: No vTPM device found at /dev/tpmrm0"
    exit 1
fi

# ---- Python environment ----
echo "[3/4] Setting up Python environment..."
python3 -m venv /opt/attest-venv
source /opt/attest-venv/bin/activate
pip install --no-cache-dir --upgrade pip 2>&1 | tail -1
pip install --no-cache-dir flask requests cryptography 2>&1 | tail -3
pip install --no-cache-dir -r "$CVM_ATTEST_DIR/cvm-attestation/requirements.txt" 2>&1 | tail -3

# ---- Write the Flask web server ----
echo "[4/4] Creating attestation web server..."

cat > /opt/attest_server.py << 'PYEOF'
"""
Attestation API Web Server — runs inside an Azure Confidential VM.
Performs MAA guest attestation via the local vTPM and returns a
richly formatted HTML page explaining every claim.
"""
import sys, os, json, base64, hashlib, time, html, traceback
from datetime import datetime, timezone
sys.path.insert(0, '/opt/cvm-attestation-tools/cvm-attestation')

from flask import Flask, request, jsonify
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger

app = Flask(__name__)

MAA_ENDPOINT = "__MAA_ENDPOINT__"
ISOLATION = "__ISOLATION_TYPE__"
TEE_DISPLAY = "__TEE_DISPLAY__"
ATTEST_TYPE = "__ATTESTATION_TYPE__"

# ── Claim explanations (technical detail for the HTML output) ──
CLAIM_DOCS = {
    "iss": {
        "name": "Issuer",
        "desc": "The MAA instance that issued this token. This is the shared MAA endpoint for the Azure region where the CVM is deployed. Relying parties should validate this matches their expected MAA authority."
    },
    "jti": {
        "name": "JWT ID",
        "desc": "A unique identifier for this specific token instance. Can be used by relying parties for replay detection — each attestation call generates a new JTI."
    },
    "iat": {
        "name": "Issued At",
        "desc": "Unix timestamp when the token was issued. The relying party should check this is recent to prevent use of stale attestation evidence."
    },
    "exp": {
        "name": "Expiration Time",
        "desc": "Unix timestamp after which the token is no longer valid. MAA tokens typically expire within hours. The relying party must reject expired tokens."
    },
    "nbf": {
        "name": "Not Before",
        "desc": "Unix timestamp before which the token must not be accepted. Usually equal to 'iat'. Prevents early use of pre-issued tokens."
    },
    "x-ms-ver": {
        "name": "MAA API Version",
        "desc": "The version of the MAA attestation API that generated this token. Useful for tracking API compatibility."
    },
    "x-ms-attestation-type": {
        "name": "Attestation Type (top-level)",
        "desc": "Indicates the type of attestation performed. For guest attestation from a CVM, this is typically 'azurevm' at the top level. The TEE-specific attestation type appears in x-ms-isolation-tee."
    },
    "x-ms-policy-hash": {
        "name": "MAA Policy Hash",
        "desc": "SHA-256 hash of the MAA attestation policy that was evaluated. Relying parties can use this to verify the specific policy version that was applied during attestation."
    },
    "x-ms-policy-signer": {
        "name": "MAA Policy Signer",
        "desc": "Information about who signed the MAA policy. For shared MAA endpoints, this is Microsoft-managed. For private MAA instances, it identifies the customer's policy signer."
    },
    "x-ms-runtime": {
        "name": "Runtime Claims",
        "desc": "Contains runtime data including the signing key(s) generated inside the TEE. The 'keys' array contains JWK public keys that were included in the attestation evidence. These keys are bound to the TEE — the private keys never leave the hardware boundary. Relying parties can use these keys for secure channel establishment."
    },
    "x-ms-sevsnpvm-authorkeydigest": {
        "name": "SEV-SNP Author Key Digest",
        "desc": "SHA-384 digest of the author signing key used to endorse the VM firmware. This is part of AMD's attestation report and identifies who authored the guest firmware."
    },
    "x-ms-sevsnpvm-bootloader-svn": {
        "name": "Bootloader SVN",
        "desc": "Security Version Number of the bootloader component. Higher values indicate newer versions with security fixes. Used to enforce minimum security levels."
    },
    "x-ms-sevsnpvm-familyId": {
        "name": "Family ID",
        "desc": "Identifies the VM family/generation. Set by the hypervisor to classify the guest type. All zeros typically indicates a standard Azure CVM deployment."
    },
    "x-ms-sevsnpvm-guestsvn": {
        "name": "Guest SVN",
        "desc": "Security Version Number of the guest firmware. Incremented when security-relevant updates are applied. Relying parties can set minimum SVN requirements."
    },
    "x-ms-sevsnpvm-hostdata": {
        "name": "Host Data",
        "desc": "Data provided by the host/hypervisor at VM launch time. Can be used to bind VM configuration to the attestation report. Typically contains configuration hashes."
    },
    "x-ms-sevsnpvm-idkeydigest": {
        "name": "ID Key Digest",
        "desc": "SHA-384 digest of the platform identity key. Uniquely identifies the physical AMD processor. Can be used to pin workloads to specific hardware."
    },
    "x-ms-sevsnpvm-imageId": {
        "name": "Image ID",
        "desc": "Identifies the guest image/firmware loaded into the VM. Set by the BIOS/firmware at launch. Used to verify the expected guest image was loaded."
    },
    "x-ms-sevsnpvm-is-debuggable": {
        "name": "Is Debuggable",
        "desc": "Whether the VM was launched with debug capabilities enabled. MUST be false for production confidential workloads. A debuggable VM allows the hypervisor to inspect guest memory, defeating confidentiality guarantees."
    },
    "x-ms-sevsnpvm-launchmeasurement": {
        "name": "Launch Measurement",
        "desc": "SHA-384 hash of the initial guest memory contents at launch time. This is the critical measurement that proves the correct firmware was loaded. Relying parties should compare this against known-good measurements."
    },
    "x-ms-sevsnpvm-microcode-svn": {
        "name": "Microcode SVN",
        "desc": "Security Version Number of the CPU microcode. Ensures the processor is running microcode with all known security fixes applied."
    },
    "x-ms-sevsnpvm-migration-allowed": {
        "name": "Migration Allowed",
        "desc": "Whether the VM is allowed to migrate between physical hosts. For maximum security, this should be false — migration could theoretically expose the VM to a different trust boundary."
    },
    "x-ms-sevsnpvm-reportdata": {
        "name": "Report Data",
        "desc": "64 bytes of arbitrary data included in the hardware attestation report. Typically contains a hash of the runtime signing key, binding the key to the hardware measurement. The relying party can verify this matches the runtime keys."
    },
    "x-ms-sevsnpvm-reportid": {
        "name": "Report ID",
        "desc": "Unique identifier for this specific attestation report. Generated by the hardware and unique per-report. Can be used for audit logging."
    },
    "x-ms-sevsnpvm-smt-allowed": {
        "name": "SMT Allowed",
        "desc": "Whether Simultaneous Multi-Threading (hyperthreading) is allowed. Some security-sensitive workloads disable SMT to prevent side-channel attacks between threads sharing a physical core."
    },
    "x-ms-sevsnpvm-snpfw-svn": {
        "name": "SNP Firmware SVN",
        "desc": "Security Version Number of the AMD SEV-SNP firmware (PSP firmware). This firmware manages the encryption keys and memory integrity. Must be at a level that addresses all known vulnerabilities."
    },
    "x-ms-sevsnpvm-tee-svn": {
        "name": "TEE SVN",
        "desc": "Security Version Number of the Trusted Execution Environment firmware. Part of the TCB (Trusted Computing Base) versioning system."
    },
    "x-ms-sevsnpvm-vmpl": {
        "name": "VMPL (VM Privilege Level)",
        "desc": "The Virtual Machine Privilege Level at which the attestation was performed. VMPL 0 is the most privileged level. Azure CVMs typically attest at VMPL 0, meaning the attestation covers the entire guest."
    },
    "x-ms-isolation-tee": {
        "name": "TEE Isolation Claims",
        "desc": "Contains claims specific to the Trusted Execution Environment. This is where the critical security properties are reported — the compliance status, attestation type, and runtime VM configuration including the unique VM ID."
    },
    "x-ms-compliance-status": {
        "name": "Compliance Status",
        "desc": "Indicates whether the VM meets Azure's compliance requirements for confidential VMs. 'azure-compliant-cvm' means the VM passed all checks: valid hardware report, verified certificate chain, acceptable firmware measurements, and no debug flags."
    },
    "x-ms-attestation-type": {
        "name": "TEE Attestation Type",
        "desc": "The specific TEE hardware type: 'sevsnpvm' for AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging) or 'tdxvm' for Intel TDX (Trust Domain Extensions). This confirms which hardware isolation technology is protecting the VM."
    },
    "x-ms-runtime": {
        "name": "TEE Runtime Data",
        "desc": "Runtime claims nested under the TEE isolation context. Contains the VM configuration, signing keys, and other data that was measured into the attestation evidence at runtime."
    },
    "vm-configuration": {
        "name": "VM Configuration",
        "desc": "Configuration data about the VM instance, including the console-enabled flag, secure-boot status, TPM details, and the unique VM ID (vmUniqueId) assigned by Azure."
    },
    "vmUniqueId": {
        "name": "VM Unique ID",
        "desc": "The Azure-assigned unique identifier for this specific VM instance. This is the value used in VM-bound release policies to pin keys to a specific CVM. The ID is assigned at deployment time and remains constant for the VM's lifetime."
    },
    "console-enabled": {
        "name": "Console Enabled",
        "desc": "Whether the serial console is accessible. A potential vector for data exfiltration in high-security scenarios, though commonly enabled for debugging."
    },
    "secure-boot": {
        "name": "Secure Boot",
        "desc": "Whether UEFI Secure Boot is enabled. When true, only signed bootloaders and kernels can execute, preventing boot-level malware."
    },
    "tpm-enabled": {
        "name": "TPM Enabled",
        "desc": "Whether the virtual TPM (vTPM) is enabled. The vTPM is the device used to perform attestation — it generates the evidence that MAA evaluates."
    },
    "tpm-persisted": {
        "name": "TPM Persisted",
        "desc": "Whether TPM state (PCR values, sealed data) persists across reboots. Persistent TPM state allows sealed secrets to survive VM restarts."
    },
    "user-data": {
        "name": "User Data",
        "desc": "Custom data provided at VM creation time. Can be used to bind application-specific context to the attestation evidence."
    },
    "x-ms-sevsnpvm-qe-svn": {
        "name": "QE SVN",
        "desc": "Security Version Number of the Quoting Enclave (Intel terminology used in some cross-platform contexts). Part of TCB versioning."
    },
    "x-ms-tdx-mrtd": {
        "name": "TDX MR TD (Measurement Register TD)",
        "desc": "Measurement of the Trust Domain (TD) — a hash of the initial TD memory contents. Equivalent to AMD's launch measurement. Proves the correct TD image was loaded."
    },
    "x-ms-tdx-mrseam": {
        "name": "TDX MR SEAM",
        "desc": "Measurement of the TDX module (SEAM — Secure Arbitration Mode). Identifies the specific TDX firmware version running on the processor."
    },
    "x-ms-tdx-mrsignerseam": {
        "name": "TDX MR Signer SEAM",
        "desc": "Identity of the entity that signed the TDX SEAM module. For production Intel TDX, this should be Intel's signing key."
    },
    "x-ms-tdx-td-attributes": {
        "name": "TDX TD Attributes",
        "desc": "Attributes of the Trust Domain including debug status and other configuration flags. Debug must be disabled for production confidential workloads."
    },
    "x-ms-tdx-seam-svn": {
        "name": "TDX SEAM SVN",
        "desc": "Security Version Number of the TDX SEAM module. Higher values indicate newer firmware with security fixes."
    },
    "x-ms-tdx-tee-tcb-svn": {
        "name": "TDX TEE TCB SVN",
        "desc": "Security Version Number of the TEE Trusted Computing Base. Covers all firmware components that form the TCB for Intel TDX."
    },
    "x-ms-tdx-report-data": {
        "name": "TDX Report Data",
        "desc": "64 bytes of data included in the TDX attestation report. Similar to SEV-SNP report data — typically contains a hash binding runtime keys to the hardware report."
    },
}


def decode_jwt_payload(token):
    """Decode a JWT payload without signature verification."""
    try:
        payload = token.split('.')[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def format_timestamp(ts):
    """Format a Unix timestamp as human-readable UTC."""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ts)


def get_claim_info(key, parent_key=None):
    """Look up documentation for a claim key."""
    # Try the full key first, then just the leaf
    info = CLAIM_DOCS.get(key)
    if not info and parent_key:
        info = CLAIM_DOCS.get(f"{parent_key}.{key}")
    if not info:
        info = {"name": key, "desc": ""}
    return info


def render_value(key, value):
    """Render a claim value as HTML, with special formatting for known types."""
    if key in ('iat', 'exp', 'nbf') and isinstance(value, (int, float)):
        return f'<code>{value}</code> <span class="ts">({format_timestamp(value)})</span>'
    if isinstance(value, bool):
        colour = "#22c55e" if value else "#ef4444"
        return f'<span style="color:{colour};font-weight:bold">{str(value).lower()}</span>'
    if isinstance(value, str) and len(value) > 120:
        escaped = html.escape(value)
        return f'<details><summary><code>{html.escape(value[:80])}…</code></summary><code class="wrap">{escaped}</code></details>'
    if isinstance(value, str):
        return f'<code>{html.escape(value)}</code>'
    if isinstance(value, (int, float)):
        return f'<code>{value}</code>'
    return f'<code>{html.escape(json.dumps(value, indent=2))}</code>'


def render_claims_table(claims, parent_key=None, depth=0):
    """Recursively render claims as nested HTML tables."""
    rows = []
    for key, value in claims.items():
        info = get_claim_info(key, parent_key)
        full_key = f"{parent_key}.{key}" if parent_key else key

        if isinstance(value, dict):
            nested = render_claims_table(value, full_key, depth + 1)
            rows.append(f'''
                <tr class="nested-header depth-{depth}">
                    <td class="claim-key"><code>{html.escape(key)}</code></td>
                    <td class="claim-value">
                        <div class="claim-desc">{html.escape(info["desc"])}</div>
                        <table class="nested">{nested}</table>
                    </td>
                </tr>
            ''')
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            list_html = ""
            for i, item in enumerate(value):
                nested = render_claims_table(item, full_key, depth + 1)
                list_html += f'<div class="list-item"><strong>[{i}]</strong><table class="nested">{nested}</table></div>'
            rows.append(f'''
                <tr class="nested-header depth-{depth}">
                    <td class="claim-key"><code>{html.escape(key)}</code></td>
                    <td class="claim-value">
                        <div class="claim-desc">{html.escape(info["desc"])}</div>
                        {list_html}
                    </td>
                </tr>
            ''')
        else:
            desc_html = f'<div class="claim-desc">{html.escape(info["desc"])}</div>' if info["desc"] else ""
            rows.append(f'''
                <tr class="depth-{depth}">
                    <td class="claim-key"><code>{html.escape(key)}</code></td>
                    <td class="claim-value">{render_value(key, value)}{desc_html}</td>
                </tr>
            ''')
    return "\n".join(rows)


HTML_STYLE = """
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
           background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #38bdf8; margin-bottom: 0.5rem; font-size: 1.8rem; }
    h2 { color: #7dd3fc; margin: 1.5rem 0 0.75rem; font-size: 1.3rem;
         border-bottom: 1px solid #334155; padding-bottom: 0.4rem; }
    .subtitle { color: #94a3b8; margin-bottom: 1.5rem; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
             font-size: 0.8rem; font-weight: 600; }
    .badge-ok { background: #166534; color: #bbf7d0; }
    .badge-tee { background: #1e3a5f; color: #7dd3fc; }
    .badge-err { background: #7f1d1d; color: #fca5a5; }
    .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem; margin: 1rem 0; }
    .meta-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                 padding: 1rem; }
    .meta-card dt { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase;
                    letter-spacing: 0.05em; }
    .meta-card dd { color: #f1f5f9; font-family: monospace; font-size: 0.9rem;
                    margin-top: 0.2rem; word-break: break-all; }
    table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; }
    table.claims { background: #1e293b; border-radius: 8px; overflow: hidden;
                   border: 1px solid #334155; }
    table.claims th { background: #0f172a; color: #94a3b8; text-align: left;
                      padding: 0.75rem 1rem; font-size: 0.75rem;
                      text-transform: uppercase; letter-spacing: 0.05em; }
    table.claims td { padding: 0.6rem 1rem; border-top: 1px solid #1e293b;
                      vertical-align: top; }
    table.claims tr:hover > td { background: #1a2744; }
    .claim-key { width: 280px; white-space: nowrap; }
    .claim-key code { color: #fbbf24; font-size: 0.85rem; }
    .claim-value code { color: #a5f3fc; font-size: 0.85rem; }
    .claim-value code.wrap { word-break: break-all; white-space: pre-wrap; }
    .claim-desc { color: #94a3b8; font-size: 0.78rem; margin-top: 0.3rem;
                  line-height: 1.4; }
    .ts { color: #94a3b8; font-size: 0.8rem; }
    table.nested { background: transparent; border: 1px solid #334155;
                   border-radius: 4px; margin-top: 0.5rem; }
    table.nested td { padding: 0.4rem 0.75rem; font-size: 0.85rem; }
    .nested-header > td { border-left: 3px solid #38bdf8; }
    .list-item { margin: 0.5rem 0; }
    .jwt-box { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
               padding: 1rem; margin: 1rem 0; overflow-x: auto; }
    .jwt-box code { color: #a5f3fc; font-size: 0.75rem; word-break: break-all;
                    white-space: pre-wrap; }
    .nonce-box { background: #1a2e1a; border: 1px solid #22c55e; border-radius: 8px;
                 padding: 1rem; margin: 1rem 0; }
    .nonce-box code { color: #bbf7d0; }
    details summary { cursor: pointer; }
    details summary:hover { color: #38bdf8; }
    .error { background: #2d1b1b; border: 1px solid #ef4444; border-radius: 8px;
             padding: 1.5rem; margin: 1rem 0; }
    .error h2 { color: #fca5a5; border: none; }
    .error pre { color: #fca5a5; white-space: pre-wrap; font-size: 0.85rem; }
    .footer { color: #475569; font-size: 0.75rem; margin-top: 2rem;
              padding-top: 1rem; border-top: 1px solid #1e293b; }
    @media (max-width: 768px) { body { padding: 1rem; } .claim-key { width: auto; } }
</style>
"""


@app.route('/')
def index():
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Attestation API — {TEE_DISPLAY}</title>{HTML_STYLE}</head>
    <body><div class="container">
    <h1>Attestation API</h1>
    <p class="subtitle">MAA Guest Attestation from an Azure Confidential VM</p>
    <div class="meta">
        <div class="meta-card"><dt>TEE Platform</dt><dd>{TEE_DISPLAY}</dd></div>
        <div class="meta-card"><dt>MAA Endpoint</dt><dd>{MAA_ENDPOINT}</dd></div>
        <div class="meta-card"><dt>Isolation Type</dt><dd>{ISOLATION}</dd></div>
    </div>
    <h2>Usage</h2>
    <p>Call the <code>/attest</code> endpoint with a <code>nonce</code> parameter:</p>
    <div class="jwt-box"><code>GET /attest?nonce=my-unique-value-123</code></div>
    <p>The server will:</p>
    <ol style="margin:0.75rem 0 0 1.5rem;color:#cbd5e1">
        <li>Hash your nonce and embed it as runtime data in the attestation request</li>
        <li>Perform MAA guest attestation via the local vTPM</li>
        <li>Decode the returned JWT token</li>
        <li>Return an HTML page with every claim explained</li>
    </ol>
    <h2>Try It</h2>
    <p><a href="/attest?nonce=hello-world" style="color:#38bdf8">/attest?nonce=hello-world</a></p>
    <div class="footer">Running on {TEE_DISPLAY} &middot; MAA: {MAA_ENDPOINT}</div>
    </div></body></html>"""


@app.route('/attest')
def attest():
    nonce = request.args.get('nonce', '').strip()
    if not nonce:
        return """<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Error</title></head><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem">
        <div class="error" style="background:#2d1b1b;border:1px solid #ef4444;border-radius:8px;padding:1.5rem">
        <h2 style="color:#fca5a5">Missing nonce parameter</h2>
        <p>Usage: <code style="color:#fca5a5">/attest?nonce=your-value</code></p>
        </div></body></html>""", 400
    if len(nonce) > 256:
        return """<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Error</title></head><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem">
        <div class="error" style="background:#2d1b1b;border:1px solid #ef4444;border-radius:8px;padding:1.5rem">
        <h2 style="color:#fca5a5">Nonce too long</h2>
        <p>Maximum 256 characters.</p>
        </div></body></html>""", 400

    start = time.time()
    try:
        # Hash the nonce to get 64 bytes of runtime data
        nonce_hash = hashlib.sha256(nonce.encode('utf-8')).hexdigest()

        # Perform MAA attestation via vTPM
        maa_clean = MAA_ENDPOINT.replace('https://', '').replace('http://', '').rstrip('/')
        attest_url = f"https://{maa_clean}/attest/AzureGuest?api-version=2020-10-01"

        isolation_type = IsolationType[ISOLATION]
        logger = Logger("attest-api").get_logger()
        params = AttestationClientParameters(
            endpoint=attest_url,
            verifier=Verifier.MAA,
            isolation_type=isolation_type,
            claims=nonce_hash,
        )
        client = AttestationClient(logger, params)
        result = client.attest_guest()

        if not result:
            raise RuntimeError("attest_guest() returned empty result")

        maa_token = result.decode('utf-8').strip() if isinstance(result, bytes) else str(result).strip()
        claims = decode_jwt_payload(maa_token)
        elapsed = time.time() - start

        if not claims:
            raise RuntimeError("Could not decode JWT payload from MAA token")

        # Build claims table
        claims_html = render_claims_table(claims)

        # Token parts for display
        token_parts = maa_token.split('.')
        header = decode_jwt_payload('.' + token_parts[0] + '.') if len(token_parts) >= 2 else None
        # Decode header properly
        try:
            h_padded = token_parts[0] + '=' * (4 - len(token_parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(h_padded))
        except Exception:
            header = None

        header_html = ""
        if header:
            header_html = f"""
            <h2>JWT Header</h2>
            <div class="jwt-box"><code>{html.escape(json.dumps(header, indent=2))}</code></div>
            """

        # Determine status badges
        iso_tee = claims.get('x-ms-isolation-tee', {})
        compliance = iso_tee.get('x-ms-compliance-status', '(unknown)') if isinstance(iso_tee, dict) else '(unknown)'
        attest_type = iso_tee.get('x-ms-attestation-type', '(unknown)') if isinstance(iso_tee, dict) else '(unknown)'
        badge_compliance = 'badge-ok' if compliance == 'azure-compliant-cvm' else 'badge-err'

        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Attestation Result — {html.escape(nonce)}</title>{HTML_STYLE}</head>
        <body><div class="container">
        <h1>Attestation Result</h1>
        <p class="subtitle">MAA Guest Attestation from {TEE_DISPLAY}</p>

        <div style="margin:1rem 0">
            <span class="badge {badge_compliance}">{html.escape(compliance)}</span>
            <span class="badge badge-tee">{html.escape(attest_type)}</span>
        </div>

        <div class="nonce-box">
            <dt style="color:#86efac;font-size:0.75rem;text-transform:uppercase">Nonce (your input)</dt>
            <dd><code>{html.escape(nonce)}</code></dd>
            <dt style="color:#86efac;font-size:0.75rem;text-transform:uppercase;margin-top:0.5rem">SHA-256 of Nonce (embedded as runtime data)</dt>
            <dd><code>{nonce_hash}</code></dd>
        </div>

        <div class="meta">
            <div class="meta-card"><dt>MAA Endpoint</dt><dd>{html.escape(MAA_ENDPOINT)}</dd></div>
            <div class="meta-card"><dt>Attestation Type</dt><dd>{html.escape(attest_type)}</dd></div>
            <div class="meta-card"><dt>Compliance Status</dt><dd>{html.escape(compliance)}</dd></div>
            <div class="meta-card"><dt>Attestation Time</dt><dd>{elapsed:.2f}s</dd></div>
        </div>

        {header_html}

        <h2>MAA Token Claims</h2>
        <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.75rem">
            Every claim from the decoded JWT payload, with technical explanations.
            Nested objects are expandable.
        </p>
        <table class="claims">
            <thead><tr><th>Claim</th><th>Value &amp; Explanation</th></tr></thead>
            <tbody>{claims_html}</tbody>
        </table>

        <h2>Raw JWT Token</h2>
        <p style="color:#94a3b8;font-size:0.85rem">
            The complete MAA token in compact JWS format. Copy this to verify
            the signature using the MAA endpoint's JWKS keys.
        </p>
        <div class="jwt-box"><code>{html.escape(maa_token)}</code></div>

        <div class="footer">
            {TEE_DISPLAY} &middot; MAA: {MAA_ENDPOINT} &middot;
            Attestation took {elapsed:.2f}s &middot;
            {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
        </div></body></html>"""

    except Exception as e:
        elapsed = time.time() - start
        tb = traceback.format_exc()
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Attestation Error</title>{HTML_STYLE}</head>
        <body><div class="container">
        <h1>Attestation Error</h1>
        <div class="error">
            <h2>Attestation Failed</h2>
            <p>Nonce: <code>{html.escape(nonce)}</code></p>
            <p>Error: <code>{html.escape(str(e))}</code></p>
            <pre>{html.escape(tb)}</pre>
            <p style="margin-top:1rem;color:#94a3b8">Elapsed: {elapsed:.2f}s</p>
        </div>
        </div></body></html>""", 500


if __name__ == '__main__':
    print(f"Starting Attestation API on port 8080...")
    print(f"  TEE: {TEE_DISPLAY}")
    print(f"  MAA: {MAA_ENDPOINT}")
    print(f"  Isolation: {ISOLATION}")
    app.run(host='0.0.0.0', port=8080)
PYEOF

# ---- Create systemd service for the web server ----
cat > /etc/systemd/system/attest-api.service << 'SVCEOF'
[Unit]
Description=Attestation API Web Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/attest-venv/bin/python3 /opt/attest_server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable attest-api
systemctl start attest-api

echo ""
echo "================================================================"
echo " Attestation API server started on port 8080"
echo "================================================================"
echo ""

# Wait a moment then verify the service is running
sleep 3
if systemctl is-active --quiet attest-api; then
    echo "  Service: RUNNING"
    echo "  Endpoint: http://$(curl -s http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01\&format=text 2>/dev/null || echo '<public-ip>'):8080/attest?nonce=test"
else
    echo "  Service: FAILED"
    journalctl -u attest-api --no-pager -n 20
    exit 1
fi
'@

# Substitute placeholders
$bootstrapScript = $bootstrapScript `
    -replace '__MAA_ENDPOINT__', $maaEndpoint `
    -replace '__ISOLATION_TYPE__', $isolationType `
    -replace '__TEE_DISPLAY__', $teeDisplay `
    -replace '__ATTESTATION_TYPE__', $attestationType

# Write bootstrap to temp file for SCP
$tempScript = Join-Path ([System.IO.Path]::GetTempPath()) "attest-bootstrap-$basename.sh"
[System.IO.File]::WriteAllText($tempScript, $bootstrapScript)

$vmIp = (Get-AzPublicIpAddress -Name $pipName -ResourceGroupName $resgrp).IpAddress
$sshUser = $cred.Username
$sshOpts = @("-i", $sshKeyPath, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR")

# Wait for SSH
Write-Host "  Waiting for SSH on $vmIp..." -ForegroundColor Gray
$sshReady = $false
for ($i = 0; $i -lt 30; $i++) {
    $testResult = ssh @sshOpts -o ConnectTimeout=5 "$sshUser@$vmIp" "echo ok" 2>&1
    if ($testResult -match "ok") {
        $sshReady = $true
        break
    }
    Start-Sleep -Seconds 10
}
if (-not $sshReady) {
    throw "SSH not available on $vmIp after 5 minutes. Check NSG rules and VM status."
}
Write-Host "  SSH connected to $vmIp" -ForegroundColor Green

# Upload and run bootstrap
Write-Host "  Uploading bootstrap script..." -ForegroundColor Cyan
scp @sshOpts $tempScript "${sshUser}@${vmIp}:/tmp/attest-bootstrap.sh" 2>&1 | Out-Null
Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

Write-Host "  Running bootstrap (installing tools + starting web server)..." -ForegroundColor Cyan
Write-Host "  This typically takes 2-4 minutes..." -ForegroundColor Gray
Write-Host ""

$sshOutput = ssh @sshOpts "$sshUser@$vmIp" "sudo bash /tmp/attest-bootstrap.sh" 2>&1
$stdout = ($sshOutput | Out-String).Trim()

if ($stdout) {
    Write-Host $stdout
}

Write-Host ""
Write-Host "Phase 3 complete.`n" -ForegroundColor Green


# ============================================================================
# SAVE CONFIG + FINAL OUTPUT
# ============================================================================
$config = @{
    resourceGroup   = $resgrp
    basename        = $basename
    location        = $Location
    vmName          = $vmName
    vmSize          = $VMSize
    vmId            = $vmObj.VmId
    vmIp            = $vmIp
    sshUser         = $sshUser
    sshKeyPath      = $sshKeyPath
    maaEndpoint     = $maaEndpoint
    teeType         = $TeeType
    attestationType = $attestationType
    attestUrl       = "http://${vmIp}:8080/attest?nonce=test123"
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Force

$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " ATTESTATION API DEPLOYED" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group:  $resgrp"
Write-Host "  VM:              $vmName ($vmIp)"
Write-Host "  TEE Platform:    $teeDisplay ($attestationType)"
Write-Host "  MAA Endpoint:    $maaEndpoint"
Write-Host ""
Write-Host "  Attestation URL:" -ForegroundColor Cyan
Write-Host "  http://${vmIp}:8080/attest?nonce=hello-world" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Landing page:" -ForegroundColor Cyan
Write-Host "  http://${vmIp}:8080/" -ForegroundColor Yellow
Write-Host ""
Write-Host ("  Deployment time: {0} minutes and {1} seconds" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds) -ForegroundColor Gray
Write-Host ""
Write-Host "  To clean up: .\$scriptName -Cleanup" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Green

}
catch {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " DEPLOYMENT FAILED" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    if ($resgrp -and (Get-AzResourceGroup -Name $resgrp -ErrorAction SilentlyContinue)) {
        $answer = Read-Host "  Delete resource group '$resgrp'? (y/N)"
        if ($answer -match '^[Yy]') {
            Write-Host "  Removing resource group (background)..." -ForegroundColor Yellow
            Remove-AzResourceGroup -Name $resgrp -Force -AsJob | Out-Null
            Remove-Item $configFile -Force -ErrorAction SilentlyContinue
            if (Test-Path $sshKeyDir) { Remove-Item "$sshKeyDir/$basename*" -Force -ErrorAction SilentlyContinue }
            Write-Host "  Cleanup job submitted." -ForegroundColor Green
        }
        else {
            Write-Host "  Resources left in place. Clean up with: .\$scriptName -Cleanup" -ForegroundColor Yellow
        }
    }

    exit 1
}
