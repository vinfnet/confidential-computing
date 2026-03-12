<#
.SYNOPSIS
    Deploy the Attestation API web server to any CVM via Custom Script Extension.

.DESCRIPTION
    Uses the Azure Custom Script Extension (Microsoft.Azure.Extensions.CustomScript)
    to install cvm-attestation-tools from GitHub and start a Flask web server on
    port 8080 that performs MAA guest attestation with a caller-supplied nonce.

    Everything runs through the ARM control plane — no SSH, no ephemeral keys,
    no credentials to manage.

    The extension automatically detects:
      - TEE type (AMD SEV-SNP or Intel TDX) from /dev/sev-guest or /dev/tdx_guest
      - MAA endpoint from IMDS region

    After deployment the VM exposes:
      http://<ip>:8080/                            Landing page with usage
      http://<ip>:8080/attest?nonce=<value>        Attestation (HTML)
      http://<ip>:8080/attest?nonce=<v>&format=json  Attestation (JSON)
      http://<ip>:8080/health                      Health check

    NOTE: Only one Custom Script Extension can exist per VM at a time.
    If the VM already has a Custom Script Extension for another purpose,
    this deployment will replace it.

.PARAMETER VMName
    Name of an existing Linux Confidential VM.

.PARAMETER ResourceGroupName
    Resource group containing the VM.

.PARAMETER MaaEndpoint
    Override the auto-detected MAA endpoint (e.g. "sharedneu.neu.attest.azure.net").

.PARAMETER OpenPort
    Add an NSG inbound rule allowing TCP 8080 from the caller's public IP.

.PARAMETER Remove
    Remove the Custom Script Extension and stop the attestation service.

.EXAMPLE
    .\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg"
    Deploy the attestation web server to an existing CVM.

.EXAMPLE
    .\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -OpenPort
    Deploy and open port 8080 on the VM's NSG.

.EXAMPLE
    .\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -MaaEndpoint "my-private.neu.attest.azure.net"
    Deploy with a custom (private) MAA endpoint.

.EXAMPLE
    .\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -Remove
    Remove the extension and stop the web server.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$MaaEndpoint,

    [Parameter(Mandatory = $false)]
    [switch]$OpenPort,

    [Parameter(Mandatory = $false)]
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$extensionName = "AttestationAPI"


# ============================================================================
# REMOVE MODE
# ============================================================================
if ($Remove) {
    Write-Host "`n=== REMOVING ATTESTATION API ===" -ForegroundColor Yellow

    # Stop the service first via RunCommand
    Write-Host "  Stopping attestation service..." -ForegroundColor Cyan
    try {
        $stopResult = Invoke-AzVMRunCommand `
            -ResourceGroupName $ResourceGroupName -VMName $VMName `
            -CommandId 'RunShellScript' `
            -ScriptString 'systemctl stop attest-api 2>/dev/null; systemctl disable attest-api 2>/dev/null; rm -f /etc/systemd/system/attest-api.service; systemctl daemon-reload; echo "Service stopped and removed"'
        $msg = ($stopResult.Value | Where-Object { $_.Code -like "*StdOut*" }).Message
        if ($msg) { Write-Host "  $($msg.Trim())" -ForegroundColor Green }
    }
    catch {
        Write-Host "  Could not stop service (VM may not be running): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Remove the extension
    Write-Host "  Removing Custom Script Extension..." -ForegroundColor Cyan
    try {
        Remove-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName `
            -Name $extensionName -Force | Out-Null
        Write-Host "  Extension removed." -ForegroundColor Green
    }
    catch {
        Write-Host "  Could not remove extension: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "`nAttestation API removed from $VMName." -ForegroundColor Green
    exit
}


# ============================================================================
# VALIDATION
# ============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Attestation API — Custom Script Extension" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Checking prerequisites..." -ForegroundColor Cyan
$azModule = Get-Module -ListAvailable -Name Az.Compute | Select-Object -First 1
if (-not $azModule) { throw "Az.Compute module not found. Run: Install-Module -Name Az -Force" }
Write-Host "  Az.Compute: $($azModule.Version)" -ForegroundColor Green

$context = Get-AzContext
if (-not $context) { throw "Not logged in to Azure. Run: Connect-AzAccount" }
Write-Host "  Logged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "  Subscription: $($context.Subscription.Name)" -ForegroundColor Green

$vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction Stop
Write-Host "  VM: $($vm.Name) ($($vm.HardwareProfile.VmSize)) in $($vm.Location)" -ForegroundColor Green

if ($vm.SecurityProfile -and $vm.SecurityProfile.SecurityType -eq "ConfidentialVM") {
    Write-Host "  Security type: ConfidentialVM" -ForegroundColor Green
}
else {
    Write-Host "  WARNING: VM may not be a Confidential VM (SecurityType: $($vm.SecurityProfile.SecurityType))" -ForegroundColor Yellow
}

# Find the VM's public IP (if any)
$vmIp = $null
try {
    $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
    $nic = Get-AzNetworkInterface -ResourceId $nicId
    $pipRef = $nic.IpConfigurations[0].PublicIpAddress
    if ($pipRef) {
        $pip = Get-AzPublicIpAddress | Where-Object { $_.Id -eq $pipRef.Id }
        $vmIp = $pip.IpAddress
        Write-Host "  Public IP: $vmIp" -ForegroundColor Green
    }
    else {
        Write-Host "  Public IP: (none)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  Public IP: could not determine" -ForegroundColor Yellow
}

if ($MaaEndpoint) {
    Write-Host "  MAA override: $MaaEndpoint" -ForegroundColor Cyan
}
else {
    Write-Host "  MAA endpoint: auto-detect from IMDS" -ForegroundColor Gray
}

Write-Host ""


# ============================================================================
# BUILD THE BOOTSTRAP SCRIPT
# ============================================================================
# This bash script is base64-encoded and passed to the Custom Script Extension.
# It installs cvm-attestation-tools from GitHub, writes a Python Flask app that
# auto-detects TEE type and MAA endpoint, and starts it as a systemd service.
#
# Nesting: PowerShell @'...'@ → Bash → cat << 'PYEOF' → Python
# All single-quoted so no variable expansion at any level.

$bootstrapScript = @'
#!/bin/bash
set -euo pipefail

echo ""
echo "================================================================"
echo " Attestation API — Custom Script Extension Bootstrap"
echo "================================================================"
echo ""

export DEBIAN_FRONTEND=noninteractive
mkdir -p /opt/attest-api

# MAA endpoint override (replaced by PowerShell if -MaaEndpoint was provided)
__MAA_OVERRIDE_COMMAND__

# ── System packages ──────────────────────────────────────────────────────────
echo "[1/5] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl tpm2-tools 2>&1 | tail -5

# ── cvm-attestation-tools from GitHub ────────────────────────────────────────
echo "[2/5] Installing cvm-attestation-tools from GitHub..."
CVM_DIR="/opt/cvm-attestation-tools"
if [ -d "$CVM_DIR" ]; then
    echo "  Already exists, updating..."
    cd "$CVM_DIR" && git pull --quiet 2>&1 | tail -1
    cd /
else
    git clone --depth 1 https://github.com/Azure/cvm-attestation-tools.git "$CVM_DIR" 2>&1 | tail -2
fi

if [ ! -d "$CVM_DIR/cvm-attestation/TSS_MSR" ]; then
    git clone --depth 1 https://github.com/microsoft/TSS.MSR.git "$CVM_DIR/cvm-attestation/TSS_MSR" 2>&1 | tail -2
fi

# Verify vTPM
if [ -e "/dev/tpmrm0" ]; then
    echo "  vTPM: /dev/tpmrm0 PRESENT"
else
    echo "  ERROR: No vTPM device found at /dev/tpmrm0"
    exit 1
fi

# ── Python environment ───────────────────────────────────────────────────────
echo "[3/5] Setting up Python environment..."
python3 -m venv /opt/attest-venv
source /opt/attest-venv/bin/activate
pip install --no-cache-dir --upgrade pip 2>&1 | tail -1
pip install --no-cache-dir flask requests cryptography 2>&1 | tail -3
pip install --no-cache-dir -r "$CVM_DIR/cvm-attestation/requirements.txt" 2>&1 | tail -3

# ── Write the Flask attestation web server ───────────────────────────────────
echo "[4/5] Creating attestation web server..."

cat > /opt/attest-api/server.py << 'PYEOF'
"""
Attestation API Web Server
Deployed via Azure Custom Script Extension.
Auto-detects TEE type (AMD SEV-SNP / Intel TDX) and MAA endpoint from IMDS.
"""
import sys, os, json, base64, hashlib, time, html, traceback, subprocess
from datetime import datetime, timezone

sys.path.insert(0, '/opt/cvm-attestation-tools/cvm-attestation')

import requests as http_requests
from flask import Flask, request, jsonify
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger

app = Flask(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

MAA_ENDPOINTS = {
    "eastus":             "sharedeus.eus.attest.azure.net",
    "eastus2":            "sharedeus2.eus2.attest.azure.net",
    "westus":             "sharedwus.wus.attest.azure.net",
    "westus2":            "sharedwus2.wus2.attest.azure.net",
    "westus3":            "sharedwus3.wus3.attest.azure.net",
    "centralus":          "sharedcus.cus.attest.azure.net",
    "northcentralus":     "sharedncus.ncus.attest.azure.net",
    "southcentralus":     "sharedscus.scus.attest.azure.net",
    "westcentralus":      "sharedwcus.wcus.attest.azure.net",
    "canadacentral":      "sharedcac.cac.attest.azure.net",
    "canadaeast":         "sharedcae.cae.attest.azure.net",
    "northeurope":        "sharedneu.neu.attest.azure.net",
    "westeurope":         "sharedweu.weu.attest.azure.net",
    "uksouth":            "shareduks.uks.attest.azure.net",
    "ukwest":             "sharedukw.ukw.attest.azure.net",
    "francecentral":      "sharedfrc.frc.attest.azure.net",
    "germanywestcentral": "shareddewc.dewc.attest.azure.net",
    "switzerlandnorth":   "sharedswn.swn.attest.azure.net",
    "swedencentral":      "sharedsec.sec.attest.azure.net",
    "norwayeast":         "sharednoe.noe.attest.azure.net",
    "eastasia":           "sharedeasia.easia.attest.azure.net",
    "southeastasia":      "sharedsasia.sasia.attest.azure.net",
    "japaneast":          "sharedjpe.jpe.attest.azure.net",
    "australiaeast":      "sharedeau.eau.attest.azure.net",
    "koreacentral":       "sharedkrc.krc.attest.azure.net",
    "centralindia":       "sharedcin.cin.attest.azure.net",
    "uaenorth":           "shareduaen.uaen.attest.azure.net",
    "brazilsouth":        "sharedsbr.sbr.attest.azure.net",
}


def detect_tee():
    """Auto-detect TEE type from device files."""
    if os.path.exists('/dev/sev-guest'):
        return 'SEV_SNP', 'AMD SEV-SNP', 'sevsnpvm'
    if os.path.exists('/dev/tdx_guest'):
        return 'TDX', 'Intel TDX', 'tdxvm'
    try:
        out = subprocess.check_output(['lscpu'], text=True)
        if 'GenuineIntel' in out:
            return 'TDX', 'Intel TDX', 'tdxvm'
    except Exception:
        pass
    return 'SEV_SNP', 'AMD SEV-SNP', 'sevsnpvm'


def detect_maa_endpoint():
    """Auto-detect MAA endpoint from IMDS region, or read override file."""
    override_file = '/opt/attest-api/maa-endpoint.conf'
    if os.path.exists(override_file):
        ep = open(override_file).read().strip()
        if ep:
            return ep
    try:
        resp = http_requests.get(
            'http://169.254.169.254/metadata/instance/compute/location'
            '?api-version=2021-02-01&format=text',
            headers={'Metadata': 'true'}, timeout=5
        )
        region = resp.text.strip().lower()
        ep = MAA_ENDPOINTS.get(region)
        if ep:
            return ep
        return f"shared{region}.{region}.attest.azure.net"
    except Exception:
        return "sharedneu.neu.attest.azure.net"


# Detect at startup
ISOLATION, TEE_DISPLAY, ATTEST_TYPE = detect_tee()
MAA_ENDPOINT = detect_maa_endpoint()

print(f"  TEE: {TEE_DISPLAY} ({ATTEST_TYPE})")
print(f"  MAA: {MAA_ENDPOINT}")
print(f"  Isolation: {ISOLATION}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLAIM DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

CLAIM_DOCS = {
    "iss": {
        "name": "Issuer",
        "desc": "The MAA instance that issued this token. Relying parties should validate this matches their expected MAA authority."
    },
    "jti": {
        "name": "JWT ID",
        "desc": "Unique identifier for this token. Can be used for replay detection."
    },
    "iat": {
        "name": "Issued At",
        "desc": "Unix timestamp when the token was issued. Should be recent to prevent stale evidence."
    },
    "exp": {
        "name": "Expiration Time",
        "desc": "Unix timestamp after which the token is invalid. Reject expired tokens."
    },
    "nbf": {
        "name": "Not Before",
        "desc": "Unix timestamp before which the token must not be accepted."
    },
    "x-ms-ver": {
        "name": "MAA API Version",
        "desc": "Version of the MAA attestation API that generated this token."
    },
    "x-ms-attestation-type": {
        "name": "Attestation Type",
        "desc": "Type of attestation performed. For CVM guest attestation this is typically 'azurevm' at the top level."
    },
    "x-ms-policy-hash": {
        "name": "MAA Policy Hash",
        "desc": "SHA-256 hash of the attestation policy evaluated. Verify to confirm the expected policy was applied."
    },
    "x-ms-policy-signer": {
        "name": "MAA Policy Signer",
        "desc": "Who signed the MAA policy. Microsoft-managed for shared endpoints; customer key for private MAA."
    },
    "x-ms-runtime": {
        "name": "Runtime Claims",
        "desc": "Runtime data including signing keys generated inside the TEE. These keys are bound to the hardware — private keys never leave the TEE boundary."
    },
    "x-ms-sevsnpvm-authorkeydigest": {
        "name": "SEV-SNP Author Key Digest",
        "desc": "SHA-384 digest of the author signing key endorsing the VM firmware."
    },
    "x-ms-sevsnpvm-bootloader-svn": {
        "name": "Bootloader SVN",
        "desc": "Security Version Number of the bootloader. Higher = newer with security fixes."
    },
    "x-ms-sevsnpvm-familyId": {
        "name": "Family ID",
        "desc": "VM family/generation identifier. All zeros = standard Azure CVM."
    },
    "x-ms-sevsnpvm-guestsvn": {
        "name": "Guest SVN",
        "desc": "Security Version Number of the guest firmware."
    },
    "x-ms-sevsnpvm-hostdata": {
        "name": "Host Data",
        "desc": "Data provided by the host at VM launch. Typically contains configuration hashes."
    },
    "x-ms-sevsnpvm-idkeydigest": {
        "name": "ID Key Digest",
        "desc": "SHA-384 digest of the platform identity key. Uniquely identifies the physical AMD processor."
    },
    "x-ms-sevsnpvm-imageId": {
        "name": "Image ID",
        "desc": "Identifies the guest image/firmware loaded into the VM."
    },
    "x-ms-sevsnpvm-is-debuggable": {
        "name": "Is Debuggable",
        "desc": "MUST be false for production. A debuggable VM allows the hypervisor to inspect guest memory."
    },
    "x-ms-sevsnpvm-launchmeasurement": {
        "name": "Launch Measurement",
        "desc": "SHA-384 hash of initial guest memory at launch. The critical measurement proving correct firmware was loaded."
    },
    "x-ms-sevsnpvm-microcode-svn": {
        "name": "Microcode SVN",
        "desc": "Security Version Number of the CPU microcode."
    },
    "x-ms-sevsnpvm-migration-allowed": {
        "name": "Migration Allowed",
        "desc": "Whether the VM can migrate between hosts. False = maximum security."
    },
    "x-ms-sevsnpvm-reportdata": {
        "name": "Report Data",
        "desc": "64 bytes of data in the hardware attestation report. Typically a hash binding runtime keys to hardware."
    },
    "x-ms-sevsnpvm-reportid": {
        "name": "Report ID",
        "desc": "Unique identifier for this attestation report."
    },
    "x-ms-sevsnpvm-smt-allowed": {
        "name": "SMT Allowed",
        "desc": "Whether hyperthreading is allowed. Some workloads disable SMT to prevent side-channel attacks."
    },
    "x-ms-sevsnpvm-snpfw-svn": {
        "name": "SNP Firmware SVN",
        "desc": "Security Version Number of the AMD SEV-SNP firmware (PSP)."
    },
    "x-ms-sevsnpvm-tee-svn": {
        "name": "TEE SVN",
        "desc": "Security Version Number of the TEE firmware."
    },
    "x-ms-sevsnpvm-vmpl": {
        "name": "VMPL",
        "desc": "VM Privilege Level. VMPL 0 = most privileged. Azure CVMs attest at VMPL 0."
    },
    "x-ms-isolation-tee": {
        "name": "TEE Isolation Claims",
        "desc": "Claims specific to the Trusted Execution Environment — compliance status, attestation type, VM configuration."
    },
    "x-ms-compliance-status": {
        "name": "Compliance Status",
        "desc": "'azure-compliant-cvm' = passed all checks: valid hardware report, verified cert chain, acceptable firmware, no debug flags."
    },
    "x-ms-runtime": {
        "name": "TEE Runtime Data",
        "desc": "Runtime claims under the TEE isolation context: VM configuration, signing keys, measured data."
    },
    "vm-configuration": {
        "name": "VM Configuration",
        "desc": "VM instance data: console-enabled, secure-boot, TPM details, unique VM ID."
    },
    "vmUniqueId": {
        "name": "VM Unique ID",
        "desc": "Azure-assigned unique VM identifier. Used in VM-bound release policies. Constant for the VM's lifetime."
    },
    "console-enabled": {
        "name": "Console Enabled",
        "desc": "Whether serial console is accessible."
    },
    "secure-boot": {
        "name": "Secure Boot",
        "desc": "Whether UEFI Secure Boot is enabled. Prevents unsigned bootloaders."
    },
    "tpm-enabled": {
        "name": "TPM Enabled",
        "desc": "Whether the virtual TPM is enabled."
    },
    "tpm-persisted": {
        "name": "TPM Persisted",
        "desc": "Whether TPM state persists across reboots."
    },
    "user-data": {
        "name": "User Data",
        "desc": "Custom data provided at VM creation time."
    },
    "x-ms-tdx-mrtd": {
        "name": "TDX MR TD",
        "desc": "Measurement of the Trust Domain — hash of initial TD memory. Equivalent to AMD launch measurement."
    },
    "x-ms-tdx-mrseam": {
        "name": "TDX MR SEAM",
        "desc": "Measurement of the TDX SEAM module firmware."
    },
    "x-ms-tdx-mrsignerseam": {
        "name": "TDX MR Signer SEAM",
        "desc": "Identity of the TDX SEAM module signer. Should be Intel for production."
    },
    "x-ms-tdx-td-attributes": {
        "name": "TDX TD Attributes",
        "desc": "Trust Domain attributes including debug status. Debug must be disabled for production."
    },
    "x-ms-tdx-seam-svn": {
        "name": "TDX SEAM SVN",
        "desc": "Security Version Number of the TDX SEAM module."
    },
    "x-ms-tdx-tee-tcb-svn": {
        "name": "TDX TEE TCB SVN",
        "desc": "Security Version Number of the TEE Trusted Computing Base for Intel TDX."
    },
    "x-ms-tdx-report-data": {
        "name": "TDX Report Data",
        "desc": "64 bytes of data in the TDX attestation report. Typically a hash binding runtime keys to hardware."
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# HTML HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def decode_jwt_payload(token):
    try:
        payload = token.split('.')[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def decode_jwt_header(token):
    try:
        header = token.split('.')[0]
        padding = 4 - len(header) % 4
        if padding != 4:
            header += '=' * padding
        return json.loads(base64.urlsafe_b64decode(header))
    except Exception:
        return None


def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ts)


def get_claim_info(key, parent_key=None):
    info = CLAIM_DOCS.get(key)
    if not info and parent_key:
        info = CLAIM_DOCS.get(f"{parent_key}.{key}")
    if not info:
        info = {"name": key, "desc": ""}
    return info


def render_value(key, value):
    if key in ('iat', 'exp', 'nbf') and isinstance(value, (int, float)):
        return f'<code>{value}</code> <span class="ts">({format_timestamp(value)})</span>'
    if isinstance(value, bool):
        colour = "#22c55e" if value else "#ef4444"
        return f'<span style="color:{colour};font-weight:bold">{str(value).lower()}</span>'
    if isinstance(value, str) and len(value) > 120:
        escaped = html.escape(value)
        return f'<details><summary><code>{html.escape(value[:80])}\u2026</code></summary><code class="wrap">{escaped}</code></details>'
    if isinstance(value, str):
        return f'<code>{html.escape(value)}</code>'
    if isinstance(value, (int, float)):
        return f'<code>{value}</code>'
    return f'<code>{html.escape(json.dumps(value, indent=2))}</code>'


def render_claims_table(claims, parent_key=None, depth=0):
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


# ═══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "tee": TEE_DISPLAY,
        "attestation_type": ATTEST_TYPE,
        "maa_endpoint": MAA_ENDPOINT,
        "isolation": ISOLATION,
    })


@app.route('/')
def index():
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Attestation API \u2014 {TEE_DISPLAY}</title>{HTML_STYLE}</head>
    <body><div class="container">
    <h1>Attestation API</h1>
    <p class="subtitle">MAA Guest Attestation from an Azure Confidential VM
    \u2014 deployed via Custom Script Extension</p>
    <div class="meta">
        <div class="meta-card"><dt>TEE Platform</dt><dd>{TEE_DISPLAY}</dd></div>
        <div class="meta-card"><dt>MAA Endpoint</dt><dd>{MAA_ENDPOINT}</dd></div>
        <div class="meta-card"><dt>Isolation Type</dt><dd>{ISOLATION}</dd></div>
    </div>
    <h2>Usage</h2>
    <p>Call the <code>/attest</code> endpoint with a <code>nonce</code> parameter:</p>
    <div class="jwt-box"><code>GET /attest?nonce=my-unique-value-123</code></div>
    <p>Add <code>&amp;format=json</code> for machine-readable JSON output:</p>
    <div class="jwt-box"><code>GET /attest?nonce=my-unique-value-123&amp;format=json</code></div>
    <h2>Try It</h2>
    <p><a href="/attest?nonce=hello-world" style="color:#38bdf8">/attest?nonce=hello-world</a> (HTML)</p>
    <p><a href="/attest?nonce=hello-world&format=json" style="color:#38bdf8">/attest?nonce=hello-world&amp;format=json</a> (JSON)</p>
    <p><a href="/health" style="color:#38bdf8">/health</a> (health check)</p>
    <div class="footer">Running on {TEE_DISPLAY} &middot; MAA: {MAA_ENDPOINT} &middot;
    Deployed via Custom Script Extension</div>
    </div></body></html>"""


@app.route('/attest')
def attest():
    nonce = request.args.get('nonce', '').strip()
    output_format = request.args.get('format', 'html').strip().lower()

    if not nonce:
        if output_format == 'json':
            return jsonify({"error": "Missing nonce parameter", "usage": "/attest?nonce=your-value"}), 400
        return """<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Error</title></head><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem">
        <div style="background:#2d1b1b;border:1px solid #ef4444;border-radius:8px;padding:1.5rem">
        <h2 style="color:#fca5a5">Missing nonce parameter</h2>
        <p>Usage: <code style="color:#fca5a5">/attest?nonce=your-value</code></p>
        </div></body></html>""", 400

    if len(nonce) > 256:
        if output_format == 'json':
            return jsonify({"error": "Nonce too long", "max_length": 256}), 400
        return """<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Error</title></head><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem">
        <div style="background:#2d1b1b;border:1px solid #ef4444;border-radius:8px;padding:1.5rem">
        <h2 style="color:#fca5a5">Nonce too long</h2><p>Maximum 256 characters.</p>
        </div></body></html>""", 400

    start = time.time()
    try:
        nonce_hash = hashlib.sha256(nonce.encode('utf-8')).hexdigest()

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
            raise RuntimeError("Could not decode JWT payload")

        # ── JSON format ──
        if output_format == 'json':
            header = decode_jwt_header(maa_token)
            iso_tee = claims.get('x-ms-isolation-tee', {})
            return jsonify({
                "token": maa_token,
                "nonce": nonce,
                "nonce_sha256": nonce_hash,
                "header": header,
                "claims": claims,
                "tee": TEE_DISPLAY,
                "attestation_type": ATTEST_TYPE,
                "compliance_status": iso_tee.get('x-ms-compliance-status', '(unknown)') if isinstance(iso_tee, dict) else '(unknown)',
                "maa_endpoint": MAA_ENDPOINT,
                "elapsed_seconds": round(elapsed, 3),
            })

        # ── HTML format ──
        claims_html = render_claims_table(claims)
        header = decode_jwt_header(maa_token)

        header_html = ""
        if header:
            header_html = f"""
            <h2>JWT Header</h2>
            <div class="jwt-box"><code>{html.escape(json.dumps(header, indent=2))}</code></div>
            """

        iso_tee = claims.get('x-ms-isolation-tee', {})
        compliance = iso_tee.get('x-ms-compliance-status', '(unknown)') if isinstance(iso_tee, dict) else '(unknown)'
        attest_type = iso_tee.get('x-ms-attestation-type', '(unknown)') if isinstance(iso_tee, dict) else '(unknown)'
        badge_compliance = 'badge-ok' if compliance == 'azure-compliant-cvm' else 'badge-err'

        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>Attestation Result \u2014 {html.escape(nonce)}</title>{HTML_STYLE}</head>
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
            <dt style="color:#86efac;font-size:0.75rem;text-transform:uppercase;margin-top:0.5rem">SHA-256 (embedded as runtime data)</dt>
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
            Every claim from the decoded JWT, with technical explanations.
        </p>
        <table class="claims">
            <thead><tr><th>Claim</th><th>Value &amp; Explanation</th></tr></thead>
            <tbody>{claims_html}</tbody>
        </table>

        <h2>Raw JWT Token</h2>
        <p style="color:#94a3b8;font-size:0.85rem">
            Complete MAA token in compact JWS format. Verify the signature
            using the MAA endpoint JWKS keys.
        </p>
        <div class="jwt-box"><code>{html.escape(maa_token)}</code></div>

        <div class="footer">
            {TEE_DISPLAY} &middot; MAA: {MAA_ENDPOINT} &middot;
            Attestation took {elapsed:.2f}s &middot;
            {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &middot;
            Deployed via Custom Script Extension
        </div>
        </div></body></html>"""

    except Exception as e:
        elapsed = time.time() - start
        tb = traceback.format_exc()
        if output_format == 'json':
            return jsonify({"error": str(e), "nonce": nonce, "elapsed_seconds": round(elapsed, 3)}), 500
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
    print(f"  TEE:       {TEE_DISPLAY}")
    print(f"  MAA:       {MAA_ENDPOINT}")
    print(f"  Isolation: {ISOLATION}")
    app.run(host='0.0.0.0', port=8080)
PYEOF

# ── Systemd service ──────────────────────────────────────────────────────────
echo "[5/5] Creating systemd service..."

cat > /etc/systemd/system/attest-api.service << 'SVCEOF'
[Unit]
Description=Attestation API Web Server (Custom Script Extension)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/attest-venv/bin/python3 /opt/attest-api/server.py
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
systemctl restart attest-api

# Wait and verify
sleep 3
if systemctl is-active --quiet attest-api; then
    echo ""
    echo "================================================================"
    echo " Attestation API: RUNNING on port 8080"
    echo "================================================================"
    echo ""
else
    echo ""
    echo "================================================================"
    echo " Attestation API: FAILED TO START"
    echo "================================================================"
    journalctl -u attest-api --no-pager -n 20
    exit 1
fi
'@


# ============================================================================
# PLACEHOLDER SUBSTITUTION
# ============================================================================
if ($MaaEndpoint) {
    $bootstrapScript = $bootstrapScript -replace '__MAA_OVERRIDE_COMMAND__', "echo '$MaaEndpoint' > /opt/attest-api/maa-endpoint.conf"
}
else {
    $bootstrapScript = $bootstrapScript -replace '__MAA_OVERRIDE_COMMAND__', '# No override — auto-detect from IMDS'
}


# ============================================================================
# DEPLOY THE CUSTOM SCRIPT EXTENSION
# ============================================================================
Write-Host "Deploying Custom Script Extension..." -ForegroundColor Cyan
Write-Host "  Extension: $extensionName (Microsoft.Azure.Extensions.CustomScript v2.1)" -ForegroundColor Gray
Write-Host "  This installs tools from GitHub and starts the web server." -ForegroundColor Gray
Write-Host "  Typically takes 3-6 minutes..." -ForegroundColor Gray
Write-Host ""

# Base64-encode the bash script for the extension's protectedSettings.script
$scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($bootstrapScript)
$scriptBase64 = [Convert]::ToBase64String($scriptBytes)

$protectedSettings = @{ script = $scriptBase64 } | ConvertTo-Json -Compress

$extResult = Set-AzVMExtension `
    -ResourceGroupName $ResourceGroupName `
    -VMName $VMName `
    -Name $extensionName `
    -Publisher "Microsoft.Azure.Extensions" `
    -ExtensionType "CustomScript" `
    -TypeHandlerVersion "2.1" `
    -ProtectedSettingString $protectedSettings `
    -ForceRerun (Get-Date -Format 'yyyyMMddHHmmss')

if ($extResult.IsSuccessStatusCode -eq $false -and $extResult.StatusCode) {
    Write-Host "  Extension deployment may have issues. Status: $($extResult.StatusCode)" -ForegroundColor Yellow
}

# Get extension output
Write-Host ""
Write-Host "Extension output:" -ForegroundColor Cyan
Write-Host "─────────────────────────────────────────────────" -ForegroundColor Gray
try {
    $extStatus = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName `
        -Name $extensionName -Status
    $stdout = ($extStatus.SubStatuses | Where-Object { $_.Code -like "*StdOut*" }).Message
    $stderr = ($extStatus.SubStatuses | Where-Object { $_.Code -like "*StdErr*" }).Message
    if ($stdout) { Write-Host $stdout }
    if ($stderr) {
        # Filter out pip/git noise, show only real errors
        $stderrLines = $stderr -split "`n" | Where-Object {
            $_ -and $_ -notmatch '^\s*(WARNING|DEPRECATION|notice|Cloning|Updating)' -and $_.Trim()
        }
        if ($stderrLines) {
            Write-Host "  stderr:" -ForegroundColor Yellow
            $stderrLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        }
    }
}
catch {
    Write-Host "  Could not retrieve extension output: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host "─────────────────────────────────────────────────" -ForegroundColor Gray


# ============================================================================
# OPEN PORT 8080 (optional)
# ============================================================================
if ($OpenPort) {
    Write-Host ""
    Write-Host "Opening port 8080 on NSG..." -ForegroundColor Cyan
    try {
        $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
        $nic = Get-AzNetworkInterface -ResourceId $nicId
        $nsgId = $nic.NetworkSecurityGroup.Id
        if (-not $nsgId) {
            # Check subnet-level NSG
            $subnetId = $nic.IpConfigurations[0].Subnet.Id
            $vnetName = ($subnetId -split '/')[8]
            $subnetName = ($subnetId -split '/')[-1]
            $vnetRg = ($subnetId -split '/')[4]
            $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRg
            $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $subnetName }
            $nsgId = $subnet.NetworkSecurityGroup.Id
        }

        if ($nsgId) {
            $nsgName = ($nsgId -split '/')[-1]
            $nsgRg = ($nsgId -split '/')[4]
            $nsg = Get-AzNetworkSecurityGroup -Name $nsgName -ResourceGroupName $nsgRg

            # Get caller's IP for a scoped rule
            $myIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()

            # Find next available priority
            $maxPriority = ($nsg.SecurityRules | Measure-Object -Property Priority -Maximum).Maximum
            $priority = if ($maxPriority) { [Math]::Max($maxPriority + 10, 1020) } else { 1020 }

            $nsg | Add-AzNetworkSecurityRuleConfig `
                -Name "AllowAttestAPI8080" `
                -Protocol Tcp -Direction Inbound -Priority $priority `
                -SourceAddressPrefix $myIp -SourcePortRange * `
                -DestinationAddressPrefix * -DestinationPortRange 8080 `
                -Access Allow | Set-AzNetworkSecurityGroup | Out-Null

            Write-Host "  NSG rule added: AllowAttestAPI8080 (TCP 8080 from $myIp)" -ForegroundColor Green
        }
        else {
            Write-Host "  No NSG found on NIC or subnet. You may need to open port 8080 manually." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Could not open port: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Open port 8080 manually in the VM's NSG." -ForegroundColor Yellow
    }
}


# ============================================================================
# FINAL OUTPUT
# ============================================================================
$elapsed = New-TimeSpan -Start $startTime -End (Get-Date)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " ATTESTATION API DEPLOYED VIA CUSTOM SCRIPT EXTENSION" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  VM:             $VMName"
Write-Host "  Resource Group: $ResourceGroupName"
Write-Host "  Extension:      $extensionName"
if ($MaaEndpoint) {
    Write-Host "  MAA Endpoint:   $MaaEndpoint (override)"
}
else {
    Write-Host "  MAA Endpoint:   auto-detected from IMDS"
}
Write-Host ""

if ($vmIp -and $vmIp -ne "Not Allocated") {
    Write-Host "  Attestation URL:" -ForegroundColor Cyan
    Write-Host "  http://${vmIp}:8080/attest?nonce=hello-world" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  JSON API:" -ForegroundColor Cyan
    Write-Host "  http://${vmIp}:8080/attest?nonce=hello-world&format=json" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Landing page:" -ForegroundColor Cyan
    Write-Host "  http://${vmIp}:8080/" -ForegroundColor Yellow
}
else {
    Write-Host "  No public IP detected. Access the API via the VM's private IP" -ForegroundColor Yellow
    Write-Host "  or add a public IP." -ForegroundColor Yellow
}

Write-Host ""
Write-Host ("  Deployment time: {0} minutes {1} seconds" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds) -ForegroundColor Gray
Write-Host ""
Write-Host "  To remove: .\$scriptName -VMName `"$VMName`" -ResourceGroupName `"$ResourceGroupName`" -Remove" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Green
