# Secure Key Release (SKR) Examples

This folder contains examples that deploy **Azure Confidential VMs** and demonstrate
**Secure Key Release** — the ability for a VM to prove its hardware identity to Azure
Key Vault and receive an encryption key that cannot be accessed any other way.

Both **AMD SEV-SNP** and **Intel TDX** hardware platforms are supported.

## Scripts

| Script | Description |
|--------|-------------|
| `Deploy-SKRExample.ps1` | SKR with standard CVM release policy (any compliant CVM with correct identity). Supports `-TeeType AMD` (default) and `-TeeType Intel`. |
| `Deploy-VMBoundSKR.ps1` | SKR with **VM-bound** release policy (key pinned to a specific VM's unique Azure VM ID) |
| `Deploy-AttestationAPI.ps1` | **Attestation API web server** — deploys a CVM with an HTTP endpoint that performs MAA guest attestation with a caller-supplied nonce |
| `Deploy-AttestationExtension.ps1` | **Attestation API via Custom Script Extension** — deploys the attestation web server to any existing CVM via ARM (no SSH needed) |

---

## Deploy-SKRExample.ps1

Deploys a CVM and releases a key using a policy that requires hardware TEE attestation.
Use `-TeeType AMD` (default) for AMD SEV-SNP or `-TeeType Intel` for Intel TDX.

## What It Does

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Deployment Overview                             │
│                                                                     │
│  1. Resource Group with random suffix                               │
│  2. VNet + Public IP + NSG (SSH locked to deployer's IP)            │
│  3. Azure Key Vault Premium (HSM-backed)                            │
│       └─ Key: "fabrikam-totally-top-secret-key"                     │
│            └─ Release policy: TEE-attested CVM only                 │
│  4. User-Assigned Managed Identity → KV get + release               │
│  5. DiskEncryptionSet → confidential OS disk (CMK)                  │
│  6. Ubuntu 24.04 Confidential VM                                    │
│       ├─ AMD: DCas_v5 series (SEV-SNP)                              │
│       └─ Intel: DCes_v6 series (TDX)                                │
│  7. SSH into CVM: attest via vTPM → MAA token → key release         │
│  8. Result streamed directly to your console                        │
│  9. Auto-cleanup: resource group deleted, SSH keys removed          │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```powershell
# AMD SEV-SNP (default) — deploy, run SKR, display result, auto-clean up (~10 minutes)
.\Deploy-SKRExample.ps1 -Prefix "skrdemo"

# Intel TDX — deploy on Intel TDX hardware
.\Deploy-SKRExample.ps1 -Prefix "skrdemo" -TeeType Intel
```

The script deploys all resources, SSHs into the CVM to perform secure key release,
displays the result, then automatically deletes the resource group and SSH keys.

To clean up a previous deployment manually (e.g. if the script was interrupted):

```powershell
.\Deploy-SKRExample.ps1 -Cleanup
```

### Parameters

| Parameter  | Required | Default             | Description                                    |
|------------|----------|---------------------|------------------------------------------------|
| `-Prefix`  | Yes*     | —                   | 3-8 char prefix for resource names             |
| `-Location`| No       | `northeurope`       | Azure region (must support chosen VM series)   |
| `-VMSize`  | No       | Auto per TeeType    | Override VM SKU (AMD: `Standard_DC2as_v5`, Intel: `Standard_DC2es_v6`) |
| `-TeeType` | No       | `AMD`               | TEE platform: `AMD` (SEV-SNP) or `Intel` (TDX) |
| `-Cleanup` | No       | —                   | Remove all resources from previous deployment  |

\* Required for deployment. Omit all params to see usage + current deployment status.

## The SKR Release Policy Explained

The key `fabrikam-totally-top-secret-key` is created with an HSM-enforced release policy.
The key material is stored in the Key Vault HSM and **cannot be exported** unless the
caller provides a **Microsoft Azure Attestation (MAA) token** that satisfies the policy.

### Policy Structure

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedneu.neu.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-compliance-status",
          "equals": "azure-compliant-cvm"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        }
      ]
    }
  ]
}
```

> The `x-ms-attestation-type` value changes based on `-TeeType`:
> - **AMD SEV-SNP**: `"sevsnpvm"` — genuine AMD SEV-SNP guest VM with memory encryption
> - **Intel TDX**: `"tdxvm"` — genuine Intel TDX Trust Domain with hardware isolation

### What Each Part Means

| Element | Purpose |
|---------|---------|
| **`anyOf`** | Array of acceptable attestation authorities. We specify the shared MAA endpoint for the deployment region. You could add multiple regions or private MAA instances. |
| **`authority`** | The MAA endpoint URL. Key Vault will only accept tokens issued by this authority. The shared MAA endpoint is operated by Microsoft and validates attestation evidence against the hardware vendor's root of trust. |
| **`allOf`** | All claims in this array must be present AND match. This is an AND condition — both claims are required. |
| **Claim 1:** `x-ms-isolation-tee.x-ms-compliance-status` = `azure-compliant-cvm` | MAA checked the hardware attestation report, verified the certificate chain against the vendor's root of trust, validated the firmware measurements, and confirmed this is a compliant Azure CVM. |
| **Claim 2:** `x-ms-isolation-tee.x-ms-attestation-type` = `sevsnpvm` or `tdxvm` | The attestation evidence came from the expected TEE hardware — AMD SEV-SNP or Intel TDX — confirming hardware memory isolation is active. |

### Why Nested Claims?

The claims use the **nested path** `x-ms-isolation-tee.x-ms-attestation-type` rather than
the top-level path `x-ms-attestation-type`. This is important because:

- MAA tokens for CVM attestation place TEE-specific claims **inside** the
  `x-ms-isolation-tee` object (the Trusted Execution Environment section)
- The top-level `x-ms-attestation-type` may contain a different value or be absent
- Using the wrong claim path causes the release policy to fail silently

> **Note:** `Add-AzKeyVaultKey -UseDefaultCVMPolicy` uses the correct nested paths
> for the disk CMK. We use the REST API for the application key to demonstrate how
> to construct a custom policy with these paths explicitly.

### What Gets Blocked

| Scenario | Result | Why |
|----------|--------|-----|
| Standard VM (no TEE) | ❌ Blocked | Cannot produce vTPM attestation with TEE evidence |
| CVM with debug enabled | ❌ Blocked | MAA will not issue `azure-compliant-cvm` for debug VMs |
| CVM that fails firmware check | ❌ Blocked | Compliance status won't be `azure-compliant-cvm` |
| CVM in wrong region (different MAA) | ❌ Blocked | Token authority won't match the policy |
| CVM without the managed identity | ❌ Blocked | Can't authenticate to Key Vault at all |
| CVM on wrong TEE (e.g. TDX key on SEV-SNP VM) | ❌ Blocked | Attestation type won't match the policy |
| Genuine Azure CVM on matching TEE with correct identity | ✅ Released | All conditions met |

## How It Works (Flow)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  1. VM boots on TEE hardware (AMD SEV-SNP or Intel TDX)                  │
│     └─ Hardware generates attestation report                             │
│        └─ AMD: SNP_REPORT signed by chip-unique VCEK                     │
│        └─ Intel: TD Quote signed by platform attestation key             │
│                                                                          │
│  2. Script SSHs into the VM and runs the bootstrap                       │
│     └─ Reads attestation evidence from vTPM (/dev/tpmrm0)               │
│        └─ cvm-attestation-tools sends evidence to MAA                    │
│                                                                          │
│  3. MAA validates the evidence                                           │
│     ├─ Verifies certificate chain → vendor root of trust                 │
│     ├─ Checks firmware measurements against known-good values            │
│     ├─ Confirms no debug flags are set                                   │
│     └─ Issues JWT token with claims:                                     │
│        ├─ x-ms-isolation-tee.x-ms-compliance-status: azure-compliant-cvm │
│        └─ x-ms-isolation-tee.x-ms-attestation-type: sevsnpvm | tdxvm     │
│                                                                          │
│  4. Bootstrap calls AKV /keys/{name}/{version}/release                   │
│     ├─ Auth: Managed identity bearer token (proves KV access)            │
│     └─ Body: { "target": "<MAA JWT token>" }                            │
│                                                                          │
│  5. AKV HSM evaluates the release policy                                 │
│     ├─ Validates MAA token signature                                     │
│     ├─ Checks token issuer matches policy authority                      │
│     ├─ Checks all claims match policy allOf conditions                   │
│     └─ If all pass → wraps key material in JWS and returns it            │
│                                                                          │
│  6. Bootstrap decodes the JWS to extract the JWK (key material)          │
│     └─ Output streams directly to your console via SSH                   │
│                                                                          │
│  7. Script auto-cleans up (deletes resource group + SSH keys)            │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Two Layers of Trust

The security of this example relies on **two independent layers**:

### Layer 1: Hardware Attestation (TEE → MAA → Release Policy)
The Key Vault HSM will not release the key unless it receives an MAA token proving
the caller is a genuine Confidential VM running on the expected TEE hardware (AMD SEV-SNP
or Intel TDX) that passed all compliance checks. This is enforced by the HSM — even
Microsoft cannot bypass it.

### Layer 2: Identity Authorization (Managed Identity → KV Access Policy)
Even if another CVM passes attestation, it cannot release the key unless its managed
identity has `get` + `release` permissions on the Key Vault. This ensures only the
**intended** CVM can access the key, not just any CVM in the subscription.

Both layers must pass for key release to succeed.

## Resources Created

| Resource | Name Pattern | Purpose |
|----------|-------------|---------|
| Resource Group | `{prefix}{suffix}-skr-rg` | Contains all resources |
| Virtual Network | `{prefix}{suffix}-vnet` | Private network (10.0.0.0/16) |
| Public IP | `{prefix}{suffix}-pip` | SSH access to VM |
| NSG | `{prefix}{suffix}-nsg` | SSH locked to deployer's IP |
| VM NIC | `{prefix}{suffix}-cvm-nic` | Public + private IP (10.0.1.4) |
| Confidential VM | `{prefix}{suffix}-cvm` | Ubuntu 24.04, DCas_v5 (AMD) or DCes_v6 (Intel), SSH key auth |
| Key Vault | `{prefix}{suffix}kv` | Premium (HSM), soft-delete |
| User Identity | `{prefix}{suffix}-id` | VM identity for KV access |
| Disk Encryption Set | `{prefix}{suffix}-des` | Confidential OS disk CMK |
| KV Key: `disk-cmk` | — | RSA-HSM 3072, disk encryption |
| KV Key: `fabrikam-totally-top-secret-key` | — | RSA-HSM 2048, exportable, SKR |

All resources are automatically deleted after the SKR result is displayed.

## Prerequisites

- **Azure PowerShell** (`Az` module) — `Install-Module -Name Az -Force`
- **SSH client** — pre-installed on macOS/Linux; on Windows use OpenSSH or Git Bash
- **Azure subscription** with Confidential VM quota for `DCas_v5` (AMD) or `DCes_v6` (Intel) series
- **Logged in** — `Connect-AzAccount`

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "No shared MAA endpoint for region" | Region doesn't have a shared MAA endpoint | Use a supported region (see script) |
| CMK creation fails repeatedly | Key Vault not fully provisioned | Script retries 6 times automatically |
| Bootstrap shows "No vTPM device" | VM not running as CVM | Check VM SKU is DCas_v5 (AMD) or DCes_v6 (Intel) |
| Key release returns 403 | Identity doesn't have KV permissions | Check access policy includes `get` + `release` |
| Key release returns policy error | MAA token claims don't match policy | Verify `-TeeType` matches the VM hardware, check claim paths |
| SSH connection times out | NSG or VM not ready | Script waits up to 5 min; check NSG allows your IP |
| "Enter passphrase for key" | SSH key generated with passphrase | Delete `.ssh/` folder and re-run; uses `-P ""` for no passphrase |
| Resources left after interruption | Script was killed before auto-cleanup | Run `.\Deploy-SKRExample.ps1 -Cleanup` |

---

## Deploy-VMBoundSKR.ps1

Deploys a CVM and creates a key whose release policy is **pinned to the specific VM's Azure VM ID**. This is the strongest form of key binding — the key can only ever be released to that one VM instance.

### How It Differs from Deploy-SKRExample.ps1

| Aspect | Deploy-SKRExample | Deploy-VMBoundSKR |
|--------|-------------------|-------------------|
| **Release policy** | Any compliant CVM + correct identity | Specific VM ID + compliant CVM + correct identity |
| **Key creation timing** | Before VM deployment | After VM deployment (needs VM ID) |
| **Key name** | `fabrikam-totally-top-secret-key` | `vm-bound-secret-key` |
| **Config file** | `skr-config.json` | `vmbound-config.json` |
| **RG naming** | `{prefix}{suffix}-skr-rg` | `{prefix}{suffix}-vmbound-rg` |

### Quick Start

```powershell
# Deploy CVM, create VM-bound key, run SKR, auto-clean up (~10 minutes)
.\Deploy-VMBoundSKR.ps1 -Prefix "vmbound"

# Clean up manually if interrupted
.\Deploy-VMBoundSKR.ps1 -Cleanup
```

### VM-Bound Release Policy

The key `vm-bound-secret-key` uses a three-condition release policy:

```json
{
  "version": "1.0.0",
  "anyOf": [{
    "authority": "https://sharedneu.neu.attest.azure.net",
    "allOf": [
      {
        "claim": "x-ms-isolation-tee.x-ms-compliance-status",
        "equals": "azure-compliant-cvm"
      },
      {
        "claim": "x-ms-isolation-tee.x-ms-attestation-type",
        "equals": "sevsnpvm"
      },
      {
        "claim": "x-ms-isolation-tee.x-ms-runtime.vm-configuration.vmUniqueId",
        "equals": "12345678-ABCD-EFGH-IJKL-000000000000"
      }
    ]
  }]
}
```

The third claim (`vmUniqueId`) is the key difference — it pins the key to a specific Azure VM ID.

> **Important:** The `vmUniqueId` comparison in the release policy is **case-sensitive**.
> MAA returns the VM ID in **uppercase** for AMD SEV-SNP but **lowercase** for Intel TDX.
> The script normalises the VM ID to match the MAA convention for the chosen TEE type
> (`.ToUpper()` for AMD, `.ToLower()` for Intel). A case mismatch will cause key release
> to fail silently.

### What Each Claim Does

| Claim | Purpose |
|-------|---------|
| `x-ms-isolation-tee.x-ms-compliance-status` = `azure-compliant-cvm` | VM passed MAA compliance checks (SNP report, VCEK chain, firmware) |
| `x-ms-isolation-tee.x-ms-attestation-type` = `sevsnpvm` | Genuine AMD SEV-SNP hardware with memory encryption |
| `x-ms-isolation-tee.x-ms-runtime.vm-configuration.vmUniqueId` = `<VM ID>` | The VM's Azure-assigned unique identifier matches exactly |

### What Gets Blocked

| Scenario | Result | Why |
|----------|--------|-----|
| Standard VM (no SEV-SNP) | Blocked | No vTPM attestation evidence |
| Different CVM (even with same identity) | Blocked | VM ID won't match the policy |
| Same CVM redeployed (new VM ID) | Blocked | Azure assigns a new VM ID on redeployment |
| CVM with debug enabled | Blocked | MAA won't issue compliance claim |
| The exact CVM deployed by this script | Released | All three conditions met |

### Why Only the Application Key Is VM-Bound

The disk encryption CMK (`disk-cmk`) uses the standard 2-claim CVM policy and is **not** VM-bound. Two independent constraints prevent this:

1. **Chicken-and-egg dependency** — The CMK must exist *before* the VM is deployed (to create the DiskEncryptionSet), but the VM ID is only assigned *after* deployment.
2. **AKV policy restriction** — Keys created with [`Add-AzKeyVaultKey -UseDefaultCVMPolicy`](https://learn.microsoft.com/powershell/module/az.keyvault/add-azkeyvaultkey) cannot have their release policy updated post-creation. AKV rejects `PATCH` requests with error `AKV.SKR.1016` ("Key Release Policy can only be set on versionless key"), even when the policy's `Immutable` flag is `False`.

Application-level keys created via the [AKV REST API](https://learn.microsoft.com/rest/api/keyvault/keys/create-key) with a custom release policy *can* include the `vmUniqueId` claim because they are created after the VM exists.

For more background on SKR policies, see:
- [Secure Key Release with AKV and ACC](https://learn.microsoft.com/azure/confidential-computing/concept-skr-attestation)
- [SKR policy grammar](https://learn.microsoft.com/azure/key-vault/keys/policy-grammar)

### Deployment Order

Because the release policy requires the VM ID, the script deploys in a different order than `Deploy-SKRExample.ps1`:

1. Resource Group + Networking (same)
2. Key Vault + Identity + Disk CMK + DES (SKR key **deferred**)
3. Deploy Confidential VM → capture `VmId`
4. **Create SKR key** with VM-ID-bound release policy
5. SSH bootstrap: attest + release key
6. Auto-cleanup

---

## Deploy-AttestationAPI.ps1

Deploys a CVM with a **web server** exposing an attestation API. When called with a
nonce, performs MAA guest attestation from inside the CVM's vTPM and returns a richly
formatted HTML page explaining every claim. Attestation-only (no Key Vault, no SKR),
uses Platform Managed Keys.

```powershell
.\Deploy-AttestationAPI.ps1 -Prefix "attest"              # AMD SEV-SNP
.\Deploy-AttestationAPI.ps1 -Prefix "attest" -TeeType Intel  # Intel TDX
.\Deploy-AttestationAPI.ps1 -Cleanup                         # Remove everything
```

Endpoints: `http://<ip>:8080/` (landing page) and `http://<ip>:8080/attest?nonce=<value>`

---

## Deploy-AttestationExtension.ps1

Deploys the same attestation API web server to any **existing** Linux CVM using the
Azure Custom Script Extension (`Microsoft.Azure.Extensions.CustomScript`). Everything
runs through the ARM control plane — no SSH, no ephemeral keys, no credentials.

The extension automatically detects the TEE type (AMD SEV-SNP or Intel TDX) and MAA
endpoint from IMDS at startup.

### Quick Start

```powershell
# Deploy the attestation web server to an existing CVM
.\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg"

# Deploy and open port 8080 on the VM's NSG
.\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -OpenPort

# Use a custom MAA endpoint (e.g. private MAA instance)
.\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -MaaEndpoint "my-private.neu.attest.azure.net"

# Remove the extension and stop the service
.\Deploy-AttestationExtension.ps1 -VMName "my-cvm" -ResourceGroupName "my-rg" -Remove
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-VMName` | Yes | Name of an existing Linux CVM |
| `-ResourceGroupName` | Yes | Resource group containing the VM |
| `-MaaEndpoint` | — | Override the auto-detected MAA endpoint |
| `-OpenPort` | — | Add NSG rule for TCP 8080 from caller's IP |
| `-Remove` | — | Remove extension and stop the service |

### Endpoints

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/` | HTML | Landing page with usage instructions |
| `/attest?nonce=<value>` | HTML | Attestation with decoded claims |
| `/attest?nonce=<value>&format=json` | JSON | Machine-readable attestation result |
| `/health` | JSON | Health check with TEE and MAA info |

### How It Works

1. PowerShell base64-encodes a bash bootstrap script
2. Deploys it via `Set-AzVMExtension` (Custom Script Extension)
3. The extension runs as root inside the VM:
   - Installs python3, venv, tpm2-tools
   - Clones cvm-attestation-tools from GitHub
   - Writes a Flask web server that auto-detects TEE + MAA
   - Creates a systemd service on port 8080
4. Optionally opens port 8080 on the VM's NSG
