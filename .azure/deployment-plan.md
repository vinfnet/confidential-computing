# Azure Deployment Plan

> **Status:** Deployed

Generated: 2026-10-14T18:00:03-07:00

---

## 1. Project Overview

**Goal:** Deploy three Azure confidential VMs with Confidential Data Disk Encryption (CDDE): Windows Server 2022, Ubuntu 22.04, and RHEL 10.2. Each VM must be reachable through Azure Bastion, tagged to prevent automatic shutdown, and verified as running, attested, and encrypted.

**Path:** Deploy the existing confidential data disk encryption sample.

**Source implementation:** `vm-samples/confidential-data-disk-encryption/Build-ConfidentialDataDiskCVM.ps1`

---

## 2. Requirements

| Attribute | Value |
|-----------|-------|
| Classification | Demo / preview evaluation |
| Scale | Small: three 2-vCPU CVMs |
| Budget | Functional validation prioritized; one isolated deployment stack and Bastion per CVM |
| Subscription | Azure Core Security PM RnD (`68432aaa-6eba-435c-bc7c-1d998d835e80`) |
| Location | Central US EUAP (`centraluseuap`) |
| VM size | `Standard_DC2ads_v5` |
| Tags | `LongRunning=true`, `description=EPO-demo` |
| Remote access | Standard Azure Bastion with tunneling; no VM public IP |
| Credentials | Generated independently per VM and printed only in the terminal |
| Success criteria | VM power state running; Confidential VM attestation succeeds; CDE extension succeeds; Linux data volume is LUKS/dm-crypt backed; Windows data volume is BitLocker protected and fully encrypted |

Central US EUAP is selected because the repository's September 2026 test matrix records end-to-end CDDE success there for all three requested OS variants with `Standard_DC2ads_v5`. Live checks on 2026-10-14 confirmed all three Marketplace images are available, the VM SKU has no subscription restrictions, and the subscription preview feature is registered.

---

## 3. Components Detected

| Component | Type | Technology | Path |
|-----------|------|------------|------|
| CDDE deployment automation | PowerShell / Azure CLI | Azure CVM, Key Vault, DES, Bastion, NAT Gateway | `vm-samples/confidential-data-disk-encryption/Build-ConfidentialDataDiskCVM.ps1` |
| Secure Key Release policy | Policy | Azure Attestation / Key Vault SKR | `vm-samples/confidential-data-disk-encryption/cdde-preview/DataDiskSKRPolicy.json` |
| Deployment guidance and tested matrix | Documentation | CDDE preview | `vm-samples/confidential-data-disk-encryption/README.md` |

Validated images:

- `Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:22.04.202610030`
- `MicrosoftWindowsServer:windowsserver2022:2022-datacenter-smalldisk-g2:20348.5761.261013`
- `RedHat:rhel-cvm:10_2_cvm:10.2.2026062312`

---

## 4. Recipe Selection

**Selected:** Azure CLI through the repository's PowerShell deployment script.

**Rationale:** The existing script implements the preview-only Compute API fields, Secure Key Release policy, confidential DES, guest disk preparation, CDE extension, private networking, NAT Gateway, Bastion, provider/feature checks, SKU checks, and retry behavior already validated by this repository.

No new infrastructure source files are required.

---

## 5. Architecture

Each OS deployment uses an isolated resource group and stack.

| Component | Azure Service | SKU / configuration | Quantity |
|-----------|---------------|---------------------|----------|
| Windows CVM | Virtual Machines | `Standard_DC2ads_v5`, ConfidentialVM, Secure Boot, vTPM | 1 |
| Ubuntu CVM | Virtual Machines | `Standard_DC2ads_v5`, ConfidentialVM, Secure Boot, vTPM | 1 |
| RHEL CVM | Virtual Machines | `Standard_DC2ads_v5`, ConfidentialVM, Secure Boot, vTPM | 1 |
| Guest data disk | Managed Disks | 32 GiB Premium SSD, `DataDiskEncryptedWithCustomerKey` | 3 |
| Key vault | Premium Azure Key Vault | RBAC, purge protection, exportable RSA-HSM key with SKR policy | 3 |
| Disk encryption set | Confidential DES | `ConfidentialVmEncryptedWithCustomerKey` | 3 |
| Managed identity | User-assigned managed identity | CDDE key-release identity | 3 |
| Private network | VNet, VM subnet, NSG, NIC | No VM public IP | 3 stacks |
| Outbound access | NAT Gateway + Standard public IP | Required by VM agent and CDE extension | 3 |
| Remote access | Azure Bastion + Standard public IP | Standard SKU with tunneling | 3 |

The design intentionally follows the tested script without consolidating networking or cryptographic resources, minimizing deviations from the successful combinations.

---

## 6. Provisioning Limit Checklist

Live quota and inventory checks were run against Central US EUAP on 2026-10-14.

| Resource Type | Number to Deploy | Current Usage | Total After Deployment | Limit / Quota | Status / source |
|---------------|------------------|---------------|------------------------|---------------|-----------------|
| Regional vCPUs | 6 | 0 | 6 | 16,100 | Within limit; `az vm list-usage` |
| Standard DCADSv5 family vCPUs | 6 | 0 | 6 | 100 | Within limit; `az quota` and `az vm list-usage` |
| Virtual machines | 3 | 0 in region | 3 | 25,000 | Within limit; `az quota` |
| Virtual networks | 3 | 0 | 3 | 1,000 | Within limit; `az network list-usages` |
| Public IP addresses | 6 | 0 | 6 | 1,000 | Within limit; `az network list-usages` |
| Network interfaces | 3 | 0 | 3 | 65,536 | Within limit; `az network list-usages` |
| Resource groups | 3 | 21 | 24 | 980 | Within documented subscription limit; Azure Resource Graph + Azure limits |
| Premium Key Vaults | 3 | 0 in region | 3 | 5,000 per subscription | Within documented limit; Azure Resource Graph + Azure limits |
| User-assigned managed identities | 3 | 1 in region | 4 | 1,000 per resource group | Within documented limit; Azure Resource Graph + Azure limits |
| Disk encryption sets | 3 | 0 in region | 3 | No constraining deployment quota identified | Azure Resource Graph; deployment verified per stack |
| NAT Gateways | 3 | 0 in region | 3 | 1,000 per subscription per region | Within documented limit; Azure Resource Graph + Azure limits |
| Azure Bastion hosts | 3 | 0 in region | 3 | No constraining regional count quota identified | Azure Resource Graph; deployment verified per stack |

**Status:** All quota-backed resources are within limits. Live SKU discovery returned `Standard_DC2ads_v5` with no restrictions. Quota does not guarantee physical capacity, so transient capacity or disk-management errors will be retried as requested.

---

## 7. Security

- VMs have private NICs only; inbound administration uses Azure Bastion.
- NAT Gateway provides outbound access without assigning a public IP to a VM.
- Confidential OS disk encryption uses `DiskWithVMGuestState`.
- Data disks use `DataDiskEncryptedWithCustomerKey`.
- Key Vault uses Premium SKU, RBAC authorization, purge protection, an HSM-backed key, and the supplied Secure Key Release policy.
- A user-assigned managed identity is used for attestation-bound key release.
- Passwords are randomly generated per VM, retained only in process memory, and printed in the final terminal table.
- RHEL CDDE remains experimental per repository guidance.

---

## 8. Execution and Verification

- [x] Analyze workspace and locate tested CDDE automation.
- [x] Confirm subscription and authenticated Azure CLI context.
- [x] Confirm CDDE preview feature and resource providers are registered.
- [x] Select a region with repository-recorded end-to-end success for all requested OS variants.
- [x] Confirm all three images and the VM SKU are currently available.
- [x] Validate compute and network quota.
- [x] Select the existing Azure CLI deployment recipe.
- [x] Validate the deployment plan.
- [x] Deploy Windows, Ubuntu, and RHEL stacks with password authentication.
- [x] Apply `LongRunning=true` and `description=EPO-demo` tags to each VM and resource group.
- [x] Verify all VMs report `PowerState/running`.
- [x] Verify CVM attestation from each guest.
- [x] Verify CDE extension provisioning succeeded.
- [x] Verify Linux LUKS/dm-crypt and Windows BitLocker encryption.
- [x] Verify Bastion provisioning and private-only VM networking.
- [x] Print one terminal table containing OS, VM, username, password, Bastion, validation state, and Azure portal link.

## 9. Validation Proof

### All validation checks pass

- [x] 1. Core validation: Azure CLI installed and authenticated; existing PowerShell deployment script parses; prerequisite feature, providers, policy, images, SKU, and quota validate.
- [x] 2. Docker build: not applicable; deployment is not containerized.
- [x] 3. Azure Policy validation: applicable assignments were enumerated; the script's Key Vault purge protection, NSG-backed subnet, private VM NIC, and first-party VM configuration are compatible with the relevant enforced assignments.
- [x] 4. Static RBAC verification: the script scopes `Key Vault Crypto Officer`, `Key Vault Crypto Service Encryption User`, and `Key Vault Crypto Service Release User` to each Key Vault. The operator has Contributor and eligible subscription Owner/User Access Administrator PIM roles for role-assignment creation.

### Commands and Results

Validated: 2026-10-14T18:32:00-07:00

| Check | Command / method | Result |
|-------|------------------|--------|
| PowerShell source | `System.Management.Automation.Language.Parser.ParseFile(Build-ConfidentialDataDiskCVM.ps1)` | PASS; no parse errors |
| SKR policy | `Get-Content -Raw DataDiskSKRPolicy.json \| ConvertFrom-Json` | PASS; valid JSON |
| Azure context | `az account show` | PASS; Azure Core Security PM RnD, enabled |
| Preview gate | `az feature show --namespace Microsoft.Compute --name ConfidentialVMDataDiskEncryptionPreview` | PASS; Registered |
| Providers | `az provider show` for Compute, KeyVault, ManagedIdentity, and Network | PASS; all Registered |
| Marketplace images | `az vm image list --location centraluseuap ...` | PASS; Windows Server 2022, Ubuntu 22.04 CVM, and RHEL 10.2 CVM images resolved |
| VM SKU | `az vm list-skus --location centraluseuap --size Standard_DC2ads_v5 --all` | PASS; no restrictions |
| Compute quota | `check-quota.ps1` and `az vm list-usage --location centraluseuap` | PASS; 100 DCADSv5-family vCPUs and 16,100 regional vCPUs available; 6 required |
| Network quota | `az network list-usages --location centraluseuap` | PASS; 1,000 VNet, 1,000 public IP, and 65,536 NIC capacity available |
| Azure Policy | `az policy assignment list --scope /subscriptions/68432aaa-6eba-435c-bc7c-1d998d835e80 --disable-scope-strict-match` | PASS; applicable assignments reviewed |
| Static RBAC | Source review of `Set-RoleAssignmentIfMissing` call sites | PASS; required Key Vault data-plane roles are least-privilege and vault-scoped |
| Operator RBAC | Role assignment and eligibility queries | PASS; Contributor active, Owner and User Access Administrator eligible |

## 10. Deployment Verification

Completed: 2026-10-14

| OS | VM | Power | Attestation | Guest CDDE | CDE extension | Bastion |
|----|----|-------|-------------|------------|---------------|---------|
| Windows Server 2022 | `epowin26-cvm` | Running | `sevsnpvm`, `azure-compliant-cvm`, Secure Boot and TPM true | BitLocker data volumes protected, fully encrypted, 100% | Succeeded | Succeeded |
| Ubuntu 22.04 | `epoubu26-cvm` | Running | `sevsnpvm`, `azure-compliant-cvm`, Secure Boot and TPM true | `/cde-data` backed by a LUKS2 dm-crypt mapper | Succeeded | Succeeded |
| RHEL 10.2 | `eporhl26-cvm` | Running | `sevsnpvm`, `azure-compliant-cvm`, Secure Boot and TPM true | `/cde-data` backed by a LUKS2 dm-crypt mapper | Succeeded | Succeeded |

All VM models report `DataDiskEncryptedWithCustomerKey` and a populated confidential data-disk encryption identity. VM NICs have no public IP. Each VM and resource group has `LongRunning=true` and `description=EPO-demo`.

### Live Role Verification

For each Key Vault:

- The VM CDDE user-assigned identity has `Key Vault Crypto Service Encryption User`.
- The VM CDDE user-assigned identity has `Key Vault Crypto Service Release User`.
- The confidential disk encryption set identity has `Key Vault Crypto Service Encryption User`.

All assignments are scoped to the corresponding Key Vault. Status: Pass.

### Guest Attestation Tools

Pre-staged and verified on 2026-10-14:

- Windows: `C:\CVMTools`, with `check-cvm-attestation.cmd` on the machine PATH.
- Ubuntu: `/opt/cvm-attestation`, with `/usr/local/bin/check-cvm-attestation`.
- RHEL: `/opt/cvm-attestation`, with `/usr/local/bin/check-cvm-attestation` configured for the RHEL CA trust bundle.

The staged command returned `sevsnpvm`, `azure-compliant-cvm`, and `Attested Platform Successfully` on all three CVMs.
