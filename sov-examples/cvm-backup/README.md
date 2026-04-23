# CVM Backup – sov-examples

Deploy a **Windows Confidential Virtual Machine (CVM)** in **Korea Central** with:

- Confidential OS-disk encryption backed by a Customer Managed Key (CMK) stored in Azure Key Vault Premium HSM
- Private Virtual Network with no public IP address
- A single resource group named `<prefix><5-digit-random-suffix>` (e.g. `myapp73421`)
- Azure Backup **Enhanced Policy** configured to back up the CVM **every 4 hours**
- An **initial on-demand backup** that is triggered and monitored to completion

All resources are created in **Korea Central** by default.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Azure subscription | Contributor or Owner on the target subscription |
| Az PowerShell module | `Install-Module Az -AllowClobber -Force` (v12.0+) |
| CVM Orchestrator service principal | Must exist in your AAD tenant (`bf7b6499-ff71-4aa2-97a4-f372087be7f0`). If it doesn't: `New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0` |
| Korea Central CVM quota | DCasv5 series quota – request via Azure portal if needed |

---

## Quick Start

```powershell
# Clone the repo and navigate to this folder
cd sov-examples/cvm-backup

# Run (prompts you to log in if not already authenticated)
./New-CVMWithBackup.ps1 -subsID "<YOUR-SUBSCRIPTION-ID>" -basename "mycvm"
```

The script will print the auto-generated admin password to the console **once** – copy it before it scrolls off.

---

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-subsID` | ✅ | — | Azure subscription ID |
| `-basename` | ✅ | — | Prefix for all resource names (e.g. `myapp`) |
| `-region` | ❌ | `koreacentral` | Azure region |
| `-vmsize` | ❌ | `Standard_DC2as_v5` | Confidential VM SKU |
| `-description` | ❌ | `""` | Optional tag added to the resource group |
| `-smoketest` | ❌ | (switch) | Automatically removes all resources after the initial backup completes |

---

## What Gets Created

```
<basename><5-digit-suffix>/           ← Resource Group (Korea Central)
├── <basename><suffix>akv             Key Vault Premium (HSM-backed CMK)
├── <basename><suffix>des             Disk Encryption Set (ConfidentialVmEncryptedWithCustomerKey)
├── <basename><suffix>vnet            Virtual Network 10.0.0.0/16
│   └── <basename><suffix>vmsubnet   VM subnet 10.0.0.0/24 (no public IP)
├── <basename><suffix>-nic            Network Interface (private only)
├── <basename><suffix>                Windows Server 2022 Confidential VM
│   SecurityType: ConfidentialVM      AMD SEV-SNP + vTPM + Secure Boot
│   SecurityEncryptionType: DiskWithVMGuestState
├── <basename><suffix>rsv             Recovery Services Vault
└── <basename><suffix>-backup-policy  Enhanced Backup Policy (every 4 h, 24 h window)
```

---

## Backup Configuration

| Setting | Value |
|---|---|
| Policy type | Enhanced (required for Confidential VMs) |
| Schedule | Hourly, every **4 hours** |
| Window start | 00:00 UTC |
| Window duration | 24 hours (all 4-hour slots active) |
| Retention | Default Enhanced Policy retention (30 days daily) |

---

## Accessing the VM

The VM has **no public IP address**.  To connect remotely, add one of:

- **Azure Bastion** in the same VNet (`AzureBastionSubnet 10.0.99.0/26` is a good choice)
- **Point-to-Site VPN**
- **Site-to-Site VPN / ExpressRoute**

---

## Cleanup

```powershell
Remove-AzResourceGroup -Name <resource-group-name> -Force
```

> ⚠️ The Key Vault has Purge Protection enabled (10-day retention).  
> If you need to re-deploy immediately with the same name, either wait 10 days or use a different `basename`.

---

## Notes & Disclaimers

- Use at your own risk; no warranties implied.
- Not intended for production without security review.
- Korea Central supports DCasv5 Confidential VMs – verify quota before deploying at scale.
- The initial backup can take 15–45 minutes depending on disk size.
- Script tested with Az PowerShell 12.x on PowerShell 7.4+.
