# Customer Managed Key (CMK) Samples

**Last Updated:** April 2026

## Overview

Scripts for creating and analyzing Customer Managed Key (CMK) encryption keys in Azure Key Vault. Useful for testing CMK-based disk encryption scenarios, key lifecycle management, and auditing key expiry status across resource groups.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CMK Key Management Workflow                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   1. BUILD                              2. DETECT                        │
│   BuildRandomCMK.ps1                    DetectCMKStatus.ps1              │
│                                                                          │
│   ┌──────────────────────────┐         ┌──────────────────────────┐     │
│   │  Create Resource Group   │         │  Scan Resource Group     │     │
│   │  Create Key Vault (HSM)  │  ────▶  │  Enumerate Key Vaults    │     │
│   │  Generate 50 RSA Keys    │         │  List All Keys           │     │
│   │  (Random Expiry Dates)   │         │  Check Expiry Status     │     │
│   └──────────────────────────┘         └──────────┬───────────────┘     │
│                                                    │                     │
│                                                    ▼                     │
│                                         ┌──────────────────────┐        │
│                                         │  Console Table       │        │
│                                         │  ┌────────────────┐  │        │
│                                         │  │ OK        (grn)│  │        │
│                                         │  │ EXPIRING  (org)│  │        │
│                                         │  │ EXPIRED   (red)│  │        │
│                                         │  └────────────────┘  │        │
│                                         │  Optional CSV Export │        │
│                                         └──────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
```

## Available Scripts

| Script | Description | Status |
|--------|-------------|--------|
| `BuildRandomCMK.ps1` | Create a Key Vault with 50 encryption keys with random expiry dates | **Stable** |
| `BuildNCVMsWithCMK.ps1` | Deploy N Confidential VMs with CMK disk encryption (10% expired keys) | **Stable** |
| `DetectCMKStatus.ps1` | Analyze all CMK keys in a resource group and report expiry status | **Stable** |
| `DetectCMKRotation.ps1` | Detect CMK key rotation for CVMs, show active key version and rotation history | **Stable** |

---

## BuildRandomCMK.ps1

Creates an Azure Resource Group, a Premium Key Vault, and populates it with 50 RSA-3072 encryption keys. Each key is assigned a random expiry date ranging from 30 days in the past to 3 years in the future, providing a realistic spread of OK, expiring, and expired keys for testing.

### Usage

```powershell
./BuildRandomCMK.ps1 -subsID <YOUR SUBSCRIPTION ID> -Prefix <YOUR PREFIX>
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-subsID` | Yes | Your Azure subscription ID |
| `-Prefix` | Yes | Prefix for all resources. A 5-character random suffix is appended automatically (e.g., `mytest` becomes `mytestabcde`) |

### Example

```powershell
# Create a Key Vault with 50 keys using prefix "cmktest"
./BuildRandomCMK.ps1 -subsID "your-subscription-id" -Prefix "cmktest"
```

### What It Creates

- **Resource Group**: `<prefix><5 random chars>` (e.g., `cmktestabcde`)
- **Key Vault**: `<prefix><5 random chars>akv` (Premium SKU, disk encryption enabled)
- **50 RSA-3072 keys**: Named `<basename>-key-001` through `<basename>-key-050` with `wrapKey` and `unwrapKey` operations

---

## BuildNCVMsWithCMK.ps1

End-to-end script that deploys N Confidential VMs (Ubuntu 24.04 LTS) on `Standard_DC2as_v5` (cheapest ACC SKU) with Confidential OS Disk Encryption using individual customer managed keys. At least 10% of VMs are deliberately assigned an expired CMK key for testing detection scenarios. All VMs share a private subnet with no public IPs, boot diagnostics disabled, and auto-shutdown at 19:00 daily. After deployment, runs `DetectCMKStatus.ps1` automatically.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  BuildNCVMsWithCMK.ps1 Deployment                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Resource Group: sgall<5 random chars>                                  │
│                                                                          │
│   ┌──────────────────┐    ┌──────────────────────────────────────────┐  │
│   │  Key Vault (HSM)  │    │  Private VNet 10.0.0.0/16               │  │
│   │  N CMK Keys       │    │  ┌──────────────────────────────────┐   │  │
│   │  (10% expired)    │    │  │  Subnet 10.0.0.0/24              │   │  │
│   │                   │    │  │                                  │   │  │
│   │  key-01 ──► DES ──┼──▶ │  │  CVM-01  CVM-02  ...  CVM-N    │   │  │
│   │  key-02 ──► DES ──┼──▶ │  │                                  │   │  │
│   │  ...              │    │  │  No Public IPs                   │   │  │
│   │  key-N  ──► DES ──┼──▶ │  │  Boot Diagnostics Disabled       │   │  │
│   └──────────────────┘    │  │  Auto-Shutdown 19:00 Daily       │   │  │
│                            │  └──────────────────────────────────┘   │  │
│                            └──────────────────────────────────────────┘  │
│                                                                          │
│   Post-Deploy: DetectCMKStatus.ps1 ──▶ Color-coded key expiry report    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Usage

```powershell
./BuildNCVMsWithCMK.ps1 -subsID <YOUR SUBSCRIPTION ID> [-vmCount <NUMBER>] [-region <AZURE REGION>]
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-subsID` | Yes | — | Your Azure subscription ID |
| `-vmCount` | No | `10` | Number of Confidential VMs to create |
| `-region` | No | `northeurope` | Azure region for all resources |

The resource group is automatically named `sgall<5 random alphanumeric chars>` (e.g., `sgall7k2mx`).

### What It Creates

| Resource | Details |
|----------|--------|
| Resource Group | `sgall<5 chars>` in specified region |
| Key Vault | Premium SKU, HSM-backed, purge protection enabled |
| N CMK Keys | RSA-3072 with CVM release policy; 10% have expired expiry dates |
| N Disk Encryption Sets | One per VM, Confidential VM encrypted with customer key |
| VNet + Subnet | `10.0.0.0/16` with VM subnet `10.0.0.0/24` |
| N Confidential VMs | Ubuntu 24.04 LTS CVM on `Standard_DC2as_v5`, no public IP |
| Auto-Shutdown Schedules | 19:00 GMT Standard Time daily for each VM |

### Examples

```powershell
# Deploy 10 CVMs with CMK in North Europe (defaults)
./BuildNCVMsWithCMK.ps1 -subsID "your-subscription-id"

# Deploy 5 CVMs in East US
./BuildNCVMsWithCMK.ps1 -subsID "your-subscription-id" -vmCount 5 -region "eastus"

# Deploy 20 CVMs in West Europe
./BuildNCVMsWithCMK.ps1 -subsID "your-subscription-id" -vmCount 20 -region "westeurope"
```

---

## DetectCMKStatus.ps1

PowerShell function that scans all Key Vaults in a resource group, enumerates every key, and displays a color-coded status table. Expired keys are shown in **red**, keys expiring within 90 days in **orange**, and healthy keys in **green**.

### Usage

```powershell
# Dot-source the function
. .\DetectCMKStatus.ps1

# Display key status in console
Get-CMKStatus -ResourceGroupName "myResourceGroup"

# Display and export to CSV
Get-CMKStatus -ResourceGroupName "myResourceGroup" -Csv "C:\reports\cmk-report.csv"
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ResourceGroupName` | Yes | The Azure resource group to scan |
| `-Csv` | No | File path to export results as CSV |

### Output Columns

| Column | Description |
|--------|-------------|
| VaultName | Name of the Key Vault |
| KeyName | Name of the key |
| KeyType | Key type (e.g., RSA, RSA-HSM) |
| KeyOps | Permitted key operations |
| Version | Key version identifier |
| Enabled | Whether the key is enabled |
| Created | Key creation date |
| Expires | Key expiry date |
| Status | `OK`, `EXPIRING SOON` (within 90 days), `EXPIRED`, or `No Expiry Set` |

### Status Colors

| Status | Color | Condition |
|--------|-------|-----------|
| **EXPIRED** | Red | Current date is past the key expiry date |
| **EXPIRING SOON** | Orange | Key expires within the next 90 days |
| **OK** | Green | Key expiry is more than 90 days away |
| **No Expiry Set** | Green | Key has no expiry date configured |

### Example Workflow

```powershell
# Step 1: Create test keys
./BuildRandomCMK.ps1 -subsID "your-sub-id" -Prefix "cmktest"

# Step 2: Analyze the keys
. .\DetectCMKStatus.ps1
Get-CMKStatus -ResourceGroupName "cmktestabcde"

# Step 3: Export report
Get-CMKStatus -ResourceGroupName "cmktestabcde" -Csv ".\cmk-report.csv"
```

---

## DetectCMKRotation.ps1

Detects Customer Managed Key rotation for Confidential VMs. For each CVM in a resource group, it examines the Disk Encryption Set to determine which key and version is currently active, lists all historical versions, and reports when the key was last rotated. Keys that have never been rotated are flagged in **orange**.

### Usage

```powershell
# Check rotation status for all CVMs in a resource group
.\DetectCMKRotation.ps1 -ResourceGroupName "myResourceGroup"

# Check and export to CSV
.\DetectCMKRotation.ps1 -ResourceGroupName "myResourceGroup" -Csv "C:\reports\rotation-report.csv"
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ResourceGroupName` | Yes | The Azure resource group containing CVMs to scan |
| `-Csv` | No | File path to export results as CSV |

### Output Columns

| Column | Description |
|--------|-------------|
| VM Name | Name of the Confidential VM |
| Key Name | CMK key name in Key Vault |
| Active Version | Truncated version ID of the currently active key |
| Vault | Key Vault name |
| Last Rotated | Creation date of the active key version (i.e., when rotation last occurred) |
| Versions | Total number of key versions (1 = never rotated) |
| Status | `ROTATED (N versions)` in green or `NEVER ROTATED` in orange |

### Status Colors

| Status | Color | Condition |
|--------|-------|-----------|
| **ROTATED** | Green | Key has more than one version (rotation has occurred) |
| **NEVER ROTATED** | Orange | Key has only one version (original key still in use) |

---

## Prerequisites

- PowerShell 7.x or later
- Azure PowerShell module (`Install-Module Az -Force`)
- Authenticated Azure session (`Connect-AzAccount`)
- Sufficient permissions to create/read Key Vaults and keys in the target subscription

## Cleanup

```powershell
# Remove all resources created by BuildRandomCMK.ps1
Get-AzResourceGroup -Name "<resource-group-name>" | Remove-AzResourceGroup -Force
```
