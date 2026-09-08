# Sovereign Examples

This directory contains example scripts and configurations for deploying Azure Confidential Computing
resources in scenarios that require heightened data sovereignty, compliance, or backup/recovery controls.

## Latest Additions

The [Citizen Registry Advanced](citizen-registry-advanced/README.md) sample is the latest end-to-end
sovereign application demonstration. It combines an AMD SEV-SNP app Confidential VM, an NVIDIA H100
in production confidential-computing mode, a separate SQL Confidential VM, and a customer-controlled
Managed HSM.

- [Citizen registry experience](citizen-registry-advanced/README.md#citizen-registry-data-and-crud-ui) - fictional records, representative synthetic portraits, and mTLS-protected CRUD operations.
- [Confidential CCTV comparison](citizen-registry-advanced/README.md#confidential-cctv-face-anonymization) - finite source and H100-anonymized video, synchronized pause, timestamps, progress, and processing lag.
- [Security boundary and deployed evidence](citizen-registry-advanced/README.md#security-boundary-and-deployed-evidence) - precise CPU, GPU, browser, TLS, attestation, and Managed HSM trust boundaries.
- [Architecture](citizen-registry-advanced/ARCHITECTURE.md) - two-region private topology, global VNet peering, encryption layers, and scaling constraints.
- [Quick start](citizen-registry-advanced/QUICKSTART.md) - deployment, access, expected application views, and cleanup.
- [Verification and security validation](citizen-registry-advanced/README.md#verification--security-validation) - checks for infrastructure, attestation, services, and application behavior.
- [Cost warning and controls](citizen-registry-advanced/README.md#cost-warning-and-controls) - current H100 and Managed HSM planning rates, auto-shutdown, deallocation, and teardown guidance.

> [!WARNING]
> Review the advanced sample's cost guidance before deployment. Its H100 app CVM and Managed HSM
> alone are approximately $12.10/hour at the documented September 2026 West Europe USD retail rates;
> SQL Server, Bastion, storage, networking, and monitoring are additional.

## Available Examples

| Folder | Description |
|--------|-------------|
| [`citizen-registry-advanced/`](citizen-registry-advanced/README.md) **Latest** | Two-stage confidential citizen registry and CCTV demo: H100 app CVM, separate SQL CVM, Managed HSM-backed app OS-disk key, private networking, attestation evidence, TLS/mTLS, synthetic portraits, and confidential face anonymization. |
| [`citizen-registry-app/`](citizen-registry-app/README.md) | Confidential ACI citizen registry behind Application Gateway with a private SQL Server Confidential VM, container security policy, Secure Key Release sidecar, and API-based data seeding. |
| [`cvm-backup/`](../cvm-backup/README.md) | Deploy a Windows Confidential VM (CVM) with Azure Backup (Recovery Services Vault) and Customer Managed Key disk encryption |

## Choose an Example

| Goal | Start here |
|------|------------|
| Demonstrate confidential GPU inference, CCTV anonymization, Managed HSM, and mTLS | [Citizen Registry Advanced](citizen-registry-advanced/README.md) |
| Demonstrate a confidential container application with a public gateway and private backend | [Confidential ACI Citizen Registry](citizen-registry-app/README.md) |
| Protect and recover a Windows Confidential VM | [Confidential VM Backup](../cvm-backup/README.md) |

Each sample documents its own trust boundary. Do not assume that a control used by one sample, such
as Managed HSM, Azure Key Vault Premium, Confidential ACI, an H100 GPU, or Bastion, applies to every
example in this directory.

## Prerequisites

- An Azure subscription with access and quota for the selected sample's regions and confidential-compute SKUs.
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) and PowerShell 7 for the citizen registry samples.
- Docker Desktop and the Azure CLI `confcom` extension for the Confidential ACI sample.
- Review the selected sample's README and cost guidance before provisioning resources.
