# Azure DevOps Server on a Confidential VM, with Confidential ACI build agents

Stand up a private **Azure DevOps (ADO) Server** on a **Confidential VM (CVM)**, reachable
only over a private VNet through Azure Bastion, plus **confidential Azure Container Instances
(ACI) build agents** that self-register to it over that private network.

Both the server *and* the build agents run inside AMD SEV-SNP confidential hardware, and no
component is exposed to the public internet.

## Why this pattern matters

Azure already encrypts data at rest and in transit, and Azure Confidential Computing (ACC)
helps protect **data in use** by processing it inside a hardware-based, attested Trusted
Execution Environment (TEE). On a Confidential VM or confidential container this protection is
**transparent to the software running inside** — the application doesn't need to be
"ACC-aware" to benefit. The real gap is on the platform side: **not every Azure PaaS and SaaS
service offers a confidential option yet.** So if the managed service you'd normally reach for
doesn't have an ACC-backed tier, you can be left without a way to help protect that workload's
data while it's in use.

This example shows a **lift-and-shift pattern** for closing that gap. Instead of waiting for a
managed service to add confidential support, you host the unmodified application yourself on a
**Confidential VM** and run its workloads on **confidential containers**, wrapping it in ACC
hardware protections. The result is **end-to-end confidentiality** — the customer owns the
confidentiality of their **data, code, and applications**. When ACC is enabled and properly
configured with customer-managed keys and verification policies, it is designed to help
prevent unauthorized access to data in use, including from the cloud operator.

**When to use this pattern**

- The Azure PaaS/SaaS service you'd use doesn't (yet) offer a confidential option.
- You want full ownership and control of the confidentiality boundary end-to-end.
- Regulatory or contractual obligations call for data to stay protected even while in use.

> ACC provides *even more robust* protection for data in use; it is not a replacement for
> Azure's existing security. Its confidentiality guarantees depend on the customer correctly
> configuring customer-managed keys and attestation/verification policies. ACC is not
> available in all geographies and does not apply to every workload (for example, it does not
> apply to Microsoft 365 or Dynamics 365).

**The trade-off.** With a managed PaaS/SaaS service, confidentiality (where available),
patching, and upgrades "just happen." This self-hosted pattern hands that responsibility back
to you: you are responsible for maintaining, patching, updating, and upgrading the VM, the
application, the container images, and the attestation configuration over time. You gain ACC
coverage for workloads that would otherwise have none — in exchange for the operational
overhead of running it yourself.

## Architecture

```
        Your workstation
              │  (Azure CLI + Bastion tunnel — no public IP on the server)
              ▼
   ┌───────────────────────────────────────────────┐
   │  VNet  <name>vnet  (10.0.0.0/16)               │
   │                                                │
   │   AzureBastionSubnet ── Bastion (Standard)     │
   │                                                │
   │   default subnet                               │
   │     └─ ADO Server CVM  (10.0.0.4, no PIP)      │
   │          IIS "Azure DevOps Server", HTTPS 443  │
   │                                                │
   │   aci-agents-subnet (10.0.1.0/24, delegated)   │
   │     ├─ Confidential ACI agent 1 ──┐            │
   │     └─ Confidential ACI agent 2 ──┤ self-      │
   │                                   │ register   │
   │            NAT gateway (egress) ──┘ via HTTPS  │
   └───────────────────────────────────────────────┘
```

## Prerequisites

- **Azure CLI** signed in to the target subscription:
  ```powershell
  az login
  az account set --subscription <subscription-id>
  ```
- **Bastion CLI extension** (for native RDP/tunnel over Bastion):
  ```powershell
  az extension add --name bastion
  ```
- **Docker** running locally (used to build and push the agent image to ACR).
- The **Azure DevOps Server installer** `.exe` (you supply this — for example
  `mul_azure_devops_server_x64_web_installer_1758aa41.exe`).
- Quota for the confidential VM size (default `Standard_DC8as_v5`) in your region.

Throughout this guide, replace the placeholders:

| Placeholder | Meaning | Reference example |
| --- | --- | --- |
| `<subscription-id>` | Azure subscription GUID | `00000000-0000-0000-0000-000000000000` |
| `<name>` | Base name for the CVM / resource group | `myado` |
| `<resource-group>` | Resource group (equals `<name>`) | `MYADO` |
| `<vm-name>` | VM name (equals `<name>`) | `myado` |
| `<vnet-name>` | VNet name (`<name>vnet`) | `myadovnet` |
| `<acr-name>` | Azure Container Registry name | `myadoacr` |
| `<your-pat>` | ADO personal access token | — |

---

## End-to-end installation

### Step 1 — Deploy the Confidential VM and network

Creates the resource group, the CVM (no public IP), the VNet with the delegated
`aci-agents-subnet` and a NAT gateway for egress, and a **Standard-SKU Bastion** with
native-client tunneling enabled.

```powershell
cd usecase-ado-server-iaas
.\Build-AdoServerCvm.ps1 `
  -subsID <subscription-id> `
  -basename <name> `
  -region northeurope `
  -vmsize Standard_DC8as_v5
```

The script prints the resource group, VM name, and Bastion name at the end. By convention:

- Resource group / VM name: `<name>` (e.g. `myado`)
- VNet: `<name>vnet` (e.g. `myadovnet`)
- Bastion: `<name>vnet-bastion` (e.g. `myadovnet-bastion`)
- Private IP of the CVM: `10.0.0.4`

### Step 2 — Connect to the CVM over Bastion (RDP)

The CVM has **no public IP**, so open its Windows desktop through Bastion. Capture the VM
resource ID once, then start the RDP session:

```powershell
$vmId = az vm show -g <resource-group> -n <vm-name> --query id -o tsv
az network bastion rdp `
  --name <vnet-name>-bastion `
  --resource-group <resource-group> `
  --target-resource-id $vmId
```

See [Connecting via Bastion](#connecting-via-bastion) for the browser/tunnel alternative.

### Step 3 — Install Azure DevOps Server manually (simplest path)

Do this **inside the RDP session** on the CVM. This is the plain, GUI-driven install using
SQL Server Express, default options, and **no Search** (Search needs a separate Elasticsearch
component and is not required for build agents).

1. **Copy the installer onto the VM.** Drag the ADO Server `.exe` through the RDP session (or
   paste via the RDP clipboard) into `C:\Install\`.

2. **Run the installer.** Double-click the `.exe`, accept the license terms, and click
   **Install**. This lays down the product bits and then launches the **Server Configuration
   Wizard**. (If the wizard does not start automatically, open a Start-menu search for
   *Azure DevOps Server Administration Console* and choose **Configure Installed Features →
   Configure**.)

3. **Choose the configuration type.** Select **Basic** (or **New deployment → Basic**). Basic
   is the simplest topology: it configures the app tier plus a local database and skips
   reporting and advanced options.

4. **Database — use SQL Server Express.** When prompted for the SQL Server instance, choose
   the option to **install SQL Server Express** (the wizard offers to download/install it
   automatically). Leave the instance name at the default. Do **not** point at an external SQL
   Server for this demo.

5. **Do NOT enable Search.** On the Search step, **uncheck / skip "Configure Search"** (also
   called *Code Search* / *Elasticsearch*). It is optional and unnecessary for running build
   agents.

6. **Accept all remaining defaults.** Keep the default:
   - Project collection name: **`DefaultCollection`**
   - Service account: **`NT AUTHORITY\NETWORK SERVICE`**
   - Website / IIS binding: default **HTTP on port 80** (site name **"Azure DevOps Server"**)
   - Application tier public URL: leave as generated

7. **Run readiness checks and configure.** Click **Verify**, then **Configure**. When it
   finishes, the console shows the collection URL, e.g. `http://<vm-name>/DefaultCollection`.

8. **Confirm it is up.** In the VM's browser, open `http://localhost/DefaultCollection` — you
   should see the Azure DevOps web UI.

> The install runs entirely on the VM over its default HTTP binding. HTTPS is added in the
> next step because the build agents refuse PAT auth over plain HTTP.

### Step 4 — Enable HTTPS on the ADO Server

The build agents authenticate with a PAT, and the agent **refuses PAT/Basic auth over plain
HTTP** — so HTTPS is required. Run this **from your workstation** (it executes on the VM as
SYSTEM via run-command); it creates a self-signed certificate (CN=`10.0.0.4`), binds 443, and
opens the firewall:

```powershell
az vm run-command invoke -g <resource-group> -n <vm-name> `
  --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/enable-ado-https.ps1"
```

### Step 5 — Create a Personal Access Token (PAT)

Open a Bastion tunnel to the ADO web UI, then create a PAT with **Agent Pools (read,
manage)** scope:

```powershell
az network bastion tunnel `
  --name <vnet-name>-bastion `
  --resource-group <resource-group> `
  --target-resource-id $vmId `
  --resource-port 443 `
  --port 8443
```

Leave that terminal open and browse to `https://localhost:8443/DefaultCollection` (accept the
self-signed certificate warning). Go to **User settings → Personal access tokens → New
Token**, grant **Agent Pools (read, manage)**, and copy the token. Store it in the current
shell (do **not** commit it):

```powershell
$env:AZP_TOKEN = '<your-pat>'
```

### Step 6 — Create the confidential build agent pool

Create the `confidential-build-pool` on the server (runs on the VM against `localhost`):

```powershell
az vm run-command invoke -g <resource-group> -n <vm-name> `
  --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/create-ado-pool.ps1" `
  --parameters "Pool=confidential-build-pool" "Pat=$env:AZP_TOKEN" `
  --query "value[0].message" -o tsv
```

Note the pool `id` from the output (`POOL-CREATED` / `POOL-EXISTS` — typically `id=2`); you
use it to verify agents in Step 8.

### Step 7 — Build and deploy the confidential ACI agents

Builds the agent container image, pushes it to ACR, and deploys the confidential ACI agents
into `aci-agents-subnet`. They self-register to the pool over the private VNet. The PAT is
read from `$env:AZP_TOKEN`:

```powershell
.\Build-ConfidentialAciAdoAgent.ps1 `
  -SubscriptionId <subscription-id> `
  -ResourceGroupName <resource-group> `
  -Prefix <name> `
  -AzpUrl 'https://10.0.0.4/DefaultCollection' `
  -AzpPool 'confidential-build-pool' `
  -AcrName <acr-name> `
  -AgentCount 2 `
  -VnetName '<vnet-name>' `
  -AgentSubnetName 'aci-agents-subnet'
```

### Step 8 — Verify the agents registered

```powershell
az vm run-command invoke -g <resource-group> -n <vm-name> `
  --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/check-ado-agents.ps1" `
  --parameters "PoolId=2" "Pat=$env:AZP_TOKEN" `
  --query "value[0].message" -o tsv
```

You should see `AGENT-COUNT 2` with each agent `status=online`. The platform is now ready:
queue a pipeline against `confidential-build-pool` and it runs on a confidential agent.

---

## Connecting via Bastion

The CVM has **no public IP**. All access goes through Azure Bastion (Standard SKU with
`--enable-tunneling` and `--enable-ip-connect`), so you connect from your workstation
without exposing the server to the internet. Capture the VM resource ID once for reuse:

```powershell
$vmId = az vm show -g <resource-group> -n <vm-name> --query id -o tsv
```

### Option A — Full desktop (RDP)

Opens the Windows desktop of the CVM through Bastion using your local RDP client. Use
this to run the installer, manage IIS, or use the ADO web UI from inside the box.

```powershell
az network bastion rdp `
  --name <vnet-name>-bastion `
  --resource-group <resource-group> `
  --target-resource-id $vmId
```

> Native RDP over Bastion is Windows-only and requires the Standard Bastion SKU (already
> configured by `Build-AdoServerCvm.ps1`).

### Option B — Reach the ADO web UI / REST API from your browser (tunnel)

Forwards a local port to the CVM's HTTPS port through Bastion, so you can browse the
Azure DevOps collection or call its REST API from your workstation — no desktop needed.

```powershell
az network bastion tunnel `
  --name <vnet-name>-bastion `
  --resource-group <resource-group> `
  --target-resource-id $vmId `
  --resource-port 443 `
  --port 8443
```

Leave that terminal open, then in a browser go to:

```
https://localhost:8443/DefaultCollection
```

The ADO Server uses a self-signed certificate, so your browser will warn about the
certificate — that is expected; proceed past the warning. To tunnel plain HTTP instead,
use `--resource-port 80` and browse `http://localhost:8443/DefaultCollection`.

---

## Repository layout

### Core scripts (run these directly, in order)

| Script | Where it runs | Purpose |
| --- | --- | --- |
| `Build-AdoServerCvm.ps1` | Workstation | Deploy the CVM, VNet, subnets, NAT gateway, and Standard Bastion (Step 1). |
| `enable-ado-https.ps1` | On the CVM (via run-command) | Create self-signed cert, bind 443, open firewall (Step 4). |
| `create-ado-pool.ps1` | On the CVM (via run-command) | Create the confidential build agent pool (Step 6). |
| `Build-ConfidentialAciAdoAgent.ps1` | Workstation | Build/push the agent image and deploy confidential ACI agents (Step 7). |
| `check-ado-agents.ps1` | On the CVM (via run-command) | List agents registered in a pool to verify registration (Step 8). |

> Installing Azure DevOps Server itself is a **manual** step (Step 3) — see
> [Step 3 — Install Azure DevOps Server manually](#step-3--install-azure-devops-server-manually-simplest-path).

### `helper-scripts/` (diagnostics, cleanup, and superseded automation)

These are **not** part of the main flow — they are troubleshooting/maintenance aids and the
earlier (unreliable) install-automation attempts kept for reference. Most run on the CVM via
`az vm run-command invoke --scripts "@usecase-ado-server-iaas/helper-scripts/<name>"`.

| Script | Purpose |
| --- | --- |
| `Install-AdoServerOneShot.ps1` | Original unattended ADO Server installer (SQL Express, HTTP). Superseded by the manual install in Step 3; kept for reference. |
| `Run-Install-AdoServerOneShot.ps1` | Convenience wrapper that calls `Install-AdoServerOneShot.ps1` with defaults. |
| `discover-ado.ps1` | Probe local ADO endpoints, project collections, and TFS registry config on the CVM. |
| `list-iis-sites.ps1` | List IIS sites and bindings on the CVM (confirm the "Azure DevOps Server" site). |
| `diag-cvm-network.ps1` | Check port 80/443 listeners, firewall rules, and local HTTP reachability on the CVM. |
| `check-agent-package.ps1` | Verify the build-agent package download/URL is reachable from the server. |
| `remove-stale-agents-v2.ps1` | Remove agents from a pool by name pattern (current cleanup helper). |
| `remove-stale-agents.ps1` | Earlier version of the cleanup helper (has a URI-parse bug; superseded by v2). |
| `agent-test.template.yaml` | Throwaway ACI template used to reproduce/debug agent registration issues. |
| `net-test.yaml` | Throwaway ACI template for testing VNet/network connectivity from a container. |

---

## Cleanup

Delete the whole deployment by removing its resource group:

```powershell
az group delete --name <resource-group> --yes --no-wait
```

To remove only the agents (keep the server), use the cleanup helper:

```powershell
az vm run-command invoke -g <resource-group> -n <vm-name> `
  --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/helper-scripts/remove-stale-agents-v2.ps1" `
  --parameters "PoolId=2" "NamePattern=<name>-agent" "Pat=$env:AZP_TOKEN" `
  --query "value[0].message" -o tsv
```