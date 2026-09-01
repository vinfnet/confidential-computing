# Quick Start Guide — Citizen Registry Advanced

> **Cost awareness:** This deployment includes Azure Managed HSM, which has a higher cost even for light testing. Review the [cost estimates, optimization guidance, and live pricing links in the README](README.md#-important-managed-hsm-requirement--cost-warning) before proceeding. Azure prices can change and vary by region and configuration.

## 🚀 Getting Started

This guide walks you through deploying the citizen registry advanced app with managed HSM and mTLS on Azure Confidential Computing.

### Prerequisites

```powershell
# Ensure you have:
# - Azure CLI (az) — https://docs.microsoft.com/cli/azure/install-azure-cli
# - PowerShell 7+ — https://github.com/PowerShell/PowerShell
# - Bicep CLI — az bicep install
# - Git for version control

# Verify installations
az --version
$PSVersionTable.PSVersion
az bicep version

# Log in to Azure
az login
az account set --subscription "your-subscription-id"
```

### Step 1: Set Your Configuration

```powershell
# Define your deployment parameters
$Prefix = "sgall"           # 3-12 char identifier
$Location = "northeurope"   # Azure region validated by this sample
$Environment = "demo"       # Environment type

Write-Host "Deploying with:"
Write-Host "  Prefix: $Prefix"
Write-Host "  Location: $Location"
Write-Host "  Environment: $Environment"
```

### Step 2: Deploy Shared Infrastructure (5 min)

```powershell
cd .\citizen-registry-advanced

# Validate the deployment
.\Deploy-SharedInfra.ps1 -Prefix $Prefix -Location $Location -ValidateOnly

# If validation succeeds, deploy
.\Deploy-SharedInfra.ps1 -Prefix $Prefix -Location $Location -Deploy

# Managed HSM provisioning and security-domain activation can take several minutes.
# Output will show:
#   ✓ Resource group ready
#   ✓ Deployment completed successfully
```

**What this creates:**
- Resource group: `{prefix}sharedinfra`
- Managed HSM (B1 SKU)
- Local 2-of-3 recovery material under the ignored `shared-infra/security-domain/`
  directory. Protect and back up these files securely.
- Virtual Network with private subnets
- Private Link endpoint for HSM
- Private DNS zones

### Step 3: Deploy App Instance (5 min)

```powershell
# Deploy your first app instance
# Note: Replace "sgallsharedinfra" with your actual shared RG name

.\Deploy-AppInstance.ps1 `
  -Prefix $Prefix `
  -Location $Location `
  -SharedInfraRg "${Prefix}sharedinfra" `
  -Deploy

# Output will show:
#   ✓ App instance resource group ready
#   ✓ Deployment completed successfully
#   Resource Group: sgall12345app (with random 5-digit suffix)
```

**What this creates:**
- Resource group: `{prefix}{random5digit}app`
- App Confidential VM (C-vn2 with SEV-SNP)
- SQL Server Confidential VM on the same private app subnet
- Private app-to-database connection on TCP 1433
- SQL Server database `citizendb` seeded with 100 fictional government-style citizen records
- Bastion host (for secure access)
- Azure Attestation Service
- Private Link to shared Managed HSM

### Step 4: Access the Web Application

```powershell
$appRg = "sgall12345app"  # Your app instance RG
$bastionName = "sgall-12345-bastion"
$cvmId = az vm show -g $appRg -n sgall-citizen-cvm --query id -o tsv

# Keep this terminal open while using the web interface.
az network bastion tunnel `
  -g $appRg `
  -n $bastionName `
  --target-resource-id $cvmId `
  --resource-port 443 `
  --port 8443
```

Open `https://localhost:8443/`. The registry is readable without a client certificate.
Add, Edit, and Delete require the Norland demo mTLS client certificate.

### Step 5: Enable Browser CRUD Access

A web page cannot install a client certificate safely. Install the demo client identity through
a temporary Bastion SSH tunnel by following
[README Step 4: Install the Demo Client Certificate on Windows](README.md#step-4-install-the-demo-client-certificate-on-windows).

In summary:

1. Open a Bastion tunnel from local port `2222` to app CVM port `22`.
2. Package the client certificate and key as a temporary mode-`600` PFX in the CVM.
3. Transfer the PFX and public Norland demo CA directly through the SSH tunnel.
4. Import the PFX into `Cert:\CurrentUser\My` and explicitly trust the fictional demo CA in
   `Cert:\CurrentUser\Root`.
5. Delete both transfer copies, close all browser windows, and reopen the browser.
6. Select `citizen-registry-demo-client` if the browser asks for a certificate.

Do not expose the PFX through a web download or commit it to the repository.

### Step 6: Use the Registry UI

- **Add citizen** remains visible in the sticky toolbar while scrolling.
- **Edit** and **Delete** remain visible in the sticky right-hand Actions column.
- The table contains 100 deterministic, entirely fictional records.
- Fields include national ID, date of birth, street address, town, state, socio-economic group,
  and tax paid last year.
- The expanded table scrolls horizontally on narrow screens.

CRUD calls are protected by mTLS. Without the demo client certificate, the API returns HTTP
`401` and the interface reports that a valid certificate is required.

### Step 7: Verify Health and Security Evidence

```powershell
# Run inside the app CVM through a Bastion SSH session.
curl -sk https://localhost/health | jq .
curl -sk https://localhost/db/status | jq .
curl -sk https://localhost/config | jq '.environment'
curl -sk https://localhost/security/evidence | jq .

# From the deployment workstation, verify the confidential Disk Encryption Set.
az disk-encryption-set show `
  --resource-group <app-resource-group> `
  --name <disk-encryption-set-name> `
  --query '{id:id,encryptionType:encryptionType,identity:identity.principalId}'
```

Expected results include health status `healthy`, database record count `100`, CMK evidence
status `retrieved`, key type `RSA-HSM`, the decoded Secure Key Release policy, and the Managed
HSM hostname resolving privately to `10.10.1.x`.

## 🏗️ Architecture Components

### Shared Infrastructure RG

| Component | Purpose | Security |
|-----------|---------|----------|
| **Managed HSM** | Key management for disk encryption | Private Link only, no public IP |
| **Virtual Network** | Networking backbone | Private subnets, no public routing |
| **Private DNS Zone** | mHSM hostname resolution | Private DNS only |

### App Instance RG

| Component | Purpose | Security |
|-----------|---------|----------|
| **Confidential VM** | Application runtime (C-vn2 TEE) | SEV-SNP/vTPM, HSM CMK via DES, attestation-bound secure release |
| **Database on ACC** | Data persistence | Private subnet, TDE enabled |
| **Bastion Host** | Secure admin access | No public IPs on resources |
| **Attestation Service** | Provider metadata and guest-attestation integration | Metadata health is separate from CVM boot attestation |

## 📊 Cost Estimate

| Component | SKU | Monthly Cost (approx) |
|-----------|-----|----------------------|
| **Managed HSM** | B1 | $400 |
| **App Confidential VM** | DC2as_v5 (2 vCPU) | $220 |
| **SQL Confidential VM** | DC2as_v5 (2 vCPU) | $220 |
| **Bastion** | Standard (2 scale units) | $50 |
| **Attestation** | Per-request | $5-10 |
| **Storage** | Premium LRS disks | $30 |
| **Total** | | ~$940/month |

**To reduce costs:**
- Use a smaller supported CVM SKU where available
- Reduce Bastion scale units
- Delete app instances when not in use (keep shared infrastructure)

## 🧹 Cleanup

```powershell
# Delete specific app instance
.\Deploy-AppInstance.ps1 -Prefix "sgall" -Cleanup

# Delete shared infrastructure (and all app instances)
.\Deploy-SharedInfra.ps1 -Prefix "sgall" -Cleanup

# Verify deletion
az group list --query "[?contains(name, 'sgall')].name" -o table
```

## 🐛 Troubleshooting

### Managed HSM Creation Fails

```
Error: "Not Authorized to perform action"
```

**Solution:** Ensure cost control tag is applied:
```powershell
az tag create --resource-id <hsm-resource-id> `
  --tags costCenter=confidential-computing
```

### CVM Fails to Boot

```
Error: "OS disk encryption failed"
```

**Solution:** Verify Managed HSM key permissions:
```powershell
# Inspect the key-scoped Managed HSM local role assignments.
az keyvault role assignment list `
  --hsm-name <shared-hsm-name> `
  --scope /keys/<os-disk-key-name> `
  --output table
```

The Disk Encryption Set requires `Managed HSM Crypto Service Encryption User`; Azure CVM
Orchestrator requires `Managed HSM Crypto Service Release User`. The app identity receives
`Managed HSM Crypto Auditor` only to display CMK and release-policy evidence.

### Bastion Connection Timeout

**Solution:** Check NSG rules:
```powershell
az network nsg rule list `
  --nsg-name <app-nsg-name> `
  --resource-group <app-resource-group> `
  --query "[?destinationPortRange=='22' || destinationPortRange=='443']"
```

Ensure rule allows inbound from Bastion subnet (`10.0.2.0/24`).

### mTLS Certificate Issues

The Norland demo CA, server certificate, and client certificate are generated by the app
CVM cloud-init bootstrap. Check the generated files and restart nginx after replacing them:

```powershell
az vm run-command invoke -g <app-resource-group> -n <app-cvm-name> `
  --command-id RunShellScript `
  --scripts "ls -l /etc/citizen-registry/certs; nginx -t; systemctl restart nginx"
```

For browser CRUD access, confirm `citizen-registry-demo-client` exists with a private key in
`Cert:\CurrentUser\My`, trust the fictional Norland demo CA in `Cert:\CurrentUser\Root`, then
fully restart the browser. See [README Step 4](README.md#step-4-install-the-demo-client-certificate-on-windows).

## 📚 Next Steps

1. **Review Architecture:** Read [README.md](README.md) for topology details
2. **Explore Scripts:** Check `scripts/` for automation helpers
3. **Customize App:** Modify `app-instance/app-src/app.py` for your use case
4. **Enable Logging:** Configure Azure Monitor for app telemetry
5. **Setup CI/CD:** Integrate with GitHub Actions for automated deployments

## 🔐 Security Best Practices

✅ **Do:**
- Keep private keys (.key files) in `.gitignore` — never commit
- Use Managed Identity for app authentication
- Enable Bastion for all admin access
- Regularly rotate certificates
- Monitor attestation logs

❌ **Don't:**
- Expose HSM public IP (private link only)
- Store secrets in code or config files
- Use default database credentials
- Disable Confidential OS disk encryption
- Skip mTLS certificate validation

---

For more help, see [README.md](README.md) or check Azure Confidential Computing docs.
