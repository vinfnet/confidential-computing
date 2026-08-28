# Quick Start Guide — Citizen Registry Advanced

> **Cost awareness:** This deployment includes Azure Managed HSM, which has a higher cost even for light testing. Review the [cost estimates, optimization guidance, and live pricing links in the README](README.md#-important-managed-hsm-requirement--cost-warning) before proceeding. Azure prices can change and vary by region and configuration.

## 🚀 Getting Started in 10 Minutes

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
$Location = "eastus"        # Azure region
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

# Wait for Managed HSM to be provisioned (~2-3 minutes)
# Output will show:
#   ✓ Resource group ready
#   ✓ Deployment completed successfully
```

**What this creates:**
- Resource group: `{prefix}sharedinfra`
- Managed HSM (B1 SKU)
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
- SQL Server database `citizendb` seeded with three demo citizens
- Bastion host (for secure access)
- Azure Attestation Service
- Private Link to shared Managed HSM

### Step 4: Access the Application

#### Option A: Using Azure Portal Bastion

```
1. Go to https://portal.azure.com
2. Navigate to: Resource Groups > {your-app-rg} > {cvm-name}
3. Click "Connect" > "Bastion"
4. Login with SSH (key-based) or RDP
5. From the CVM: curl https://localhost:8443/health
```

#### Option B: Using Azure CLI

```powershell
$appRg = "sgall12345app"  # Your app instance RG
$bastionName = "sgall-12345-bastion"
$cvmId = az vm show -g $appRg -n sgall-citizen-cvm --query id -o tsv

# Create SSH tunnel through Bastion
az network bastion tunnel `
  -g $appRg `
  -n $bastionName `
  --resource-id $cvmId `
  --resource-port 22 `
  --port 2222

# In another terminal:
ssh -i ~/.ssh/id_rsa -p 2222 azureuser@localhost
```

### Step 5: Verify mTLS + Attestation

```powershell
# From within the CVM (via Bastion):

# Check health
curl -v -k https://localhost/health

# View app logs
tail -f /var/log/citizen-registry/app.log

# Check database connectivity
curl -s https://localhost/db/status | jq .

# View attestation status
curl -s https://localhost/config | jq '.environment'
```

### Step 6: Test Data Access

```powershell
# Get list of all citizens (mTLS required)
curl -k --cert citizen.crt --key citizen.key \
  https://localhost:8443/api/citizens | jq .

# Get specific citizen
curl -k --cert citizen.crt --key citizen.key \
  https://localhost:8443/api/citizen/1 | jq .

# Create new citizen
curl -X POST -k --cert citizen.crt --key citizen.key \
  -H "Content-Type: application/json" \
  -d '{
    "national_id": "CC-2024-006",
    "first_name": "Alice",
    "last_name": "Johnson",
    "date_of_birth": "1995-06-15",
    "region": "Northern",
    "municipality": "Harbor"
  }' \
  https://localhost:8443/api/citizen
```

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
| **Confidential VM** | Application runtime (C-vn2 TEE) | SEV-SNP, OS disk encryption |
| **Database on ACC** | Data persistence | Private subnet, TDE enabled |
| **Bastion Host** | Secure admin access | No public IPs on resources |
| **Attestation Service** | mTLS certificate validation | Attestation-backed verification |

## 📊 Cost Estimate

| Component | SKU | Monthly Cost (approx) |
|-----------|-----|----------------------|
| **Managed HSM** | B1 | $400 |
| **Confidential VM** | DC2as_v6 (2 vCPU) | $220 |
| **Database** | 10 GB SQL Server | $80 |
| **Bastion** | Standard (2 scale units) | $50 |
| **Attestation** | Per-request | $5-10 |
| **Storage** | Premium LRS disks | $30 |
| **Total** | | ~$800/month |

**To reduce costs:**
- Use smaller CVM SKU (DC1as_v6)
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
az tag create --resource-id {hsmId} \
  --tags costCenter=confidential-computing
```

### CVM Fails to Boot

```
Error: "OS disk encryption failed"
```

**Solution:** Verify Managed HSM key permissions:
```powershell
# Grant CVM managed identity permissions on HSM
az role assignment create \
  --role "Managed HSM Crypto User" \
  --assignee-object-id {cvmIdentityId} \
  --scope {hsmId}
```

### Bastion Connection Timeout

**Solution:** Check NSG rules:
```powershell
az network nsg rule list \
  --nsg-name sgall-app-nsg \
  -g sgall12345app \
  --query "[?destinationPortRange=='22' || destinationPortRange=='3389']"
```

Ensure rule allows inbound from Bastion subnet (`10.0.2.0/24`).

### mTLS Certificate Issues

**Solution:** Regenerate certificates:
```powershell
.\scripts\configure-mtls.ps1 `
  -CvmName "sgall-citizen-cvm" `
  -AttestationEndpoint "https://sgallattest123.eus.attest.azure.net"
```

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
