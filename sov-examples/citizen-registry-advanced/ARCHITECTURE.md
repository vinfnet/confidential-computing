# Technical Architecture — Citizen Registry Advanced

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CITIZEN REGISTRY ADVANCED                       │
│              Two-Stage Confidential Computing Deployment                 │
└─────────────────────────────────────────────────────────────────────────┘

Stage 1: SHARED INFRASTRUCTURE RG                Stage 2: APP INSTANCE RG
┌───────────────────────────────────────┐      ┌──────────────────────────┐
│  {prefix}sharedinfra                  │      │  {prefix}{5-digit}app    │
│                                       │      │                          │
│  ┌─────────────────────────────────┐  │      │  ┌────────────────────┐  │
│  │   MANAGED HSM (Private Link)    │  │      │  │  CONFIDENTIAL VM   │  │
│  │   - B1 SKU                      │  │      │  │  (C-vn2 / SEV-SNP) │  │
│  │   - AMD-backed HSM              │  │      │  │  - DC2as_v6 (2CPU) │  │
│  │   - Private endpoint only       │  │      │  │  - OS disk enc.    │  │
│  │   - No public IP                │  │      │  │  - Managed ID      │  │
│  │   - Key management              │  │      │  │  - Private IP only │  │
│  └─────────────────────────────────┘  │      │  └────────────────────┘  │
│          ▲                             │      │          ▲               │
│          │                             │      │          │               │
│  ┌─────────────────────────────────┐  │      │  ┌────────────────────┐  │
│  │  VIRTUAL NETWORK                │  │      │  │  DATABASE on ACC   │  │
│  │  - 10.0.0.0/16                  │  │      │  │  - SQL Server      │  │
│  │  - Subnets:                     │  │      │  │  - TDE enabled     │  │
│  │    • Private Link (10.0.1.0/24) │  │      │  │  - Private subnet  │  │
│  │    • Bastion (10.0.2.0/24)      │  │      │  │  - Port 1433 only  │  │
│  │    • App (10.0.3.0/24)          │  │      │  │                    │  │
│  │    • DB (10.0.4.0/24)           │  │      │  └────────────────────┘  │
│  │  - NSGs with strict rules       │  │      │                          │
│  │  - Private DNS zone             │  │      │  ┌────────────────────┐  │
│  │    (mhsm.azure.net)             │  │      │  │  BASTION HOST      │  │
│  └─────────────────────────────────┘  │      │  │  - Standard SKU    │  │
│                                       │      │  │  - Public IP only  │  │
│                                       │      │  │  - SSH/RDP tunnel  │  │
│                                       │      │  └────────────────────┘  │
│  ┌─────────────────────────────────┐  │      │                          │
│  │  PRIVATE LINK ENDPOINT          │  │      │  ┌────────────────────┐  │
│  │  - HSM connection               │  │      │  │  ATTESTATION SRVC  │  │
│  │  - Cross-RG peering ready       │  │      │  │  - mTLS validation │  │
│  └─────────────────────────────────┘  │      │  │  - Policy engine   │  │
│                                       │      │  │  - AAD trust model │  │
└───────────────────────────────────────┘      │  └────────────────────┘  │
         │                                     └──────────────────────────┘
         │                                              │
         └──────────────────┬───────────────────────────┘
                            │
                   PRIVATE LINK ENCRYPTED
                   TLS 1.2/1.3 (mTLS)
                      VNet Peering
```

## Data Flow & Security

### 1. User → App Connection (mTLS)

```
User Machine
    │
    ├─ SSH via Bastion
    │  └─ Port 2222 → Bastion → Port 22 (CVM)
    │
    └─ HTTPS via Bastion  
       └─ Port 8443 (mTLS)
          └─ Client cert required
             └─ Azure Attestation validates

         ↓↓↓ (Mutual TLS Handshake) ↓↓↓

    User Cert (issued by Attestation)
         │
    CVM Certificate (SEV-SNP attested)
         │
    ↓ TLS 1.3 ↓
    
Confidential VM (C-vn2)
    ├─ nginx (reverse proxy)
    │  ├─ mTLS termination
    │  ├─ Security headers
    │  └─ Request forwarding
    │
    ├─ Flask App (port 8000)
    │  ├─ Database driver
    │  ├─ Attestation client
    │  └─ HSM key release
    │
    └─ Guestagent (OS)
       └─ SEV-SNP measurement
```

### 2. App → Database (Private Link + TLS)

```
Flask App (8000)
    │
    ├─ SQL Connection String
    │  ├─ Server: 10.0.4.5 (private IP)
    │  ├─ Port: 1433
    │  ├─ Encrypt: yes
    │  ├─ TrustServerCertificate: yes
    │  └─ Database: citizendb
    │
    ↓ (pyodbc with ODBC Driver 18)
    
Private Network
    ├─ App subnet (10.0.3.0/24) → DB subnet (10.0.4.0/24)
    ├─ NSG rule: Allow TCP 1433 from app subnet
    ├─ All traffic encrypted (TLS)
    └─ No internet exposure
    
Database on ACC
    ├─ SQL Server
    ├─ TDE (Transparent Data Encryption)
    ├─ citizen_registry table
    └─ Private subnet only
```

### 3. App → Managed HSM (Private Link + mTLS)

```
Flask App
    │
    ├─ Azure Identity SDK
    │  └─ Managed Identity credential
    │
    ├─ Key Vault Python SDK
    │  └─ HSM endpoint: https://mhsm.azure.net
    │
    ↓ (DNS resolution via Private DNS Zone)
    
Private DNS Zone (mhsm.azure.net)
    └─ A record → 10.0.1.x (HSM private endpoint IP)

Private Link Endpoint
    ├─ VNet: 10.0.0.0/16
    ├─ Subnet: 10.0.1.0/24
    └─ HSM connectivity (encrypted)

Managed HSM
    ├─ Key operations
    │  ├─ Get (HSM does not export keys)
    │  ├─ Sign (mTLS certs)
    │  ├─ Wrap/Unwrap (disk encryption)
    │  └─ GenerateKey
    │
    └─ Audit logging
       └─ All operations logged
```

## Security Architecture

### 1. Authentication & Authorization

```
┌─────────────────────────────────────┐
│  Azure Attestation Service          │
│  ─────────────────────────────────  │
│  ✓ Validates CVM enclave            │
│  ✓ Verifies OS disk encryption      │
│  ✓ Checks app measurements          │
│  ✓ Issues mTLS certificates         │
│  ✓ Enforces policies                │
└─────────────────────────────────────┘
         │
         ├─ Policy: Attestation_v1
         │  ├─ Only attested CVMs allowed
         │  ├─ Check OS disk state
         │  ├─ Verify app SHA256
         │  └─ Enforce TLS version
         │
         └─ Claims Issued
            ├─ subject: cvm-identity
            ├─ aud: citizen-registry
            ├─ sgx-is-debuggable: false
            └─ exp: (1 hour)
```

### 2. Encryption Layers

| Layer | Type | Keys | Protection |
|-------|------|------|-----------|
| **OS Disk** | AES-256 (at-rest) | HSM-managed | Confidential VM requirement |
| **Data Disk** | AES-256 (at-rest) | HSM-managed | Application database |
| **Network** | TLS 1.2/1.3 (in-transit) | App-issued | mTLS + Attestation |
| **Database** | TDE (in-rest) | SQL Server | Standard encryption |
| **Memory** | SEV-SNP (runtime) | Hardware TEE | CPU-level isolation |

### 3. Network Isolation

```
Internet ━━━━ BLOCKED ━━━━━ (No public access to resources)
   │
   └─→ Bastion Public IP (only entry point)
        │
        └─→ SSH/RDP tunnel
            │
            └─→ Private VNet (10.0.0.0/16)
                │
                ├─→ App Subnet (10.0.3.0/24)
                │   └─ CVM (no public IP)
                │
                ├─→ DB Subnet (10.0.4.0/24)
                │   └─ Database (no public IP)
                │
                └─→ Private Link Subnet (10.0.1.0/24)
                    └─ HSM endpoint (no public IP)

NSG Rules (Explicit Allow):
  • Bastion ← Internet (port 443)
  • App ← Bastion (port 22, 3389)
  • Database ← App (port 1433)
  • HSM ← App (port 443, private link)
```

### 4. Managed Identity Permissions

```
Confidential VM (Managed Identity: cvm-identity)
    │
    ├─→ RBAC on Managed HSM
    │   └─ Role: Managed HSM Crypto User
    │      ├─ Get keys/secrets
    │      ├─ Sign operations
    │      ├─ Wrap/Unwrap keys
    │      └─ List permissions
    │
    ├─→ RBAC on Database
    │   └─ SQL Login: sqladmin
    │      ├─ Read citizen_registry
    │      ├─ Write citizen_registry
    │      └─ Execute stored procedures
    │
    └─→ RBAC on Attestation Service
        └─ Role: Attestation Reader (via policy)
           └─ Read attestation tokens
```

## Deployment Process

### Stage 1: Shared Infrastructure

```
1. Parse Parameters
   ├─ Prefix: sgall
   ├─ Location: eastus
   └─ Validate naming conventions

2. Create Resource Group
   └─ {Prefix}sharedinfra (e.g., sgallsharedinfra)

3. Deploy Bicep Template (shared-infra.bicep)
   ├─ Virtual Network (10.0.0.0/16)
   ├─ Private subnets
   ├─ Network Security Groups
   ├─ Managed HSM (B1 SKU)
   ├─ Private Link endpoint
   ├─ Private DNS zones
   └─ Role assignments

4. Initialize Security Domain
   └─ Run: .\scripts\initialize-hsm.ps1

5. Output Shared Resources
   ├─ VNet ID
   ├─ HSM ID & endpoint
   ├─ Private DNS zone ID
   └─ Subnet IDs (for Stage 2)
```

### Stage 2: App Instance

```
1. Parse Parameters
   ├─ Prefix: sgall
   ├─ SharedInfraRg: sgallsharedinfra
   ├─ Location: eastus
   ├─ CvmSize: Standard_DC2as_v6
   └─ Validate and link to shared infra

2. Create Resource Group
   └─ {Prefix}{random5digit}app (e.g., sgall12345app)

3. Deploy Bicep Template (app-instance.bicep)
   ├─ Virtual Network (10.0.0.0/16, different VNet)
   ├─ NSGs (app, db, bastion)
   ├─ Confidential VM
   │  ├─ Image: Ubuntu 24.04 LTS Gen2
   │  ├─ Confidential OS disk encryption
   │  ├─ Managed Identity attached
   │  └─ SSH key-based auth
   ├─ Database (SQL Server on ACC)
   ├─ Bastion host
   └─ Attestation Service

4. Configure mTLS
   └─ Run: .\scripts\configure-mtls.ps1

5. Setup Bastion
   └─ Run: .\scripts\setup-bastion.ps1

6. Seed Database
   └─ Run: .\scripts\seed-database.ps1

7. Output App Resources
   ├─ CVM ID & private IP
   ├─ Bastion endpoint
   ├─ Attestation service URI
   └─ Connection strings
```

## Deployment Timeline

| Stage | Component | Time | Notes |
|-------|-----------|------|-------|
| 1.1 | Resource Group | 1s | Instant |
| 1.2 | Virtual Network | 5s | Create subnets |
| 1.3 | Managed HSM | 120s | Provisioning |
| 1.4 | Private Link | 10s | Create endpoint |
| 1.5 | Private DNS | 5s | Configure zones |
| **Total Stage 1** | | **~2-3 min** | Shared infra ready |
| 2.1 | Resource Group | 1s | Instant |
| 2.2 | Virtual Network | 5s | Create subnets |
| 2.3 | NSGs & NIC | 10s | Create interfaces |
| 2.4 | Confidential VM | 60s | Provisioning |
| 2.5 | Database Server | 90s | SQL install |
| 2.6 | Bastion | 30s | Deploy host |
| 2.7 | Attestation Service | 15s | Create provider |
| **Total Stage 2** | | **~5-7 min** | App ready |

## File Structure & Purposes

```
citizen-registry-advanced/
│
├─ README.md                           # Detailed architecture & setup guide
├─ QUICKSTART.md                       # 10-minute getting started guide
├─ Deploy-SharedInfra.ps1              # Stage 1 orchestration script
├─ Deploy-AppInstance.ps1              # Stage 2 orchestration script
├─ .gitignore                          # Exclude secrets/keys from git
│
├─ bicep/
│  ├─ shared-infra.bicep              # Managed HSM + VNet deployment
│  └─ app-instance.bicep              # CVM + DB + Bastion deployment
│
├─ scripts/
│  ├─ initialize-hsm.ps1              # HSM security domain setup
│  ├─ configure-mtls.ps1              # mTLS certificate generation
│  ├─ setup-bastion.ps1               # Bastion access configuration
│  └─ seed-database.ps1               # Database initialization
│
└─ app-instance/app-src/
   ├─ app.py                          # Flask app (450 lines)
   ├─ requirements.txt                # Python dependencies
   ├─ Dockerfile                      # Container image build
   ├─ nginx.conf                      # Reverse proxy (mTLS config)
   ├─ supervisord.conf                # Process management
   └─ templates/
      └─ index.html                   # Web UI
```

## Performance & Scalability

### Single App Instance Resources

```
Confidential VM (DC2as_v6):
  • 2 vCPUs: Sufficient for 10-50 concurrent users
  • 8 GB RAM: Python + nginx + SQL driver
  • Network: 2 Gbps max throughput

Database (SQL Server on ACC):
  • 10 GB default size: ~1 million citizens
  • TPS (transactions/sec): 100-500 typical
  • Connection pool: 10 concurrent connections

Performance Target:
  • API response: <500ms (p99)
  • Database query: <100ms (average)
  • mTLS handshake: <1s (once per session)
```

### Horizontal Scaling

```
Option 1: Multiple App Instances
  • Deploy Stage 2 multiple times
  • Each gets unique RG: {prefix}{random1}app, {prefix}{random2}app
  • All share same Stage 1 Managed HSM
  • Load balance with Azure Load Balancer (private LB)

Option 2: Larger VM
  • Change -CvmSize parameter
  • Options: DC1as_v6, DC2as_v6, DC4as_v6
  • Scale up from 1 to 4 vCPUs

Option 3: Database Replication
  • Deploy secondary SQL Server on ACC
  • Configure Always On availability group
  • High availability (active-active)
```

## Disaster Recovery

### Backup Strategy

```
1. Managed HSM
   ├─ Security domain backup (offline, in secure facility)
   └─ Key rotation policy (quarterly)

2. Database
   ├─ Automated backups: Daily
   ├─ Retention: 7-35 days
   ├─ Geo-redundant: Yes (paired region)
   └─ Point-in-time restore: Supported

3. Application Code
   ├─ Git repository: GitHub (public)
   ├─ Secrets: Git-ignored (not in repo)
   ├─ Configuration: Key Vault (HSM-backed)
   └─ Certificates: HSM-stored

Recovery Time Objective (RTO): 30 minutes (full redeploy)
Recovery Point Objective (RPO): 1 hour (database backup)
```

## Cost Optimization

### Current Pricing (as of Aug 2026)

```
Managed HSM (B1):
  • Fixed monthly: $400 USD
  • Not a good fit for dev/test
  • Share across multiple app instances

Confidential VM (DC2as_v6):
  • $0.298/hour × 730 hours = $217/month
  • Cheapest v6 option
  • Include OS disk encryption

Database (SQL Server on ACC):
  • $0.10/GB/month × 10 GB = $1/month
  • Plus: Storage ($0.05/GB/month)
  • Total: ~$30-50/month

Bastion:
  • $50/month (Standard SKU, 2 scale units)
  • Can reduce to 1 scale unit if low usage

Azure Attestation:
  • $0.01 per 1000 requests
  • Typical app: $5-10/month

Total per Instance: $720/month (HSM + CVM + DB + Bastion + Attest)
  • HSM is shared, so cost-per-app decreases with scale
  • 3 app instances: $420/month + $720×3 = $2,580/month
```

### Cost-Saving Options

1. **Consolidate HSM** — One shared HSM for 10+ app instances
2. **Use smaller CVM** — DC1as_v6 (1 vCPU): -50% compute
3. **Reduce Bastion scale** — 1 scale unit: -50% bastion cost
4. **Delete on-demand** — Full destroy when not in use
5. **Reserved instances** — 1-year or 3-year commitment discounts

---

For more details, refer to:
- [README.md](README.md) — Deployment guide
- [QUICKSTART.md](QUICKSTART.md) — 10-minute setup
- Azure Docs: Confidential Computing, Managed HSM, Azure Attestation
