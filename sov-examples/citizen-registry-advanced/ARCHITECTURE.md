# Technical Architecture — Citizen Registry Advanced

## System Overview

### Deployed Stage 2 Topology

```mermaid
flowchart LR
  Browser[Customer browser] -->|HTTPS through Bastion tunnel| Bastion[Azure Bastion]

  subgraph AppVNet[App VNet - West Europe<br/>default 10.20.0.0/16]
    Bastion -->|Private 443| App[App Confidential VM<br/>Standard_NCC40ads_H100_v5<br/>default 10.20.3.4]
  end

  subgraph SqlVNet[SQL VNet - North Europe<br/>default 10.21.0.0/16]
    Sql[SQL Confidential VM<br/>Standard_DC2as_v5<br/>default 10.21.4.5]
  end

  subgraph SharedVNet[Shared VNet - West Europe<br/>default 10.10.0.0/16]
    HsmPe[Managed HSM private endpoint<br/>default 10.10.1.4] --> Hsm[Customer Managed HSM]
  end

  App -->|Encrypted SQL connection<br/>TCP 1433 over global VNet peering| Sql
  App -->|Private endpoint access| HsmPe
```

The app and SQL Server run on separate Confidential VMs and separate regional VNets. Global VNet
peering carries the private SQL connection; neither VM has a public IP. The app VM combines an
AMD SEV-SNP confidential CPU boundary with an NVIDIA H100 in production confidential-computing
mode. Bastion provides workstation access, and the app reaches Managed HSM through its private
endpoint in the shared VNet.

## Data Flow & Security

### 1. User → App Connection (mTLS)

```text
User Machine
    │
    ├─ SSH via Bastion
    │  └─ Port 2222 → Bastion → Port 22 (CVM)
    │
    └─ HTTPS via Bastion
       └─ Port 8443 (mTLS)
          └─ Client certificate required for protected CRUD operations

         ↓↓↓ (Mutual TLS Handshake) ↓↓↓

    Customer-issued User Certificate
         │
    Customer-issued App Certificate
         │
    ↓ TLS 1.2/1.3 ↓

Confidential App VM
    ├─ nginx (reverse proxy)
    │  ├─ TLS and mTLS termination
    │  ├─ Security headers
    │  └─ Request forwarding
    │
    ├─ Flask App (port 8000)
    │  ├─ Database driver
    │  ├─ Attestation status
    │  └─ Confidential GPU processing
    │
    └─ Azure guest attestation
       └─ SEV-SNP boot evidence
```

### 2. App → Database (Global VNet Peering + TLS)

The database is a second Confidential VM in the North Europe SQL VNet. By default, the SQL CVM
uses private IP `10.21.4.5`; the West Europe app VNet reaches it over global VNet peering.

```text
Flask App (8000)
    │
    ├─ SQL Connection String
   │  ├─ Server: 10.21.4.5 (default SQL CVM private IP)
    │  ├─ Port: 1433
    │  ├─ Encrypt: yes
    │  ├─ TrustServerCertificate: yes
    │  └─ Database: citizendb
    │
    ↓ (pyodbc with ODBC Driver 18)
    
Private Network
   ├─ App CVM → SQL CVM over global VNet peering
   ├─ NSG rule: Allow TCP 1433 from the peered app VNet
    ├─ All traffic encrypted (TLS)
    └─ No internet exposure
    
SQL Server Confidential VM
    ├─ SQL Server
   ├─ AMD SEV-SNP confidential compute
   ├─ Encryption at host
    ├─ citizen_registry table
   └─ Private SQL subnet only
```

### 3. App → Managed HSM (Private Link + mTLS)

```
Flask App
    │
    ├─ Azure Identity SDK
    │  └─ Managed Identity credential
    │
   ├─ Azure managed disk service
   │  └─ HSM-backed CMK through the Disk Encryption Set
    │
    ↓ (DNS resolution via Private DNS Zone)
    
Private DNS Zone (privatelink.managedhsm.azure.net)
   └─ A record → 10.10.1.4 (HSM private endpoint IP)

Private Link Endpoint
   ├─ VNet: 10.10.0.0/16
   ├─ Subnet: 10.10.1.0/24
    └─ HSM connectivity (encrypted)

Managed HSM
   ├─ Key operations
   │  ├─ Read/Wrap/Unwrap for the DES identity
   │  └─ Attestation-gated release for Azure CVM Orchestrator
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
│  ✓ Publishes provider metadata      │
│  ✓ Supports guest attestation flows │
│  ✓ Does not issue demo mTLS certs   │
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
| **App OS disk** | AES-256 (at rest) | Managed HSM-backed customer-managed key | Disk Encryption Set |
| **SQL VM storage** | Encryption at host | Platform-managed keys | Encrypts data through the Azure storage path |
| **Browser network** | TLS 1.2/1.3 (in transit) | Customer-issued server and client certificates | mTLS for protected CRUD operations |
| **SQL network** | TLS (in transit) | SQL Server certificate | Encrypted private connection over global VNet peering |
| **CPU memory** | SEV-SNP (runtime) | Hardware TEE | App and SQL CVM isolation |
| **GPU memory** | H100 confidential-computing mode | Hardware TEE | Attested confidential inference boundary |

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
   ├─ Prefix: yourprefix
   ├─ Location: northeurope
   └─ Validate naming conventions

2. Create Resource Group
   └─ {Prefix}sharedinfra (e.g., yourprefixsharedinfra)

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
   ├─ Prefix: yourprefix
   ├─ SharedInfraRg: yourprefixsharedinfra
   ├─ Location: northeurope
   ├─ CvmSize: Standard_DC2as_v5
   └─ Validate and link to shared infra

2. Create Resource Group
   └─ {Prefix}{random5digit}app (e.g., yourprefix12345app)

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
   └─ Cloud-init creates the Norland demo PKI and installs nginx configuration

5. Setup Bastion
   └─ Bicep deploys Standard Bastion with tunneling enabled

6. Seed Database
   └─ App migration creates the expanded schema and 100 fictional records

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
│  └─ seed-database.ps1               # Database initialization
│
└─ app-instance/app-src/
   ├─ app.py                          # Flask app (450 lines)
   ├─ nginx.conf                      # Reverse proxy (mTLS config)
   └─ templates/
      └─ index.html                   # Web UI
```

## Performance & Scalability

### Single App Instance Resources

| Tier | Default resource | Workload |
|---|---|---|
| App | `Standard_NCC40ads_H100_v5` | Flask/nginx, SDXL portraits, and MTCNN CCTV anonymization on one H100 |
| Database | `Standard_DC2as_v5` | SQL Server persistence on an AMD SEV-SNP Confidential VM |

The sample does not assert production throughput or latency targets. Measure registry traffic,
portrait generation, video processing, database latency, and cross-region network latency with a
representative workload before selecting production capacity.

### Horizontal Scaling

The deployment scripts create one app CVM and one SQL CVM. Horizontal app scaling, shared media
state, load balancing, and SQL high availability are not implemented by this demo. A production
design must preserve per-instance CPU and GPU attestation gates, private connectivity, certificate
validation, and database consistency while adding those capabilities.

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

### Current Pricing (verified September 8, 2026)

| Core resource | West Europe USD retail rate | 8-hour run | 730 hours |
|---|---:|---:|---:|
| Linux `Standard_NCC40ads_H100_v5` | $8.90/hour | $71.20 | $6,497 |
| Managed HSM Standard B1 | $3.20/hour | $25.60 | $2,336 |
| **Core subtotal** | **$12.10/hour** | **$96.80** | **$8,833** |

These are planning estimates, not quotes. The SQL CVM and SQL Server licensing, Bastion, disks,
Private Link, VNet peering, monitoring, and data transfer are additional. Managed HSM has no
stopped state and continues hourly billing while provisioned. See the [README cost warning and
live pricing links](README.md#cost-warning-and-controls) before deployment.

### Cost-Saving Options

1. **Run short demonstrations** — Schedule a bounded window and enable VM auto-shutdown.
2. **Verify deallocation** — Confirm both VMs show **Stopped (deallocated)** after use.
3. **Delete app instances** — Remove residual disks and networking between demonstrations.
4. **Delete shared infrastructure after the final run** — Preserve the Managed HSM security-domain backup and key-recovery plan first.
5. **Consider Spot only for disposable tests** — The observed H100 Spot meter is cheaper but interruptible and not guaranteed to be available.

---

For more details, refer to:
- [README.md](README.md) — Deployment guide
- [QUICKSTART.md](QUICKSTART.md) — 10-minute setup
- Azure Docs: Confidential Computing, Managed HSM, Azure Attestation
