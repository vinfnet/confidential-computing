# Citizen Registry Advanced — Two-Stage Confidential Deployment

**Topology:** App Confidential VM ↔ SQL Server Confidential VM on a private subnet ↔ Managed HSM
**Author:** Autonomous AI-Assisted Development  
**Date:** August 2026

---

### Deployed Stage 2 Topology

```text
                 North Europe VNet: 10.0.0.0/16
                              |
                    App subnet: 10.0.3.0/24
                    (private IPs only)
                  +-----------+-----------+
                  |                       |
          App CVM: 10.0.3.4       SQL CVM: 10.0.3.5
          Flask + nginx            SQL Server 2022
                  |                       |
                  +------ TLS :1433 -----+

  Workstation -- Bastion tunnel --> App CVM
  App/SQL subnet -- NAT Gateway --> outbound package access only
  Shared HSM <-- Private Endpoint + Private DNS -- VNet
```

Stage 2 deploys two Confidential VMs on the same private `app-subnet`: the application CVM
(`10.0.3.4`) and SQL Server CVM (`10.0.3.5`). SQL Server is initialized with `citizendb`, the
`registryadmin` login, and three demo citizen records. The app connects over private TCP 1433.

## ⚠️ IMPORTANT: Managed HSM Requirement & Cost Warning

**This example requires Azure Managed HSM (Hardware Security Module), which has significant costs.**

### Monthly Cost Estimate

| Component | SKU | Daily Cost | Monthly Cost |
|-----------|-----|-----------|--------------|
| **Managed HSM** | B1 Standard | ~$13.33 | $400 |
| **App Confidential VM** | DC2as_v5 (2 CPU) | ~$7.29 | $220 |
| **SQL Server Confidential VM** | DC2as_v5 (2 CPU) | ~$7.29 | $220 |
| **Bastion Host** | Standard (2 units) | ~$1.67 | $50 |
| **Storage** | Premium SSD (64 GB OS + 64 GB Data) | ~$1.00 | $30 |
| **Attestation** | Per-request (~1000/day) | ~$0.10 | $3 |
| **Total (1 App + SQL Instance)** | | **~$30.68/day** | **~$923/month** |

> **Pricing information:** The estimates above are provided for planning purposes only and are not quotes. Azure prices can change and may vary by region, currency, agreement, usage, operating system, and selected configuration. Check the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) and the current service pricing pages before deployment:
>
> - [Azure Key Vault Managed HSM pricing](https://azure.microsoft.com/pricing/details/key-vault/)
> - [Azure Virtual Machines pricing](https://azure.microsoft.com/pricing/details/virtual-machines/linux/)
> - [Azure SQL Database pricing](https://azure.microsoft.com/pricing/details/azure-sql-database/)
> - [Azure Bastion pricing](https://azure.microsoft.com/pricing/details/azure-bastion/)
> - [Azure Attestation pricing](https://azure.microsoft.com/pricing/details/azure-attestation/)

### Cost Optimization Strategies

✅ **Do This to Save Money:**
- **Share Managed HSM** — Deploy multiple app instances (Stage 2) to amortize HSM cost
  - With 3 app instances: ~$31/month HSM per app (shared)
  - Total: ~$333/month per app instance
- **Use smaller CVM** — Standard_DC1as_v6 (1 CPU): saves ~$110/month
- **Reduce Bastion** — 1 scale unit instead of 2: saves ~$25/month
- **Delete when not in use** — Keep Stage 1, delete Stage 2 instances: save $280+/month per instance
- **Reserved instances** — 1-year commitment: save ~20-30%

❌ **Avoid Doing This:**
- Don't deploy HSM in production regions you don't need (unnecessary cost)
- Don't leave Stage 2 instances running if not actively testing
- Don't create multiple HSMs (share across all apps)

### Before You Deploy

1. **Ensure Managed HSM quota** in your target region:
   ```powershell
   az vm list-usage --location eastus --query "[?name.value=='Standard_B1']"
   ```

2. **Verify cost center/chargeback** is set up for Managed HSM (quota requirement):
   - Tag: `costControl: confidential-computing`
   - You may need to request HSM quota approval from your Azure admin

3. **Understand commitment** — This is a **$400+/month standing charge** even if running minimal workload

4. **Consider alternatives** if cost is prohibitive:
   - Use standard Key Vault (not HSM-backed) for development
   - Use Azure Confidential Ledger for audit scenarios
   - See Azure Confidential Computing docs for other patterns

---

## 🔒 Architecture Overview

This advanced deployment splits citizen registry infrastructure into **two stages**:
- **Stage 1 (Shared Infrastructure):** Managed HSM + private networking backbone
- **Stage 2 (App Instance):** App Confidential VM + SQL Server Confidential VM on the same private subnet + Bastion access + mTLS

### Complete System Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          USER MACHINE / WORKSTATION                      │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ (SSH/RDP via Bastion)
                                    ▼
                    ┌───────────────────────────────┐
                    │   AZURE BASTION HOST          │
                    │  (Public IP - Entry Point)    │
                    │  Standard_B2s                 │
                    └───────────────────────────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 │     PRIVATE VNet │                  │
                 │  10.0.0.0/16     │                  │
                 │                  ▼                  │
                 │         ┌─────────────────┐         │
                 │         │ APP SUBNET      │         │
                 │         │ 10.0.3.0/24     │         │
                 │         │                 │         │
                 │         │  ┌───────────┐  │         │
                 │         │  │ APP CVM   │  │         │
                 │         │  │ SEV-SNP   │  │         │
                 │         │  │ 10.0.3.4  │  │         │
                 │         │  └─────┬─────┘  │         │
                 │         │        │ 1433   │         │
                 │         │  ┌─────▼─────┐  │         │
                 │         │  │ SQL CVM   │  │         │
                 │         │  │ SEV-SNP   │  │         │
                 │         │  │ 10.0.3.5  │  │         │
                 │         │  └───────────┘  │         │
                 │         └────────┬────────┘         │
                 │                  │                  │
                 │  ┌───────────────┼───────────────┐  │
                 │  │               │               │  │
                 │  ▼               ▼               ▼  │
        ┌─────────────────┐  ┌──────────────┐  ┌────────────┐
        │ PRIVATE LINK    │  │ DB SUBNET    │  │ BASTION    │
        │ SUBNET          │  │ 10.0.4.0/24  │  │ SUBNET     │
        │ 10.0.1.0/24     │  │              │  │ 10.0.2.0   │
        │                 │  │ ┌──────────┐ │  │            │
        │ ┌───────────────┐│  │ │SQL       │ │  │ Connected  │
        │ │Private Link   ││  │ │Server    │ │  │ to Conf.VM │
        │ │Endpoint       ││  │ │on ACC    │ │  │            │
        │ │(mHSM.net)     ││  │ │Encrypted│ │  └────────────┘
        │ │No Public IP   ││  │ │TDE      │ │
        │ └───────────────┘│  │ └──────────┘ │
        └─────────────────┘  └──────────────┘
                 │
                 │ Private DNS Resolution
                 │ (mhsm.azure.net → 10.0.1.x)
                 │
   ┌─────────────────────────────────────────────┐
   │       STAGE 1: SHARED INFRASTRUCTURE        │
   │          {prefix}sharedinfra RG             │
   │                                             │
   │  ┌──────────────────────────────────────┐  │
   │  │   MANAGED HSM (B1 SKU)               │  │
   │  │   AMD-backed, SEV-SNP                │  │
   │  │   Private Link Only                  │  │
   │  │   NO PUBLIC IP                       │  │
   │  │                                      │  │
   │  │  ┌─ Key Management                   │  │
   │  │  ├─ Certificate Issuance (mTLS)      │  │
   │  │  ├─ Disk Encryption Key Storage      │  │
   │  │  └─ Attestation Service Integration  │  │
   │  │                                      │  │
   │  └──────────────────────────────────────┘  │
   └─────────────────────────────────────────────┘
                 │
    ┌────────────────────────────────────────────────────────┐
    │  AZURE ATTESTATION SERVICE                             │
    │  - Validates Confidential VM enclave                   │
    │  - Issues mTLS certificates (signed by attestation)    │
    │  - Enforces attestation policies                       │
    │  - Key release based on TEE measurements               │
    └────────────────────────────────────────────────────────┘
```

### Simplified Data Flow Architecture

```
EXTERNAL USER ACCESS (via Bastion Tunnel)
    │
    ├─ Establishes SSH/RDP tunnel through Bastion
    ├─ Tunnel target: CVM private IP (10.0.3.x)
    └─ No direct internet access to CVM
    
    ▼
    
CONFIDENTIAL VM (C-vn2 with SEV-SNP TEE)
    │
    ├─ OS Disk: Encrypted at-rest (AES-256)
    │  └─ Key: Managed by Managed HSM
    │  └─ Protection: Hardware-backed (confidential computing)
    │
    ├─ Nginx (Reverse Proxy)
    │  ├─ TLS 1.3 termination
    │  ├─ mTLS client verification
    │  ├─ Certificate chain: User Cert ← Attestation Service
    │  └─ Forward to: http://localhost:8000
    │
    ├─ Flask Application (Gunicorn)
    │  ├─ CRUD endpoints for citizen registry
    │  ├─ Database connection pooling
    │  ├─ Managed Identity for HSM auth
    │  └─ Attestation token validation
    │
    ├─ Managed Identity
    │  ├─ Authenticates to: Managed HSM
    │  ├─ Authenticates to: Azure Attestation Service
    │  └─ No secret keys in code
    │
    └─ Confidential OS Disk
       ├─ Encrypted: AES-256 at-rest
       ├─ Key stored in: Managed HSM (not on disk)
       ├─ Encryption state: Verified by Attestation
       └─ Hardware TEE: SEV-SNP isolation
    
    ▼
    
DATABASE (SQL Server on ACC)
    │
    ├─ Private Subnet: 10.0.4.0/24
    ├─ No Public IP: Accessible only from App CVM
    ├─ Encryption: TDE (Transparent Data Encryption)
    ├─ Connection: TLS 1.2 encrypted (pyodbc)
    ├─ Port: 1433 (private subnet only)
    └─ NSG Rule: Allow TCP 1433 from app subnet (10.0.3.0/24) only
    
    ▼
    
MANAGED HSM (B1 SKU, Shared)
    │
    ├─ Private Link Only: No public access
    ├─ Access: Via private endpoint (10.0.1.x)
    ├─ Key Management:
    │  ├─ OS disk encryption keys
    │  ├─ mTLS certificate signing
    │  └─ Key release gates (attestation-backed)
    │
    ├─ Managed Identity Permissions:
    │  └─ Role: Managed HSM Crypto User
    │     ├─ Wrap/Unwrap keys
    │     ├─ Get certificates
    │     └─ Sign operations
    │
    └─ Private DNS Resolution:
       ├─ Zone: mhsm.azure.net
       ├─ A Record: Points to private endpoint IP
       └─ No internet routing
```

### Detailed Network Segmentation & Security Boundaries

```
╔════════════════════════════════════════════════════════════════════╗
║                     SECURITY BOUNDARY LAYERS                       ║
╚════════════════════════════════════════════════════════════════════╝

┌─ LAYER 1: INTERNET BOUNDARY ─────────────────────────────────────┐
│                                                                   │
│  ✗ NO DIRECT ACCESS to app resources                             │
│  ✗ NO PUBLIC IPs on CVM, Database, or HSM                        │
│  ✓ ONLY Bastion Host has public IP (gated by NSG)                │
│  ✓ Bastion requires authenticated user + MFA (Azure Portal)      │
│                                                                   │
│  Bastion NSG Rules:                                              │
│    • Inbound 443: From Internet (User browsers)                  │
│    • Inbound 443: From GatewayManager                            │
│    • Inbound 443: From AzureLoadBalancer                         │
│    • Outbound: To private subnets via SSH/RDP gateways           │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌─ LAYER 2: VNET BOUNDARY ─────────────────────────────────────────┐
│                                                                   │
│  VNet: 10.0.0.0/16 (isolated, no internet gateway)               │
│                                                                   │
│  Route Table: Default (no routes to internet)                    │
│    • Routes only to: Local (10.0.0.0/16)                         │
│    • Routes only to: Private Link endpoints                      │
│    • NO 0.0.0.0/0 route (no internet egress)                     │
│                                                                   │
│  Peering: Cross-RG (Shared Infra ↔ App Instance)                │
│    • Peering Name: {prefix}-shared-to-app                        │
│    • Allows: Private Link access to HSM                          │
│    • Encrypted: All traffic via TLS                              │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌─ LAYER 3: APP SUBNET BOUNDARY (10.0.3.0/24) ─────────────────────┐
│                                                                   │
│  App NSG (Applied to CVM NIC):                                   │
│    • Inbound 22 (SSH): From Bastion subnet only                  │
│    • Inbound 443 (HTTPS): From Bastion subnet only               │
│    • Inbound 8000: From Bastion subnet (Gunicorn direct)         │
│    • Outbound 443: To Private Link subnet (HSM)                  │
│    • Outbound 1433: To DB subnet (SQL)                           │
│    • Outbound DNS: To Azure DNS (169.254.169.254)                │
│    • Deny ALL other inbound                                      │
│                                                                   │
│  Result: CVM isolated, reachable only via Bastion                │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌─ LAYER 4: DATABASE SUBNET BOUNDARY (10.0.4.0/24) ────────────────┐
│                                                                   │
│  DB NSG (Applied to Database NIC):                               │
│    • Inbound 1433 (SQL): From App subnet (10.0.3.0/24) ONLY      │
│    • Deny ALL other inbound                                      │
│    • Allow outbound to Azure logging/monitoring                  │
│                                                                   │
│  Result: Database only accessible from app CVM                   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌─ LAYER 5: PRIVATE LINK BOUNDARY (10.0.1.0/24) ────────────────────┐
│                                                                   │
│  Private Link Endpoint (HSM):                                    │
│    • Deployment: 10.0.1.x (managed by Azure)                     │
│    • DNS: mhsm.azure.net → Private A record                      │
│    • Access: Via VNet peering (App Instance ← Shared Infra)      │
│    • Protocol: HTTPS (TLS 1.2/1.3)                               │
│    • No NSG needed (private link endpoint)                       │
│                                                                   │
│  Private DNS Zone:                                               │
│    • Zone: mhsm.azure.net                                        │
│    • A Record: mhsm.azure.net → 10.0.1.x                        │
│    • Linked to: Both VNets (shared + app instance)               │
│    • Result: Seamless hostname resolution on private subnets     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌─ LAYER 6: TEE BOUNDARY (Hardware Isolation) ─────────────────────┐
│                                                                   │
│  Confidential VM (C-vn2 with SEV-SNP):                           │
│    • OS Disk: Encrypted (key never exposed to hypervisor)        │
│    • Memory: Encrypted (CPU-level isolation)                     │
│    • Attestation: Hardware proves encryption state               │
│    • Measurement: VM boot sequence hashed and signed             │
│                                                                   │
│  SEV-SNP Security Model:                                         │
│    • Hypervisor: Cannot access guest VM memory                   │
│    • Guest OS: Protected at CPU level                            │
│    • Attestation: Remote party verifies TEE state                │
│    • Key Release: HSM gates key issuance until attestation OK    │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Stage 1: Shared Infrastructure (`Deploy-SharedInfra.ps1`)

Creates resource group: **`{prefix}sharedinfra`**

**Resources:**
- **Managed HSM** — AMD-backed HSM with SEV-SNP attestation
  - Private Link endpoint (no public access)
  - Cost control tag for resource authorization
  - Security domain initialized
  - Ready for mTLS certificate management
- **Virtual Network (VNet)** — Private backbone
  - Private DNS zone for Managed HSM
  - Private Link subnet reserved
- **Private Link Endpoint** — HSM ↔ VNet connectivity

**Outputs:**
- Managed HSM ID and private endpoint connection
- Private DNS zone configuration
- VNet ID for cross-RG peering

### Stage 2: App Instance (`Deploy-AppInstance.ps1`)

Creates resource group: **`{prefix}{random5digit}app`** (e.g., `sgall18447app`)

**Resources:**
- **Confidential VM (C-vn2)** — AMD SEV-SNP
  - Confidential OS disk encryption enabled
  - Deployed to secure enclave
  - Connected to shared mHSM over private link
- **Database on ACC** — SQL Server or PostgreSQL
  - Transparent Data Encryption (TDE)
  - Private subnet only
  - Attestation-backed connectivity
- **Bastion Host** — Private access gateway
  - RDP/SSH tunnel to CVM
  - No public IPs on app resources
- **Azure Attestation Service** — mTLS enablement
  - Validates CVM confidentiality
  - Issues mTLS certificates via key release
  - Attestation policy tied to citizen-registry app

**Security Model:**
```
User → (mTLS over Bastion)
  ↓
App CVM (attestation verified)
  ↓ (TLS)
DB on ACC ← (confidential OS)
  ↓ (mTLS)
Managed HSM (key release)
```

## 🛡️ Comprehensive Data Protection Architecture

### 1. End-to-End Encryption Model

```
┌─────────────────────────────────────────────────────────────┐
│                    ENCRYPTION LAYERS                        │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: USER → BASTION                                     │
│   Protocol: HTTPS (TLS 1.2/1.3)                             │
│   Cipher: AES-256-GCM (Modern)                              │
│   Authentication: Azure Entra ID + MFA                      │
│   Key Exchange: ECDHE (Forward secrecy)                     │
│                                                             │
│ Layer 2: BASTION → CONFIDENTIAL VM (SSH/RDP Tunnel)        │
│   Protocol: SSH-2 or RDP-TLS                               │
│   Cipher: AES-256 with HMAC-SHA2-256                       │
│   Authentication: Public key or certificate                │
│   Isolation: Tunnel isolated per session                   │
│                                                             │
│ Layer 3: APP CVM → DATABASE (SQL Connection)               │
│   Protocol: TLS 1.2 (enforced)                             │
│   Cipher: AES-128-CBC or AES-256-GCM                       │
│   Authentication: SQL login (encrypted)                    │
│   Isolation: Private subnet only (no internet)             │
│                                                             │
│ Layer 4: CVM → MANAGED HSM (mTLS)                          │
│   Protocol: HTTPS (TLS 1.2/1.3)                            │
│   Cipher: AES-256-GCM                                      │
│   Authentication: mTLS (client cert + HSM cert)            │
│   Key Exchange: ECDHE (client cert from attestation)       │
│   Isolation: Private Link endpoint (10.0.1.x)              │
│                                                             │
│ Layer 5: OS DISK AT-REST (Confidential OS)                 │
│   Algorithm: AES-256                                       │
│   Key Location: Managed HSM (never on-disk)                │
│   Mode: Confidential VM encryption                         │
│   Verification: SEV-SNP attestation required               │
│                                                             │
│ Layer 6: MEMORY AT-REST (Confidential Computing)           │
│   Algorithm: AES-256 (CPU-level)                           │
│   Isolation: SEV-SNP (Hardware TEE)                        │
│   Verification: VM measurement hash via attestation         │
│   Hypervisor Access: BLOCKED (hardware enforced)           │
│                                                             │
│ Layer 7: DATABASE ENCRYPTION AT-REST (TDE)                 │
│   Algorithm: AES-256 (SQL Server TDE)                      │
│   Key Location: Database encryption key                    │
│   Scope: All tables in citizendb                           │
│   Transparent: No application code changes needed          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. Citizen Data Protection Journey

```
DATA STATE: REST (On Disk)
═════════════════════════════════════════════════════════════
    
    Citizen Record
    ├─ id: 1
    ├─ national_id: "NL-2024-001"
    ├─ first_name: "John"
    ├─ last_name: "Smith"
    └─ ... (other PII)
    
         ▼ (Encrypted by SQL Server TDE)
    
    Encrypted Bytes on SQL Data File
    ├─ Algorithm: AES-256
    ├─ Key: Database Encryption Key (DEK)
    ├─ Master Key: Azure Key Vault (HSM-backed)
    └─ Visible as: Binary garbage (can't be read)
    
         ▼ (Data file on private ACC)
    
    Stored in: Confidential VM private data disk
    ├─ Path: /var/lib/mssql/data/citizendb.mdf
    ├─ Disk: Premium SSD (encrypted)
    ├─ Encryption: AES-256 at hypervisor level
    ├─ Key: Stored in Managed HSM (not on disk)
    └─ Protection: Attestation-gated key release

─────────────────────────────────────────────────────────────

DATA STATE: IN TRANSIT (Moving)
═════════════════════════════════════════════════════════════

    1. User Request (Web Browser / API Client)
    
        GET /api/citizen/1
        ├─ TLS ClientHello
        ├─ Presents: User certificate (from Attestation Service)
        ├─ Validates: CVM certificate (from Attestation Service)
        └─ Handshake: Establishes shared session key (ephemeral)
    
             ▼ (HTTPS/TLS encrypted)
    
        Over Bastion Tunnel (Private)
        ├─ Entry: User machine SSH/RDP
        ├─ Tunnel: Bastion → CVM (encrypted)
        ├─ Cipher: AES-256-GCM
        └─ Protocol: TLS 1.3 (no weak ciphers)
    
             ▼ (Request received at CVM)
    
        Request Decrypted at Nginx
        ├─ Decryption: TLS session key (ephemeral)
        ├─ Verification: Client cert chain (attestation proof)
        ├─ Access Control: mTLS cert thumbprint matches policy
        └─ Forward: To Flask app (via Unix socket)
    
             ▼ (Local IPC, no network)
    
        Flask App Queries Database
        ├─ Connection String: Server=10.0.4.5; Encrypt=yes
        ├─ Protocol: TDS (SQL Server protocol)
        ├─ Encryption: TLS 1.2 (enforced)
        ├─ Auth: SQL user + password (encrypted in connection)
        └─ Query: SELECT * FROM citizen WHERE id = 1
    
             ▼ (TLS encrypted across private subnet)
    
        Database Decrypts on Receipt
        ├─ TLS Session: Established with client certificate
        ├─ Decryption: Session key used to decrypt query
        ├─ Processing: Query executed in protected enclave
        └─ Result: Citizen record retrieved (still encrypted)
    
             ▼ (Database returns encrypted result)
    
        Flask App Receives Encrypted Response
        ├─ TLS Decryption: Session key (opposite direction)
        ├─ Data: {id: 1, national_id: ..., ...}
        ├─ Processing: Application logic (Python logic runs)
        └─ Serialization: Converted to JSON response
    
             ▼ (Encrypted via TLS session)
    
        Nginx Encrypts Response
        ├─ TLS Encryption: Session key (established at handshake)
        ├─ Cipher: AES-256-GCM
        ├─ Signing: HMAC-SHA2-256 (integrity)
        └─ Wrapping: TLS record format with MAC
    
             ▼ (HTTPS encrypted over Bastion tunnel)
    
        Response Transmitted
        ├─ Path: CVM (10.0.3.x) → Bastion → User
        ├─ Encryption: End-to-end TLS (no decryption in transit)
        ├─ Network: Private VNet (no internet exposure)
        └─ Integrity: MAC verified at each hop
    
             ▼ (Decrypted at User Endpoint)
    
        User Receives Decrypted Response
        ├─ Decryption: Browser TLS stack (user key pair)
        ├─ Display: Citizen data shown in browser
        ├─ Security: User's endpoint responsible for memory protection
        └─ Note: User must protect device (screen, keyboard)

─────────────────────────────────────────────────────────────

DATA STATE: IN MEMORY (Active Processing)
═════════════════════════════════════════════════════════════

    Confidential VM (SEV-SNP TEE)
    
    Flask App Process Memory (PID 1234)
    ├─ Virtual Address: 0x7f8a12345678
    ├─ Data: {"id": 1, "national_id": "NL-2024-001", ...}
    ├─ Protection: Encrypted by CPU (SEV-SNP)
    ├─ Hypervisor Access: BLOCKED (hardware enforced)
    └─ Attestation: Proves encryption & integrity
    
         ▼ (CPU hardware encryption)
    
    Physical Memory (DDR5)
    ├─ Contents: Encrypted bytes
    ├─ Decryption Key: Inside CPU (never exposed)
    ├─ Only CPU can decrypt: For instruction execution
    ├─ Hypervisor can't see plaintext
    └─ Guest OS can't extract plaintext without attestation
    
         ▼ (Proof via attestation)
    
    Attestation Report
    ├─ VM Launch Measurement: SHA256 hash
    ├─ App Code Hash: Verified against policy
    ├─ OS State: Measured (confidential encryption enabled)
    ├─ Signature: Signed by Azure Attestation Service
    └─ Verifiable: By relying party (e.g., HSM for key release)

─────────────────────────────────────────────────────────────

THREAT MODEL: What's Protected
═════════════════════════════════════════════════════════════

    ✅ PROTECTED:
       • Data at rest on disk (AES-256)
       • Data in transit on network (TLS 1.2/1.3)
       • Data in memory (SEV-SNP CPU encryption)
       • Confidential VM OS (confidential OS disk)
       • Private keys (never leave HSM)
       • Network traffic from interception
       • Hypervisor from accessing guest memory
       • Database encryption keys (HSM-stored)

    ⚠️  PARTIALLY PROTECTED (User Responsibility):
       • User device (endpoint security)
       • Screen/keyboard eavesdropping (physical security)
       • Bastion login credentials (MFA required)
       • Admin access (RBAC + PIM elevation)

    ❌ NOT PROTECTED (By Design):
       • Application logic bugs (input validation needed)
       • Social engineering attacks (training required)
       • Weak passwords (password policy needed)
       • USB/physical theft of user device (encryption + lock)
```

### 3. Key Management Architecture

```
┌──────────────────────────────────────────────────────────────┐
│            MANAGED HSM — KEY HIERARCHY                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Root Authority: Managed HSM (B1 SKU)                        │
│  │                                                           │
│  ├─→ Certificate Authority Key (HSM-resident)               │
│  │   ├─ Algorithm: RSA-2048                                 │
│  │   ├─ Usage: Sign mTLS certificates                       │
│  │   ├─ Rotation: Quarterly via HSM policy                  │
│  │   └─ Never Exported: HSM-only operations                 │
│  │                                                           │
│  ├─→ OS Disk Encryption Key (HSM-resident)                  │
│  │   ├─ Algorithm: AES-256                                  │
│  │   ├─ Usage: Encrypt CVM OS disk                          │
│  │   ├─ Protected By: SEV-SNP key release gate              │
│  │   └─ Access: Only attested CVM can use                   │
│  │                                                           │
│  ├─→ Database Encryption Key Encryption Key (KEK)           │
│  │   ├─ Algorithm: AES-256                                  │
│  │   ├─ Usage: Wrap SQL Server DEK                          │
│  │   ├─ Location: Managed HSM or Key Vault                  │
│  │   └─ Azure SQL TDE: Transparent access via managed ID    │
│  │                                                           │
│  └─→ Application Session Keys                               │
│      ├─ Algorithm: ECDHE ephemeral keys                      │
│      ├─ Generation: During TLS handshake                     │
│      ├─ Lifetime: Duration of connection only               │
│      └─ Destruction: Automatically after disconnect         │
│                                                              │
│  Access Control: Managed Identity (mTLS auth)               │
│  ├─ Identity: {prefix}-cvm-identity (on CVM)                │
│  ├─ Role: Managed HSM Crypto User                           │
│  ├─ Permissions:                                            │
│  │  • Get (retrieve key/cert)                               │
│  │  • Sign (create signatures)                              │
│  │  • Wrap/Unwrap (protect keys)                            │
│  │  • GenerateKey (create new keys)                         │
│  └─ MFA: Attestation-gated (key release requires TEE proof) │
│                                                              │
│  Audit Logging: HSM Operation Log                           │
│  ├─ All key operations logged                               │
│  ├─ Timestamp: UTC with nanosecond precision                │
│  ├─ User: Managed Identity principal                        │
│  ├─ Operation: Get, Sign, Wrap, GenerateKey, etc.           │
│  └─ Sent to: Azure Monitor / Log Analytics                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 4. mTLS & Attestation-Based Certificate Flow

```
CITIZEN REGISTRY mTLS CERTIFICATE LIFECYCLE
═════════════════════════════════════════════════════════════

    PHASE 1: CVM Certificate Issuance
    ┌─────────────────────────────────────────┐
    │ Stage 2 Deployment (CVM Boot)           │
    │                                         │
    │ 1. CVM boots with Confidential OS       │
    │    ├─ OS measured (SHA256)              │
    │    ├─ App code measured                 │
    │    └─ Memory encrypted (SEV-SNP)        │
    │                                         │
    │ 2. CVM retrieves attestation token      │
    │    ├─ Source: Attestation Service       │
    │    ├─ Contains: VM measurements         │
    │    ├─ Signed: By Azure Attestation      │
    │    └─ Validation: Proves CVM integrity  │
    │                                         │
    │ 3. CVM requests certificate from HSM    │
    │    ├─ Request: CSR (Certificate Signing │
    │    ├─ Includes: Attestation token proof │
    │    ├─ Identity: Managed Identity auth   │
    │    └─ Protocol: mTLS to HSM             │
    │                                         │
    │ 4. Managed HSM validates attestation    │
    │    ├─ Verification: Token signature     │
    │    ├─ Check: App measurement against    │
    │    │         policy (if custom policy)  │
    │    ├─ Gate: Only issue cert if valid    │
    │    └─ Log: All certificate issuances    │
    │                                         │
    │ 5. HSM creates CVM certificate          │
    │    ├─ Signed by: HSM CA key             │
    │    ├─ Algorithm: RSA-2048 or EC         │
    │    ├─ Validity: 1 year (configurable)   │
    │    ├─ Subject: CN=sgall-citizen-cvm     │
    │    ├─ Extensions: KeyUsage, SAN         │
    │    └─ Delivery: Returned to CVM app     │
    │                                         │
    │ 6. CVM nginx installs certificate       │
    │    ├─ File: /etc/nginx/certs/cvm.crt    │
    │    ├─ Key: /etc/nginx/certs/cvm.key     │
    │    ├─ Config: mTLS listener on 443      │
    │    └─ Reload: nginx -s reload           │
    │                                         │
    └─────────────────────────────────────────┘
    
    PHASE 2: User Certificate Issuance
    ┌─────────────────────────────────────────┐
    │ User Preparation (Browser / CLI)        │
    │                                         │
    │ 1. User authenticates to Azure          │
    │    ├─ Method: Azure CLI or Portal       │
    │    ├─ MFA: Required by default          │
    │    └─ Token: JWT from Entra ID          │
    │                                         │
    │ 2. User requests attestation token      │
    │    ├─ Endpoint: Azure Attestation Srv   │
    │    ├─ Request: Attest endpoint          │
    │    ├─ Payload: Minimal (role claim)     │
    │    └─ Response: Attestation JWT         │
    │                                         │
    │ 3. User requests client certificate     │
    │    ├─ Endpoint: Managed HSM             │
    │    ├─ Includes: Attestation token       │
    │    ├─ CSR: Generated locally on device  │
    │    ├─ Public Key: Never sent to HSM     │
    │    └─ Auth: Managed Identity or Entra   │
    │                                         │
    │ 4. HSM validates user authorization     │
    │    ├─ Check: RBAC role (reader/writer)  │
    │    ├─ Check: Not in deny list           │
    │    ├─ Check: Attestation scope matches  │
    │    └─ Result: Approve or deny           │
    │                                         │
    │ 5. HSM signs user certificate           │
    │    ├─ CA: Citizen Registry CA           │
    │    ├─ Subject: CN=user@example.com      │
    │    ├─ Validity: 24 hours (short-lived)  │
    │    └─ Extensions: Group claims          │
    │                                         │
    │ 6. Certificate delivered to user        │
    │    ├─ Format: PEM or DER                │
    │    ├─ Storage: Browser keystore         │
    │    └─ Security: No private key exposure │
    │                                         │
    └─────────────────────────────────────────┘
    
    PHASE 3: mTLS Handshake (Connection)
    ┌─────────────────────────────────────────┐
    │ User Connects to CVM App                │
    │                                         │
    │ 1. User initiates HTTPS/TLS connection  │
    │    ├─ Endpoint: cvm-ip:443              │
    │    ├─ SNI: citizen-registry.local       │
    │    └─ Protocol: TLS 1.2/1.3             │
    │                                         │
    │ 2. TLS ClientHello                      │
    │    ├─ Supported Ciphers: AES-256-GCM    │
    │    ├─ Curves: P-256, P-384              │
    │    ├─ Signature Algorithms: ECDSA, RSA  │
    │    └─ Extensions: SNI, Supported Versions
    │                                         │
    │ 3. nginx responds with ServerHello      │
    │    ├─ Selected Cipher: TLS_AES_256_GCM  │
    │    ├─ Certificate: CVM cert (HSM-signed)│
    │    ├─ Extensions: Supported Versions    │
    │    └─ Signature: CVM cert chain         │
    │                                         │
    │ 4. Client verifies CVM certificate      │
    │    ├─ Issuer: HSM CA (trusted root)     │
    │    ├─ Validity: Valid dates             │
    │    ├─ Hostname: Matches certificate CN  │
    │    └─ Revocation: Checked (CRL/OCSP)    │
    │                                         │
    │ 5. Server requests client certificate   │
    │    ├─ CertificateRequest message        │
    │    ├─ Supported Types: X.509            │
    │    ├─ Issuer: Citizen Registry CA       │
    │    └─ Signature Algorithms: Any         │
    │                                         │
    │ 6. Client sends certificate             │
    │    ├─ Certificate: User cert (HSM-signed)
    │    ├─ Verification: Against policy      │
    │    ├─ Revocation: Checked               │
    │    └─ Thumbprint: Matched against ACL   │
    │                                         │
    │ 7. Server verifies user certificate     │
    │    ├─ Issuer: HSM CA (trusted)          │
    │    ├─ Validity: Valid dates             │
    │    ├─ Extensions: Read claims           │
    │    ├─ ACL Check: Cert in allow list     │
    │    └─ Role: Extracted from cert claims  │
    │                                         │
    │ 8. Key exchange (ECDHE)                 │
    │    ├─ Ephemeral Diffie-Hellman key      │
    │    ├─ Forward Secrecy: Enabled          │
    │    ├─ Shared Secret: Established        │
    │    └─ Session Keys: Derived from secret │
    │                                         │
    │ 9. Certificate Verify (client)          │
    │    ├─ Signature: Over handshake hash    │
    │    ├─ Key: Client private key           │
    │    ├─ Algorithm: ECDSA or RSA           │
    │    └─ Verification: Confirms ownership  │
    │                                         │
    │ 10. Finished messages (both parties)    │
    │     ├─ MAC over handshake transcript    │
    │     ├─ Encrypted: With session key      │
    │     ├─ Verification: Handshake integrity
    │     └─ Connection: Secure, ready for app
    │                                         │
    │ 11. Application data transfer           │
    │     ├─ All requests/responses encrypted │
    │     ├─ MAC/AEAD: Integrity verified     │
    │     ├─ Forward Secrecy: Ephemeral keys  │
    │     └─ Session: Lasts for connection    │
    │                                         │
    └─────────────────────────────────────────┘
```

### 5. Secrets & Credentials — What's Never Stored

```
❌ SECRETS NOT STORED ANYWHERE IN CODEBASE:
─────────────────────────────────────────

    Private Keys (.key files)
    ├─ Location: Never committed to git
    ├─ Reason: Would expose key material
    ├─ Actual Storage: Managed HSM
    └─ Rule: Gitignored (*.key pattern)

    TLS Certificates (.crt files)
    ├─ Location: Generated at deployment time
    ├─ Transport: Via HSM (never unencrypted)
    ├─ Actual Storage: nginx filesystem (protected by filesystem ACLs)
    └─ Rule: Not committed (*.crt in gitignore)

    Database Credentials
    ├─ Username: Built into environment variable
    ├─ Password: From Azure Key Vault (at runtime)
    ├─ Storage: Never in config files
    ├─ Rotation: Via Key Vault secret rotation
    └─ Rule: Environment vars only (never .env committed)

    Azure Service Principal Secrets
    ├─ Actual Mechanism: Managed Identity (no secrets needed)
    ├─ Method: IMDS token exchange (automatic)
    ├─ Benefit: No credentials to manage
    └─ Result: Zero secrets for Azure auth

    HSM Security Domain Backup
    ├─ Location: Local folder on admin machine (outside git)
    ├─ Encryption: Encrypted by HSM (not readable)
    ├─ Storage: Secure offline backup (not in repo)
    ├─ Rule: Gitignored (security-domain/ folder)
    └─ Protection: Access restricted to HSM admins

✅ WHAT'S SAFE TO COMMIT:
─────────────────────────

    Bicep Templates (.bicep)
    ├─ No secrets embedded
    ├─ Placeholder values for resource names
    ├─ Policy rules & constraints
    └─ Infrastructure-as-Code safe

    PowerShell Scripts (.ps1)
    ├─ Orchestration logic
    ├─ Resource deployment calls
    ├─ No embedded credentials
    └─ Safe for repo

    Python Application Code (.py)
    ├─ Flask endpoints
    ├─ Database logic
    ├─ Credential loading from environment
    ├─ Attestation validation code
    └─ Safe (secrets externalized)

    Docker Configuration
    ├─ Dockerfile: Safe
    ├─ nginx.conf: Safe (except cert paths)
    ├─ supervisord.conf: Safe
    └─ No secrets in images

    Documentation (.md)
    ├─ Architecture explanations
    ├─ Deployment guides
    ├─ No credential examples
    └─ Safe for public repo
```



## Quick Start

### Prerequisites

- **Azure CLI** (`az` command)
- **PowerShell 7+**
- **Bicep CLI** (`az bicep`)
- **Your prefix** (3-12 chars, e.g., `sgall`)
- **PIM elevation** (if required for your subscription)

### Step 1: Deploy Shared Infrastructure

```powershell
cd .\citizen-registry-advanced

# First time setup
.\Deploy-SharedInfra.ps1 -Prefix "sgall" `
  -Location "eastus" `
  -Deploy

# Output: Resource group "sgallsharedinfra" with Managed HSM
```

**Parameters:**
- `-Prefix` (required) — Naming prefix (3-12 chars)
- `-Location` — Azure region (default: `eastus`)
- `-Deploy` — Execute deployment
- `-ValidateOnly` — Validate templates without deploying

**What it does:**
1. Creates shared infrastructure RG
2. Provisions Managed HSM with private link
3. Initializes HSM security domain
4. Sets up private DNS zones
5. Exports shared resource IDs for Stage 2

### Step 2: Deploy App Instance

```powershell
# Deploy one or more app instances sharing the same HSM
.\Deploy-AppInstance.ps1 -Prefix "sgall" `
  -Location "eastus" `
  -SharedInfraRg "sgallsharedinfra" `
  -Deploy

# Output: Resource group "sgall12345app" (random 5-digit suffix)
#         Bastion accessible, CVM running citizen-registry
```

**Parameters:**
- `-Prefix` (required) — Naming prefix
- `-Location` — App instance region (default: `eastus`)
- `-SharedInfraRg` (required) — Shared infrastructure RG name
- `-Deploy` — Execute deployment
- `-ValidateOnly` — Validate templates
- `-CvmSize` — CVM SKU (default: `Standard_DC2as_v6`)

**What it does:**
1. Creates app instance RG
2. Provisions Confidential VM (C-vn2 TEE)
3. Installs citizen-registry app
4. Configures mTLS with Azure Attestation
5. Sets up Bastion for secure access
6. Establishes private link to shared Managed HSM
7. Seeds database with demo citizen records

### Step 3: Access the App via Bastion

```powershell
# Connect to Bastion (opens tunnel)
az network bastion ssh --resource-group sgall12345app `
  --bastion-name sgall12345bastion `
  --target-resource-id /subscriptions/...

# Or use native Bastion in Azure Portal
# Open: https://localhost:8443 (mTLS)
```

### Step 4: Verify mTLS + Attestation

```powershell
# From Bastion tunnel:
curl -v --cert citizen.crt --key citizen.key \
  https://citizen-registry-internal.local:8443/health

# Output shows:
# - Certificate issued by Azure Attestation Service
# - CVM enclave measurements validated
# - HSM key release verified
```

### Cleanup

```powershell
# Delete one app instance
.\Deploy-AppInstance.ps1 -Prefix "sgall" -Cleanup

# Delete all (app + shared infrastructure)
.\Deploy-SharedInfra.ps1 -Prefix "sgall" -Cleanup
```

## File Structure

```
citizen-registry-advanced/
├── README.md                          # This file
├── Deploy-SharedInfra.ps1            # Stage 1: Shared HSM + VNet
├── Deploy-AppInstance.ps1            # Stage 2: CVM + Bastion + App
├── .gitignore                         # Excludes certificates, keys, secrets
├── bicep/
│   ├── shared-infra.bicep            # Managed HSM + private link
│   ├── app-instance.bicep            # Confidential VM + networking
│   ├── attestation.bicep             # Azure Attestation Service
│   ├── bastion.bicep                 # Bastion host
│   └── parameters/
│       ├── shared-infra.json
│       └── app-instance.json
├── scripts/
│   ├── initialize-hsm.ps1            # HSM security domain init
│   ├── configure-mtls.ps1            # mTLS with attestation
│   ├── setup-bastion.ps1             # Bastion configuration
│   └── seed-database.ps1             # Demo data loading
├── app-instance/
│   ├── app-src/                      # Citizen registry app code
│   │   ├── Dockerfile                # Container for CVM
│   │   ├── requirements.txt
│   │   ├── app.py
│   │   └── nginx.conf
│   ├── nginx.conf                    # Reverse proxy config (mTLS)
│   └── supervisord.conf              # Process management
└── shared-infra/
    ├── certificates/                 # (gitignored) mTLS certs
    └── security-domain/              # (gitignored) HSM domain backup
```

## Security Considerations

### ✅ No GitHub Secrets

- Private keys (`.key`) — **gitignored**
- mTLS certificates — **gitignored**
- HSM security domain backups — **gitignored**
- Azure credentials — **never committed**

See `.gitignore` for complete exclusion list.

### ✅ Private Link Only

- Managed HSM — **no public IP**
- App CVM — **no public IP** (Bastion tunnels inbound)
- Database — **private subnet only**
- All inter-service TLS encrypted

### ✅ Confidential OS Disk Encryption

- CVM disk encrypted at rest (AES-256)
- Key stored in Managed HSM
- Confidential computing attestation proves disk protection

### ✅ Attestation-Backed mTLS

- Azure Attestation Service validates CVM enclave
- mTLS certificate signed by attestation service
- End-user connection verified against:
  - CVM hardware measurements
  - Confidential OS disk encryption state
  - Citizen-registry app hash

### ✅ Network Isolation & Segmentation

- **Bastion NSG:** Only allows authenticated users via Portal/CLI
- **App NSG:** Only allows SSH/RDP from Bastion; no direct internet
- **DB NSG:** Only allows SQL traffic from app subnet
- **Private Link NSG:** No NSG needed (Azure-managed)

### ✅ Zero Trust Authentication

- **User Access:** Azure Entra ID + MFA required for Bastion
- **App Authentication:** Managed Identity (no stored credentials)
- **HSM Authentication:** Managed Identity + Attestation token
- **Database Authentication:** SQL login (TLS-encrypted)

---

## 🌍 Data Residency & Compliance

### Geographic Data Residency

```
DEPLOYMENT: eastus (Default)
├─ Physical Location: Virginia, USA
├─ Data Residency: East US region
├─ Paired Region: West US (for geo-redundancy)
└─ Alternative Regions: Replace in deployment script

DATA LOCATION GUARANTEES:
├─ App Data: Stored on ACC in deployment region
├─ Managed HSM: Deployed in specified region
├─ Database: SQL Server on ACC (same region)
├─ Backups: Can be geo-replicated via SQL settings
└─ Result: All data stays within chosen region
```

### Compliance Frameworks

```
SUPPORTED COMPLIANCE CERTIFICATIONS
└─ Azure Confidential Computing

   ✓ ISO/IEC 27001 (Information Security)
   ├─ Managed HSM: Certified
   ├─ Confidential VM: Included in Azure scope
   └─ Database: Standard SQL Server compliance

   ✓ SOC 2 Type II
   ├─ Azure Platform: Compliant
   ├─ Physical Security: Data center hardened
   └─ Operational Controls: Audit logging enabled

   ✓ HIPAA (Health Data)
   ├─ Encryption: At-rest + in-transit
   ├─ Access Control: RBAC + ABAC (via attestation)
   ├─ Audit Logs: Automatic to Log Analytics
   └─ Note: HIPAA BAA required from Microsoft

   ✓ GDPR (Personal Data)
   ├─ Data Subject Rights: Implement in app logic
   ├─ Right to Deletion: Add cascade delete to schema
   ├─ Data Portability: Export via app API
   ├─ Encryption: Mandatory (implemented)
   └─ Data Protection Officer: Required (your org)

   ✓ NIST Cybersecurity Framework
   ├─ Identify: Managed HSM asset inventory
   ├─ Protect: TLS + mTLS + OS encryption
   ├─ Detect: Azure Monitor + Audit logs
   ├─ Respond: Alert rules + automation
   └─ Recover: Backup & disaster recovery

   ✓ FIPS 140-2 (Cryptographic Standards)
   ├─ Managed HSM: FIPS 140-2 Level 3 certified
   ├─ TLS: FIPS-approved ciphers (AES-256)
   ├─ Database TDE: FIPS 140-2 encryption
   └─ Note: HSM itself is FIPS Level 3 hardware
```

### Audit & Logging

```
COMPREHENSIVE AUDIT TRAIL
═════════════════════════════════════════════════════════════

Resource: Managed HSM
├─ Log Destination: Azure Monitor / Log Analytics
├─ Events Logged:
│  ├─ Key operations (Get, Sign, Wrap, GenerateKey)
│  ├─ Certificate issuances
│  ├─ Failed access attempts
│  ├─ Policy changes
│  └─ Security domain operations
├─ Retention: 30+ days (configurable)
└─ Query: Azure Monitor KQL

Resource: Confidential VM
├─ Audit Sources:
│  ├─ OS logs: /var/log/auth.log, /var/log/syslog
│  ├─ App logs: /var/log/citizen-registry/app.log
│  ├─ Nginx logs: /var/log/nginx/{access,error}.log
│  └─ Supervisor: /var/log/supervisor/supervisord.log
├─ Log Forwarding: To Log Analytics workspace
└─ Analysis: KQL queries for forensics

Resource: Database
├─ SQL Audit Logging:
│  ├─ Connection events
│  ├─ Query execution (configurable)
│  ├─ Schema changes
│  └─ Failed access attempts
├─ Destination: Storage account (archived)
└─ Retention: 30+ days

Resource: Azure Attestation Service
├─ Attestation Token Audit:
│  ├─ Token issuances (timestamp, claims)
│  ├─ Verification requests
│  ├─ Policy evaluations
│  └─ Claim validations
├─ Logged Events: All by default
└─ Destination: Activity Log → Log Analytics

SEARCHING AUDIT LOGS (Example KQL Queries)
═════════════════════════════════════════════════════════════

// All HSM key operations (last 24 hours)
AzureDiagnostics
| where ResourceType == "MANAGED_HSM"
| where OperationName contains "Key"
| where TimeGenerated > ago(24h)
| summarize Count=count() by OperationName, Identity

// Failed authentication attempts on app
SecurityEvent
| where Computer contains "sgall-citizen-cvm"
| where EventID == 4625  // Failed logon
| summarize Count=count() by Account, IpAddress
| order by Count desc

// Certificate operations in HSM
AzureDiagnostics
| where ResourceType == "MANAGED_HSM"
| where OperationName contains "certificate"
| extend Result = case(StatusCode == "Success", "Granted", "Denied")
| summarize Count=count() by Result, Identity, TimeGenerated
```

---

## ✅ Verification & Security Validation

### Pre-Deployment Checklist

```powershell
# 1. Verify Azure CLI login
az account show --output table

# 2. Check Bicep template syntax
az bicep build --file bicep/shared-infra.bicep --output-format json
az bicep build --file bicep/app-instance.bicep --output-format json

# 3. Validate resource naming conventions
$Prefix = "sgall"  # Must be 3-12 chars
if ($Prefix.Length -lt 3 -or $Prefix.Length -gt 12) {
    Write-Error "Prefix must be 3-12 characters"
}

# 4. Check CVM quota availability
az vm list-usage --location eastus `
  --query "[?name.value=='Standard_DC2as_v6']" `
  --output table

# 5. Verify Managed HSM quota
az vm list-usage --location eastus `
  --query "[?name.value=='Standard_B1']" `
  --output table
```

### Post-Deployment Validation

```powershell
# 1. Verify Managed HSM is reachable
az keyvault show --name "{hsmName}" --resource-group "{sharedInfraRg}"

# 2. Check Private Link connectivity
az network private-endpoint show `
  --name "{prefix}-mhsm-pe" `
  --resource-group "{sharedInfraRg}" `
  --output table

# 3. Verify CVM is in confidential state
az vm show --resource-group "{appRg}" `
  --name "sgall-citizen-cvm" `
  --query "securityProfile.securityType" `
  --output tsv
# Expected: ConfidentialVM

# 4. Check Bastion connectivity
az network bastion show --name "{bastionName}" `
  --resource-group "{appRg}" --output table

# 5. Verify mTLS certificates exist
ssh -p 2222 azureuser@localhost -i ~/.ssh/id_rsa
  # Once connected:
  ls -la /etc/nginx/certs/cvm.*
  curl -v -k https://localhost/health
```

### Runtime Security Checks

```bash
# From CVM (via Bastion):

# 1. Verify SEV-SNP is active
dmesg | grep -i sev

# 2. Check OS disk encryption
df -h | grep -E "mapper|sda"

# 3. Verify Managed Identity is working
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-12-01&resource=https://management.azure.com/" -H "Metadata:true" | jq '.access_token' | wc -c

# 4. Test database connectivity
/opt/mssql-tools/bin/sqlcmd -S 10.0.4.5 -U sqladmin -P [password] -Q "SELECT @@VERSION"

# 5. Check HSM connectivity (requires certificate)
curl -v --cert citizen.crt --key citizen.key \
  https://mhsm.azure.net/keys/citizen-registry-key/versions \
  --resolve mhsm.azure.net:443:10.0.1.x

# 6. Validate mTLS with client certificate
curl -v --cert /path/to/client.crt --key /path/to/client.key \
  https://localhost:443/health
```

### Attestation Verification

```powershell
# 1. Get attestation token from CVM
$AttestationUri = "https://{attestationProvider}.eus.attest.azure.net"
$AttestationToken = Invoke-WebRequest -Uri "$AttestationUri/attest" `
  -Method Post -Body '{}' | Select-Object -ExpandProperty Content

# 2. Decode and verify token claims
$Claims = $AttestationToken | ConvertFrom-Json
Write-Output $Claims | Select-Object -ExpandProperty claims

# Expected claims:
# - "is-debuggable": false
# - "vm-configuration": {...}  # Hardware measurements
# - "exp": [future timestamp]  # Expiration
# - "iss": "https://sharedeus.eus.attest.azure.net"  # Issuer

# 3. Verify certificate was issued by attestation service
openssl x509 -in /etc/nginx/certs/cvm.crt -text -noout | grep -A2 "Issuer:"
# Expected: Issuer: CN=Citizen Registry Attestation CA
```

---

## Cost Optimization

> **Note:** See [⚠️ IMPORTANT: Managed HSM Requirement & Cost Warning](#-important-managed-hsm-requirement--cost-warning) at the top of this README for detailed cost breakdown and optimization strategies.

### Detailed Pricing Breakdown

**Managed HSM (B1 SKU) — $400/month (Fixed)**
- **Cost Type:** Hourly reservation (not consumption-based)
- **Shared Infrastructure Cost:** One HSM shared across all app instances
- **Optimization:** Deploy 3-5 app instances to amortize cost
- **Minimum Commitment:** Must have cost control tag (subscription policy)
- **Region Variation:** Prices vary by Azure region (~$400 in eastus)

**Confidential VM — ~$220/month per instance**
- **SKU Options:**
  - DC1as_v6 (1 vCPU, 4 GB): ~$110/month (budget option)
  - DC2as_v6 (2 vCPU, 8 GB): ~$220/month (recommended)
  - DC4as_v6 (4 vCPU, 16 GB): ~$440/month (production)
- **Includes:** Confidential OS disk, SEV-SNP TEE, managed identity
- **Additional:** Premium storage ~$30/month (OS + data disks)

**Database on ACC — ~$30/month (SQL Server)**
- **Size:** 10 GB default (configurable)
- **Encryption:** TDE enabled at no additional cost
- **Backups:** Included (geo-redundant)
- **Growth:** ~$3 per additional 10 GB/month

**Bastion Host — ~$50/month**
- **SKU:** Standard (2 scale units, sufficient for dev/test)
- **Optimization:** Reduce to 1 scale unit (~$25/month) if low usage
- **Monitoring:** No metered charges, only hosting

**Azure Attestation Service — ~$3-10/month**
- **Pricing:** $0.01 per 1,000 requests
- **Typical Usage:** 10-100 attestation tokens/day
- **Negligible Cost:** Often free tier for testing

**Network & Storage — ~$60/month**
- **VNet Peering:** Free within region
- **Private Link:** Free (part of VNet)
- **Premium SSD Storage:** 128 GB default = ~$30/month
- **Data Transfer:** No egress charges (private VNet)

### Total Cost Examples

```
SCENARIO 1: Single App Instance (Development)
─────────────────────────────────────────────
  HSM (shared)               $400
  CVM (DC2as_v6)             $220
  Database                    $30
  Bastion (2 units)           $50
  Storage & Network           $60
  Attestation                  $3
  ─────────────────────────────────
  MONTHLY TOTAL:             $763
  DAILY COST:              $25.43
  HOURLY COST:             $1.06

SCENARIO 2: Multiple App Instances (Cost Sharing)
──────────────────────────────────────────────────
  Deployment: 3 app instances sharing 1 HSM
  
  HSM (shared by 3)          $133  per app
  CVM × 3 (each)             $220  per app
  Database × 3               $30   per app
  Bastion × 3                $50   per app
  Storage & Network × 3      $60   per app
  Attestation × 3             $3   per app
  ─────────────────────────────────────
  PER APP MONTHLY:           $496
  PER APP DAILY:           $16.53
  PER APP HOURLY:           $0.69

SCENARIO 3: Production with Reserved Instances
───────────────────────────────────────────────
  (Assuming 1-year reserved instance discount: 20%)
  
  HSM (no discount)          $400
  CVM (DC2as_v6, -20%)       $176
  Database (-15%)             $26
  Bastion (-15%)              $43
  ─────────────────────────────────
  MONTHLY TOTAL:             $645
  DAILY COST:              $21.50
  Annual Savings:           ~$1,416

SCENARIO 4: Budget Option (Minimal Resources)
──────────────────────────────────────────────
  HSM (shared by 5 apps)     $80   per app
  CVM (DC1as_v6)             $110  per app
  Database (5 GB)            $15   per app
  Bastion (1 unit, shared)   $10   per app
  Storage (64 GB)            $30   per app
  ─────────────────────────────────
  MONTHLY TOTAL:             $245
  DAILY COST:              $8.17
```

### Cost-Saving Actions (Ranked by Impact)

| Action | Savings | Effort | Complexity |
|--------|---------|--------|-----------|
| Share HSM across 5 apps | **$280/app** | Moderate | Medium |
| Use DC1as_v6 instead of DC2as_v6 | **$110/month** | 1 param change | Low |
| Reduce Bastion from 2 to 1 scale unit | **$25/month** | 1 param change | Low |
| Deploy on-demand (delete when not used) | **Up to 90%** | 5 mins to redeploy | Low |
| Reserve instances (1-year commitment) | **20-30% discount** | Setup once | Medium |
| Use different region (if available) | **5-15%** | Full redeploy | Medium |
| Consolidate databases on one SQL instance | **$15/app** | Schema changes | High |

### Cost Monitoring

```powershell
# Check current HSM spend (last 7 days)
az cost management query create `
  --scope "/subscriptions/{subscriptionId}" `
  --time-period from:2026-08-21 to:2026-08-28 `
  --granularity Daily `
  --filter "tolower(resourceType) eq 'microsoft.keyvault/managedhsms'" `
  --metrics ActualCost

# List all resources and their tags (for cost allocation)
az resource list --output table `
  --query "[].{Name:name, Type:type, ResourceGroup:resourceGroup, Tags:tags}"

# Set up billing alert (optional)
az monitor metrics alert create `
  --name HSMCostAlert `
  --resource-group {resourceGroup} `
  --scopes /subscriptions/{subId} `
  --condition "avg Billing > 500"
```

**Total Demo Cost:** ~$25/day for 1 app instance | ~$16/day with 3 shared instances | ~$8/day with budget config

## Next Steps

1. **Deploy Stage 1:**
   ```powershell
   .\Deploy-SharedInfra.ps1 -Prefix "sgall" -Deploy
   ```

2. **Deploy Stage 2:**
   ```powershell
   .\Deploy-AppInstance.ps1 -Prefix "sgall" `
     -SharedInfraRg "sgallsharedinfra" `
     -Deploy
   ```

3. **Access via Bastion** (see Step 3 above)

4. **Validate mTLS + Attestation** (see Step 4 above)

## Troubleshooting

### Managed HSM Creation Fails with "Not Authorized"

- Ensure cost control tag is present in the Bicep template
- Tag: `costControl: confidential-computing`
- Check subscription quota for Managed HSM in target region

### CVM Fails to Boot with "Disk Encryption"

- Verify Managed HSM key URI is valid
- Ensure CVM managed identity has HSM key wrap/unwrap permissions
- Check Bicep `keyEncryptionKey` parameter

### Bastion Connection Timeout

- Verify NSG rule allows Bastion inbound on port 3389/22
- Check Bastion subnet contains `Microsoft.Bastion/bastionHosts`
- Ensure CVM network interface is in the correct subnet

### mTLS Certificate Validation Fails

- Run: `az attestation policy list --resource-group {appRg}`
- Compare with expected app measurements
- Re-run `configure-mtls.ps1` to refresh certificates

---

**Questions?** Refer to the deployment scripts or Azure documentation on Confidential Computing, Managed HSM, and Azure Attestation Service.
