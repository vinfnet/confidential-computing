# sample-app-deployment — end-to-end CI/CD to Confidential ACI

A **simple, self-contained Azure DevOps deployment project** that takes the
[`aci-samples/visual-attestation-demo-v2`](../../../aci-samples/visual-attestation-demo-v2/README.md)
app all the way from **code check-in → build → deploy** to an **AMD SEV-SNP
Confidential Azure Container Instance**, with every step running **inside a
self-hosted Azure DevOps Server** on the dockerless **confidential build
runners** (`confidential-build-pool`).

This is the live counterpart of the sibling
[`visual-attestation-demo`](../visual-attestation-demo/README.md) scaffold. The
difference: this project is wired into a **real ADO project** (`sample-app-deployment`)
and uses the build agent's **managed identity** (`az login --identity`) instead
of an ARM service connection, because service-principal creation is blocked in
the target tenant.

## Flow

```
 git push (main)                Azure DevOps Server (on a CVM)
      │                        ┌───────────────────────────────┐
      ▼                        │  Pipeline: sample-app-deployment │
 ADO Git repo  ── trigger ───▶ │  pool: confidential-build-pool  │
 sample-app-                   │  agent: confidential ACI (MI)   │
 deployment                    └──────────────┬────────────────┘
                                              │ az login --identity
                        ┌─────────────────────┼─────────────────────┐
                        ▼                     ▼                     ▼
                 az acr build         az confcom acipolicygen   az deployment
                 (server-side)        (CCE policy, dockerless)  group create
                        │                     │                     │
                        ▼                     ▼                     ▼
                 ACR: cc-attest        HOST_DATA = policy hash   Confidential
                 :$(BuildId)           bound into the guest      ACI (SEV-SNP)
                                                                 → attests to MAA
```

## Authentication model

There is **no ARM service connection**. The confidential ACI build agent has a
**user-assigned managed identity** attached. Every pipeline step runs
`az login --identity --client-id <miClientId>`. The MI holds a **least-privilege
custom role** — `ACI Pipeline Deployer` — scoped to the resource group, granting
only what the pipeline needs:

- `Microsoft.ContainerRegistry/registries/scheduleRun/action` + read +
  `listBuildSourceUploadUrl` + `listCredentials` (for `az acr build` and image
  pull creds), and
- `Microsoft.Resources/deployments/*` + `Microsoft.ContainerInstance/containerGroups/*`
  (to deploy the ACI container group).

## Repo layout (self-contained)

| Path | Purpose |
|------|---------|
| `azure-pipelines.yml` | Build + deploy pipeline; `aciSku` parameter picks Standard or Confidential. |
| `app/` | Snapshot of the visual-attestation-demo-v2 image source (Dockerfile + Flask app). |
| `deploy/aci-visual-attestation.json` | Standard-SKU ACI ARM template (attestation fails by design). |
| `deploy/aci-visual-attestation-confidential.json` | Confidential-SKU ACI ARM template; `ccePolicy` filled by `confcom` at deploy time. |

## Queue-time parameter

- **`aciSku`** (default `Confidential`) — `Confidential` generates a CCE policy
  and deploys on AMD SEV-SNP so the app's **Attest** button returns a live MAA
  SEV-SNP token; `Standard` deploys plain ACI where attestation fails by design
  (the educational contrast).
