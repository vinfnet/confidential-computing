# hello-world-aci — the smallest end-to-end CI/CD to Confidential ACI

A **minimal, self-contained Azure DevOps deployment project** that takes a tiny
dependency-free hello-world web app all the way from **code check-in → build →
deploy** to an **AMD SEV-SNP Confidential Azure Container Instance**, with every
step running **inside a self-hosted Azure DevOps Server** on the dockerless
**confidential build runners** (`confidential-build-pool`).

It is the trimmed-down sibling of
[`sample-app-deployment`](../sample-app-deployment/README.md): same CI/CD shape,
but the app is a ~60-line Python standard-library HTTP server so the moving
parts are as small as possible.

## Flow

```
 git push (main)                Azure DevOps Server (on a CVM)
      │                        ┌───────────────────────────────┐
      ▼                        │  Pipeline: hello-world-aci      │
 ADO Git repo  ── trigger ───▶ │  pool: confidential-build-pool  │
 hello-world-                  │  agent: confidential ACI (MI)   │
 aci                           └──────────────┬────────────────┘
                                              │ az login --identity
                        ┌─────────────────────┼─────────────────────┐
                        ▼                     ▼                     ▼
                 az acr build         az confcom acipolicygen   az deployment
                 (server-side)        (CCE policy, dockerless)  group create
                        │                     │                     │
                        ▼                     ▼                     ▼
                 ACR image             HOST_DATA = policy hash   Confidential
                 :$(BuildId)           bound into the guest      ACI (SEV-SNP)
```

## Repo layout (self-contained)

| Path | Purpose |
|------|---------|
| `azure-pipelines.yml` | Build + deploy pipeline (build server-side, then confcom + confidential ACI deploy). |
| `app/Dockerfile` | Tiny `python:3.12-slim` image, no pip packages. |
| `app/server.py` | ~60-line stdlib HTTP server; serves a hello page + `/healthz`. |
| `deploy/aci-hello-world-confidential.json` | Confidential-SKU ACI ARM template; `ccePolicy` filled by `confcom` at deploy time. |

## Target environment

The pipeline `variables` point at the live confidential-computing footprint:

- Subscription `68432aaa-6eba-435c-bc7c-1d998d835e80`
- Resource group `sgallhyglz`, location `westus2`
- ACR `sgallacr74016` (fill `acrName` in `azure-pipelines.yml`)
- Agent pool `confidential-build-pool` (self-hosted, confidential ACI agents)

## Authentication — the one prerequisite before a fully agent-driven run

There is **no ARM service connection** (service-principal creation is blocked in
the target tenant). The pipeline authenticates to Azure with the **build agent's
user-assigned managed identity** (`az login --identity --client-id <miClientId>`).

The confidential ACI agents in `confidential-build-pool` are deployed by
[`Build-ConfidentialAciAdoAgent.ps1`](../../Build-ConfidentialAciAdoAgent.ps1).
To let the pipeline deploy Azure resources, the agents need a user-assigned
managed identity attached, and that identity needs:

- **AcrPush** on the registry (`az acr build`), and
- **Contributor** scoped to the resource group (`az deployment group create`
  for the container group).

Attach the MI by redeploying the agents with the script's
`-UserAssignedIdentityResourceId` parameter, then set `miClientId` (and
`acrName`) in `azure-pipelines.yml`.

> Until an MI is attached, the build/deploy steps that call `az login --identity`
> cannot authenticate. The exact commands the pipeline runs were verified
> out-of-band with a Contributor user identity; the resulting confidential ACI
> served the hello-world page over HTTP 200 on genuine SEV-SNP hardware.

## Why Confidential

The `Confidential` SKU deploys on AMD SEV-SNP, and `az confcom acipolicygen`
generates a per-image CCE policy (with `--disable-stdio` and no `exec_processes`)
that is bound to the guest as `HOST_DATA`. As a result, `az container exec` into
the running container is **denied by policy** — the same enforcement the
confidential build agents themselves rely on.

## Port 8080 (not 80)

The container runs as an **unprivileged user** (`USER 1000:1000` in the
Dockerfile). On Linux a non-root process **cannot bind privileged ports (< 1024)**,
so the app listens on **8080** — set consistently in `app/server.py` (`PORT`
default), `app/Dockerfile` (`EXPOSE`), and the ARM template (both the container
port and the public `ipAddress` port). ACI does **no port remapping**, so the
container port *is* the public port. Binding 80 as non-root makes the container
crash-loop and the ACI HTTP frontend returns `500` on every path (including
`/healthz`); `az container logs` is empty because the CCE policy disables stdio.

## Verify a running deployment

```powershell
$fqdn = az container show -g sgallhyglz -n <containerGroupName> `
  --query "ipAddress.fqdn" -o tsv
curl.exe "http://$fqdn:8080/healthz"        # -> ok  (HTTP 200)
curl.exe "http://$fqdn:8080/"               # -> hello page, echoes ACI SKU = Confidential
# exec is refused by the CCE policy on genuine SEV-SNP hardware:
az container exec -g sgallhyglz -n <containerGroupName> `
  --container-name hello-world --exec-command id   # -> "exec ... denied due to policy"
```
