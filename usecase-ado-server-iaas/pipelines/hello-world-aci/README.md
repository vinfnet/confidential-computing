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
| `Create-HelloWorldPipeline.ps1` | Helper that creates the YAML pipeline definition on the ADO Server (bound to `confidential-build-pool`) and optionally queues a run. Runs on the server via `az vm run-command`. |

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
`acrName`) in `azure-pipelines.yml`. The concrete commands are in
[Set up the demo from scratch](#set-up-the-demo-from-scratch) below.

> Until an MI is attached, the build/deploy steps that call `az login --identity`
> cannot authenticate.

## Set up the demo from scratch

This walks the whole demo end-to-end: from a bare subscription to a queued
pipeline run that builds and deploys the confidential ACI **on the confidential
build agents themselves**. Steps 1–4 stand up the private ADO Server, pool, and
confidential runners (documented in the [parent README](../../README.md)); steps
5–8 are specific to this pipeline.

Because the ADO Server has **no public IP**, every server-side action is issued
with `az vm run-command` (which runs as `localhost` on the server) or over an
**Azure Bastion tunnel**. Set your PAT once per shell session — it does **not**
persist across terminal sessions:

```powershell
$env:AZP_TOKEN = '<your-ADO-Server-PAT>'
```

### Prerequisites

- Azure CLI, logged in (`az login`), with the target subscription selected.
- **Owner** (or Contributor **plus** `Microsoft.Authorization/roleAssignments/write`)
  on the resource group — needed to create the managed identity and assign roles.
- The variables in `azure-pipelines.yml` reflect your footprint (subscription,
  `resourceGroup`, `location`, `acrName`).

### Step 1–4 — Private ADO Server, agent pool, and confidential runners

Follow the [parent README](../../README.md) to run, in order:

1. [`Build-AdoServerCvm.ps1`](../../Build-AdoServerCvm.ps1) — CVM, VNet, subnets,
   NAT gateway, Bastion.
2. Install Azure DevOps Server on the CVM and create the `DefaultCollection`.
3. [`enable-ado-https.ps1`](../../enable-ado-https.ps1) — bind HTTPS on the server.
4. [`create-ado-pool.ps1`](../../create-ado-pool.ps1) — create the
   `confidential-build-pool` agent pool (this demo assumes `PoolId=2`).

You also need an **ADO Server PAT** for the automation. PATs on ADO Server can
only be minted from the browser web UI over an RDP/Bastion session (programmatic
creation is blocked over Windows/NTLM auth). Create one with these scopes:

| Capability | Scope | Access |
|------------|-------|--------|
| Register/see agents in the pool | **Agent Pools** | Read & manage |
| Create + push the git repo | **Code** | Read & write |
| Create the pipeline + queue a run | **Build** | Read & execute |
| Create the team project (only if it doesn't exist yet) | **Project and Team** | Read, write & manage |

### Step 5 — Create the user-assigned managed identity and grant roles

```powershell
$rg   = 'sgallhyglz'
$acr  = 'sgallacr74016'
$sub  = '68432aaa-6eba-435c-bc7c-1d998d835e80'
$miName = 'sgall-caci-pipeline-mi'

# Create the identity
$mi = az identity create -g $rg -n $miName -o json | ConvertFrom-Json

# AcrPush on the registry (for `az acr build`)
$acrId = az acr show -n $acr -g $rg --query id -o tsv
az role assignment create --assignee-object-id $mi.principalId --assignee-principal-type ServicePrincipal `
  --role AcrPush --scope $acrId

# Contributor on the resource group (for `az deployment group create`)
az role assignment create --assignee-object-id $mi.principalId --assignee-principal-type ServicePrincipal `
  --role Contributor --scope "/subscriptions/$sub/resourceGroups/$rg"

"MI clientId  = $($mi.clientId)"       # -> put this in azure-pipelines.yml (miClientId)
"MI resource  = $($mi.id)"             # -> pass to the agent redeploy below
```

### Step 6 — Attach the MI to the confidential runners (redeploy)

Redeploy the agents with `-UserAssignedIdentityResourceId` so each confidential
ACI runner carries the identity. Run from `usecase-ado-server-iaas/`:

```powershell
.\Build-ConfidentialAciAdoAgent.ps1 `
  -SubscriptionId $sub `
  -ResourceGroupName $rg `
  -Prefix sgall `
  -AzpUrl 'https://10.0.0.4/DefaultCollection' `
  -AzpPool confidential-build-pool `
  -AzpToken $env:AZP_TOKEN `
  -AgentCount 2 `
  -Location westus2 `
  -VnetName sgallhyglzvnet `
  -AcrName $acr `
  -UserAssignedIdentityResourceId $mi.id
```

The script rebuilds the agent image, regenerates a restrictive CCE policy,
redeploys both agents, and asserts they are **Confidential SKU with `exec`
blocked**. Confirm the identity is attached and the agents are online:

```powershell
az container show -g $rg -n sgall-caci-agent-1 `
  --query "identity.userAssignedIdentities" -o jsonc     # -> shows the MI

# Agent registration (runs on the server; PoolId=2):
az vm run-command invoke -g $rg -n sgallhyglz --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/check-ado-agents.ps1" `
  --parameters "PoolId=2" "Pat=$env:AZP_TOKEN" --query "value[0].message" -o tsv
```

### Step 7 — Point the pipeline at your MI and registry

Edit [`azure-pipelines.yml`](azure-pipelines.yml) `variables` so `miClientId`
matches the identity from Step 5 and `acrName`/`resourceGroup`/`subscriptionId`/
`location` match your footprint. Commit and push to your source control.

### Step 8 — Create the ADO project, repo, pipeline, and queue a run

The pipeline needs to live in a git repo **on the ADO Server**, bound to the
`confidential-build-pool`.

**8a. Project + repo.** If they don't already exist, create a team project (via
the web UI over Bastion, or the REST API with the *Project and Team* scope). This
demo uses project **`Confidential-IaaS-ADO`** with a repo of the same name.

**8b. Push the pipeline into the server repo.** Open a Bastion tunnel to the
server's HTTPS port, then push the `hello-world-aci` folder to the repo root so
`azure-pipelines.yml` sits at the repo root:

```powershell
# In one shell: tunnel localhost:8443 -> ADO Server :443 over Bastion
az network bastion tunnel --name <bastionName> -g $rg `
  --target-resource-id $(az vm show -g $rg -n sgallhyglz --query id -o tsv) `
  --resource-port 443 --port 8443

# In another shell: push just this folder as the repo root
$src = 'usecase-ado-server-iaas/pipelines/hello-world-aci'
$tmp = Join-Path $env:TEMP 'hello-world-aci-seed'
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item $src $tmp -Recurse
Push-Location $tmp
git init -b main
git add .
git -c user.email=demo@local -c user.name=demo commit -m 'hello-world-aci pipeline'
$remote = "https://user:$env:AZP_TOKEN@localhost:8443/DefaultCollection/Confidential-IaaS-ADO/_git/Confidential-IaaS-ADO"
git -c http.sslVerify=false push $remote main
Pop-Location
```

> The self-signed server cert makes `git` reject TLS; `-c http.sslVerify=false`
> is acceptable for this private, tunneled demo only.

**8c. Create the pipeline definition and queue a run.** Use the helper script,
which runs on the server and talks to `localhost`:

```powershell
az vm run-command invoke -g $rg -n sgallhyglz --command-id RunPowerShellScript `
  --scripts "@usecase-ado-server-iaas/pipelines/hello-world-aci/Create-HelloWorldPipeline.ps1" `
  --parameters "Pat=$env:AZP_TOKEN" "Project=Confidential-IaaS-ADO" `
               "RepoName=Confidential-IaaS-ADO" "Pool=confidential-build-pool" `
               "YamlPath=azure-pipelines.yml" "Queue=true" `
  --query "value[0].message" -o tsv
```

It resolves the repo id and the `confidential-build-pool` agent-queue id, creates
a YAML pipeline definition named `hello-world-aci` bound to that queue, and (with
`Queue=true`) queues a build — printing `BUILD-QUEUED id=... number=...`. Every
subsequent push to `main` triggers the pipeline automatically.

The queued build runs on a confidential ACI agent: it `az login --identity`s with
the attached MI, runs `az acr build`, generates the CCE policy with
`az confcom acipolicygen`, and deploys the confidential ACI — all on SEV-SNP
hardware. Verify the result with the [commands below](#verify-a-running-deployment).

> **Verified end-to-end.** A live run on the confidential runners built the image
> server-side with `az acr build` (managed-identity login), generated the CCE
> policy dockerlessly (see [below](#dockerless-cce-policy-generation)), and
> deployed a running SEV-SNP ACI that returns `HTTP 200` on `:8080` and refuses
> `az container exec` by policy.

> **Rotate the demo PAT** when finished — a PAT used in `az vm run-command`
> parameters and `git` remotes ends up in shell history and, for the agent PAT,
> in the agent's CCE-policy `env_rules`.

## Why Confidential

The `Confidential` SKU deploys on AMD SEV-SNP, and `az confcom acipolicygen`
generates a per-image CCE policy (with `--disable-stdio` and no `exec_processes`)
that is bound to the guest as `HOST_DATA`. As a result, `az container exec` into
the running container is **denied by policy** — the same enforcement the
confidential build agents themselves rely on.

## Dockerless CCE policy generation

The confidential build agents are **sealed and dockerless** — there is no Docker
daemon on them (that is precisely what makes them confidential). But for a Linux
ACI, `az confcom acipolicygen` reads the image's layers from either a running
Docker daemon or a **local image tarball** (`--tar`); it does *not* pull from a
remote registry itself, and `--containerd-pull` is AKS-only.

So the deploy step pulls the freshly built image into a tarball with
[`crane`](https://github.com/google/go-containerregistry) — a single static,
dockerless binary — and feeds that to `acipolicygen`:

```bash
# crane is downloaded to the agent temp dir; it reads ~/.docker/config.json for auth
crane pull --format=tarball "$IMAGE" image.tar
az confcom acipolicygen -a template.json --parameters params.json \
  --tar image.tar --disable-stdio --approve-wildcards
```

The image itself is still built by `az acr build` (which runs the build
*server-side* in ACR, so the agent never needs Docker for the build either).

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
