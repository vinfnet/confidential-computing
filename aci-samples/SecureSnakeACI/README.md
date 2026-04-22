# Secure Snake ACI

A deliberately simple browser-based Snake game that demonstrates how to run an ordinary containerized web app on **Azure Confidential ACI** with a hardened `confcom` policy and a live attestation page.

> This is intentionally a trivial example. The game is just a lightweight stand-in to show that you can package and deploy essentially **any** suitable containerized app onto Confidential ACI using the same pattern.

## What this sample demonstrates

- deploying to **Confidential** Azure Container Instances
- pinning the workload to an immutable container image digest
- generating a **CCE policy** with `az confcom acipolicygen`
- disabling interactive stdio access in the policy
- surfacing live attestation evidence from inside the running container

## Files

- `app.py` - Flask app that serves the game and attestation UI
- `Dockerfile` - container image definition
- `requirements.txt` - Python dependencies
- `supervisord.conf` - runs both the app and the attestation helper
- `deployment-template.json` - ARM template used as input to `confcom`
- `Deploy-SecureSnakeACI.ps1` - repeatable deployment script

## Security posture

This sample is simple, but the deployment path is materially hardened:

- **Confidential-only target** via `sku: Confidential`
- **Exact image pinning** using the pushed ACR image digest
- **`confcom`-generated CCE policy** injected into the deployment template
- **No interactive stdio** in the generated policy
- **Reduced policy surface** by excluding unused default fragments
- **Live attestation** at `/attestation`, including raw evidence and MAA token flow

If the image or runtime shape changes, the attestation evidence changes as well.

## App endpoints

- `/` - Snake game UI
- `/attestation` - attestation and security evidence page
- `/health` - health probe
- `/api/scenario` - sample metadata
- `/api/security` - runtime security summary

## Prerequisites

- Azure PowerShell authenticated with `Connect-AzAccount`
- Azure CLI installed
- Docker Engine running locally

The deployment script will install the Azure CLI `confcom` extension if needed.

## Deploy from PowerShell

```powershell
Connect-AzAccount
.\Deploy-SecureSnakeACI.ps1 -SubscriptionId <SUBSCRIPTION_ID> -Region eastus
```

To reuse the same deployment name across runs:

```powershell
.\Deploy-SecureSnakeACI.ps1 -SubscriptionId <SUBSCRIPTION_ID> -Region eastus -DeploymentName sgall-secure-snake-demo
```

The script builds the image in ACR, resolves the immutable digest, generates the `ccePolicy`, deploys the confidential container group, and prints the public endpoint.

## Cleanup

```powershell
Remove-AzResourceGroup -Name <RESOURCE_GROUP_NAME> -Force
```

## Notes

A user-assigned managed identity is supported when the subscription allows it. If policy blocks identity creation, the sample still deploys and the attestation page still works.
