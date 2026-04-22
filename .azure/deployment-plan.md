# Deployment Plan

**Status:** Validated and deployed successfully
**Project:** `aci-samples/SecureSnakeACI`
**Requested Outcome:** Browser-playable retro game deployed to Azure Confidential ACI with digest pinning, `confcom` policy enforcement, and live attestation.

## App
- Lightweight **Snake** game in HTML5/JavaScript served by Flask
- Packaged with Docker
- Deployed to **Azure Container Registry + Azure Confidential ACI**
- Includes a repeatable PowerShell deployment script and an attestation page

## Key Files
- `aci-samples/SecureSnakeACI/app.py`
- `aci-samples/SecureSnakeACI/Dockerfile`
- `aci-samples/SecureSnakeACI/requirements.txt`
- `aci-samples/SecureSnakeACI/supervisord.conf`
- `aci-samples/SecureSnakeACI/Deploy-SecureSnakeACI.ps1`
- `aci-samples/SecureSnakeACI/README.md`

## Azure Resources
- Resource group
- Azure Container Registry
- Confidential Azure Container Instance
- Optional user-assigned managed identity

## Outcome
1. Built the browser game sample
2. Added repeatable confidential deployment automation
3. Generated and injected the `ccePolicy` via `az confcom acipolicygen`
4. Verified the public endpoint and health check
5. Verified live attestation evidence and MAA token issuance
