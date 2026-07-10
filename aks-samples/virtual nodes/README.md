# AKS Virtual Nodes on a Confidential AKS Cluster

This sample creates a fresh AKS cluster with:

- Azure CNI networking and dedicated AKS plus ACI subnets
- A standard system node pool
- An AMD SEV-SNP confidential node pool
- The AKS virtual nodes add-on backed by Azure Container Instances
- A public hello-world deployment scheduled onto the virtual node

The script lives entirely in this folder and follows the repo's usual naming and tagging pattern:

- Resource group name: `<prefix><5 random lowercase letters>`
- Tags: `owner`, `BuiltBy`, `GitRepo`, `Workload`, `Scenario`

## Files

- `Deploy-VirtualNodesAKS.ps1`: end-to-end deployment script
- `virtual-node-hello-world.yaml`: hello-world workload scheduled onto the virtual node (standard ACI)
- `virtual-node-confidential.yaml`: confidential ACI workload template with CCE policy annotation scaffold

## What the script checks

- Azure CLI installed and logged in
- Azure PowerShell `Az` modules installed and logged in
- `kubectl` installed, with an option to install via `az aks install-cli`
- `aks-preview` Azure CLI extension installed, with an option to install it
- Required Azure resource providers registered
- Active RBAC capable of creating role assignments at subscription scope
- PIM eligibility for the required roles if the active role is missing, using native Az PowerShell cmdlets
- Confidential VM SKU visibility in the target region

The script requires an active subscription-scope role that can both create resources and assign RBAC on the virtual-node network resources. In practice, that means one of:

- `Owner`
- `User Access Administrator`
- `Role Based Access Control Administrator`

If one of those roles is only eligible through Microsoft Entra PIM, the script pauses and asks you to activate it before retrying the permission check.

During live validation, the AKS virtual-nodes connector identity needed `Network Contributor` on both the `aci-subnet` and the parent virtual network to stabilize quickly, so the script assigns both scopes before restarting the connector.

## Usage

```powershell
./Deploy-VirtualNodesAKS.ps1 -Prefix sgall
```

Optional parameters:

```powershell
./Deploy-VirtualNodesAKS.ps1 -Prefix sgall -Region eastus2 -SubscriptionId <subscription-id>
./Deploy-VirtualNodesAKS.ps1 -Prefix sgall -ConfidentialVmSize Standard_DC2as_v5 -SystemVmSize Standard_D2as_v7
./Deploy-VirtualNodesAKS.ps1 -Prefix sgall -Region eastus2 -AutoActivatePim
```

## Default behavior

- If `-Region` is omitted, the script prefers `eastus2` and falls back across a short candidate list until it finds visible availability for the confidential node SKU.
- The default system node pool size is `Standard_D2as_v7`, which aligns with the currently allowed SKUs in the target subscription and region used during validation.
- The cluster uses Azure CNI because virtual nodes require advanced networking.
- The hello-world pod is scheduled onto the virtual node using node selectors and tolerations from the AKS virtual nodes guidance.
- The RBAC and PIM preflight uses native Azure PowerShell cmdlets. If you pass `-AutoActivatePim`, the script can submit a native `SelfActivate` request for the first eligible role instead of waiting for manual confirmation.
- The script performs an internal smoke test from inside the cluster and, when possible, an external HTTP test through the public load balancer.

## Notes on confidential ACI

This first sample validates the virtual-nodes plumbing on top of a confidential-node AKS cluster and uses the standard `mcr.microsoft.com/azuredocs/aci-helloworld` image as the smoke test.

That gives you a working foundation for the next step: replacing the sample manifest with a confidential ACI deployment that includes a generated Confidential Computing Enforcement policy and any attestation sidecars you want to test.

`virtual-node-confidential.yaml` is the starting point for that step. It includes the `microsoft.containerinstance.virtualnode.ccepolicy` annotation with an allow-all debug policy. Replace the policy value with the output of:

```bash
az confcom acipolicygen --image <your-image> --print-policy
```

## References

- https://learn.microsoft.com/en-us/azure/aks/virtual-nodes
- https://learn.microsoft.com/en-us/azure/aks/virtual-nodes-cli
- https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview
- https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview