# Provenance infrastructure

This Bicep deployment creates the isolated resources used by the governed build template:

- A user-assigned managed identity for the provenance agent pool.
- A private Azure Confidential Ledger. The deployment operator is an Administrator and the
  provenance identity is a ledger-local Contributor.
- A StorageV2 account with shared-key access disabled and a versioned, immutable evidence
  container. The provenance identity receives `Storage Blob Data Contributor` on that container.

The immutability policy is initially **Unlocked** so its retention period can be tested. Lock it
only after validating the complete workflow: a locked policy cannot be shortened or removed.

Validate before deployment:

```powershell
Copy-Item infra/provenance/main.example.bicepparam infra/provenance/main.bicepparam
# Replace the globally unique names and administratorPrincipalId in main.bicepparam.

az deployment group what-if `
  --subscription <subscription-id> `
  --resource-group <resource-group> `
  --template-file infra/provenance/main.bicep `
  --parameters infra/provenance/main.bicepparam
```

Use the same parameters with `az deployment group create` after reviewing the what-if result.
Capture the deployment outputs; they map directly to the governed pipeline template:

| Deployment output | Pipeline template parameter |
| --- | --- |
| `ledgerEndpoint` | `ledgerEndpoint` |
| `provenanceIdentityClientId` | `ledgerWriterClientId` |
| `evidenceStorageAccountName` | `evidenceStorageAccountName` |
| `evidenceContainer` | `evidenceContainerName` |

## Isolated provenance pool

Create a separate Azure DevOps pool named `confidential-provenance-pool`, then deploy confidential
agents into it with `Build-ConfidentialAciAdoAgent.ps1`. Pass the deployment's
`provenanceIdentityResourceId` as `-UserAssignedIdentityResourceId`. Do not pass workload resource
group parameters: the provenance identity must not be able to deploy or mutate application
resources.

Grant the identity `AcrPull` on each registry containing artifacts it scans. Its remaining access is
already provisioned by Bicep: ledger-local `Contributor` and container-scoped
`Storage Blob Data Contributor`. Do not grant ledger or evidence-container access to developer
build identities.

The shared pipeline templates are:

- `usecase-ado-server-iaas/pipelines/templates/confidential-build-with-provenance.yml` for new
  pipelines that want a developer-supplied `buildSteps` list.
- `usecase-ado-server-iaas/pipelines/templates/provenance-stage.yml` for existing pipelines
  that already own their build/deploy stages. It resolves the immutable ACR digest, generates
  the SBOM, records the ledger receipt, uploads immutable evidence, and publishes the report.

Developers may add build or diagnostic steps through `buildSteps` or `preProvenanceSteps`, but
the provenance stage itself must remain last in the build gate. Deployment stages must depend on
`Provenance`; a successful image build alone is not a successful governed build.

A consumer of the new stage supplies these infrastructure parameters:

```yaml
ledgerEndpoint: https://<ledger>.confidential-ledger.azure.com
ledgerCollectionId: default
ledgerWriterClientId: <provenanceIdentityClientId>
evidenceStorageAccountName: <evidenceStorageAccountName>
evidenceContainerName: build-evidence
acrName: <artifact-registry-name>
imageName: <artifact-name>
imageTag: $(Build.BuildId)
```

The repository's hello-world, sample-app, visual-attestation, and both SecretApp pipeline
definitions now reference `provenance-stage.yml`. The SecretApp definitions run provenance after
the selected Standard or Confidential path; the dedicated-build definitions gate deployment on
successful provenance. Do not remove that dependency or replace the digest-qualified image URI
with a mutable tag.