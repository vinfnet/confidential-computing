using './main.bicep'

param ledgerName = 'sgall-provenance-ledger'
param storageAccountName = 'sgallprovenance001'
param administratorPrincipalId = '00000000-0000-0000-0000-000000000000'
param provenanceIdentityName = 'sgall-provenance-writer'
param evidenceContainerName = 'build-evidence'
param evidenceRetentionDays = 365
param location = 'eastus2'
param tags = {
  workload: 'confidential-build-provenance'
}