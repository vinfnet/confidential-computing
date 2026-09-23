using './main.bicep'

param ledgerName = 'sgallprovledger2026'
param storageAccountName = 'sgallprovstg2026'
param administratorPrincipalId = '3a2c0db5-79a1-47ef-ac17-694e2c6370cf'
param provenanceIdentityName = 'sgall-provenance-writer'
param evidenceContainerName = 'build-evidence'
param evidenceRetentionDays = 365
param location = 'eastus'
param privateEndpointSubnetResourceId = resourceId('Microsoft.Network/virtualNetworks/subnets', 'sgalladopovcrvnet', 'sgalladopovcrvmsubnet')
param privateEndpointLocation = 'eastus2euap'
param tags = {
  workload: 'confidential-build-provenance'
}
