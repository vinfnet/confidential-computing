targetScope = 'resourceGroup'

@description('Globally unique Azure Confidential Ledger name.')
@minLength(3)
@maxLength(34)
param ledgerName string

@description('Globally unique lowercase storage account name.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Object ID of the human or group that administers ledger-local users.')
param administratorPrincipalId string

@description('Name of the managed identity attached only to provenance agents.')
param provenanceIdentityName string = 'provenance-writer'

@description('Name of the immutable Blob container.')
param evidenceContainerName string = 'build-evidence'

@description('Number of days each evidence blob remains immutable.')
@minValue(1)
param evidenceRetentionDays int = 365

@description('Azure region for the provenance resources.')
param location string = resourceGroup().location

@description('Resource ID of the non-delegated subnet for the storage private endpoint.')
param privateEndpointSubnetResourceId string

@description('Azure region of the VNet hosting the private endpoint.')
param privateEndpointLocation string = location

@description('Resource tags.')
param tags object = {}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.blob.core.windows.net'
}

module provenanceIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  params: {
    name: provenanceIdentityName
    location: location
    enableTelemetry: false
    tags: tags
  }
}

module evidenceStorage 'br/public:avm/res/storage/storage-account:0.33.1' = {
  params: {
    name: storageAccountName
    location: location
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    requireInfrastructureEncryption: true
    skuName: 'Standard_LRS'
    blobServices: {
      isVersioningEnabled: true
      containers: [
        {
          name: evidenceContainerName
          publicAccess: 'None'
          immutableStorageWithVersioningEnabled: true
          immutabilityPolicy: {
            allowProtectedAppendWrites: false
            allowProtectedAppendWritesAll: false
            immutabilityPeriodSinceCreationInDays: evidenceRetentionDays
          }
          roleAssignments: [
            {
              principalId: provenanceIdentity.outputs.principalId
              principalType: 'ServicePrincipal'
              roleDefinitionIdOrName: 'Storage Blob Data Contributor'
            }
          ]
        }
      ]
    }
    tags: tags
  }
}

resource ledger 'Microsoft.ConfidentialLedger/ledgers@2022-05-13' = {
  name: ledgerName
  location: location
  properties: {
    aadBasedSecurityPrincipals: [
      {
        ledgerRoleName: 'Administrator'
        principalId: administratorPrincipalId
        tenantId: tenant().tenantId
      }
      {
        ledgerRoleName: 'Contributor'
        principalId: provenanceIdentity.outputs.principalId
        tenantId: tenant().tenantId
      }
    ]
    ledgerType: 'Private'
  }
  tags: tags
}

resource blobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-07-01' = {
  name: '${storageAccountName}-blob-pe-eus2'
  location: privateEndpointLocation
  properties: {
    subnet: {
      id: privateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: '${storageAccountName}-blob-connection'
        properties: {
          privateLinkServiceId: evidenceStorage.outputs.resourceId
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
  tags: tags
}

resource blobPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = {
  parent: blobPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobPrivateDnsZone.id
        }
      }
    ]
  }
}

output ledgerEndpoint string = 'https://${ledger.name}.confidential-ledger.azure.com'
output provenanceIdentityClientId string = provenanceIdentity.outputs.clientId
output provenanceIdentityPrincipalId string = provenanceIdentity.outputs.principalId
output provenanceIdentityResourceId string = provenanceIdentity.outputs.resourceId
output evidenceStorageAccountName string = evidenceStorage.outputs.name
output evidenceContainer string = evidenceContainerName
output blobPrivateEndpointResourceId string = blobPrivateEndpoint.id
output blobPrivateDnsZoneName string = blobPrivateDnsZone.name