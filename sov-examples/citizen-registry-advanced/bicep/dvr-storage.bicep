@description('Azure region for the DVR storage resources')
param location string = resourceGroup().location

@minLength(3)
@maxLength(24)
@description('Globally unique DVR Storage account name')
param storageAccountName string

@description('Private Blob container name')
param containerName string = 'cctv-dvr'

@description('DVR source blob name')
param blobName string

@description('Managed HSM URI used for Storage encryption')
param managedHsmUri string

@description('Managed HSM key name used for Storage encryption')
param storageKeyName string

@description('Managed HSM key version used for Storage encryption')
param storageKeyVersion string

@description('Resource ID of the user-assigned identity used by Storage encryption')
param storageEncryptionIdentityId string

@description('Principal ID of the DVR writer identity')
param dvrIdentityPrincipalId string

@description('Principal ID of the confidential analyzer reader identity')
param analyzerIdentityPrincipalId string

@description('Deploy Blob data-plane role assignments with this module')
param deployDataPlaneRoleAssignments bool = true

@description('Subnet resource ID for the Blob private endpoint')
param privateEndpointSubnetId string

@description('Application virtual network resource ID')
param vnetId string

@description('Application virtual network name')
param vnetName string

@description('Tags applied to DVR resources')
param tags object = {}

resource dvrStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${storageEncryptionIdentityId}': {}
    }
  }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
    encryption: {
      keySource: 'Microsoft.Keyvault'
      requireInfrastructureEncryption: true
      identity: {
        userAssignedIdentity: storageEncryptionIdentityId
      }
      keyvaultproperties: {
        keyname: storageKeyName
        keyvaulturi: managedHsmUri
        keyversion: storageKeyVersion
      }
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
  }
}

resource dvrBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: dvrStorage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource dvrContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: dvrBlobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
  tags: tags
}

resource blobPrivateDnsVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: blobPrivateDnsZone
  name: '${vnetName}-blob-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnetId
    }
  }
}

resource dvrBlobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${storageAccountName}-blob-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: dvrStorage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

resource dvrBlobPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: dvrBlobPrivateEndpoint
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

resource dvrWriterRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployDataPlaneRoleAssignments) {
  name: guid(dvrStorage.id, dvrIdentityPrincipalId, 'Storage Blob Data Contributor')
  scope: dvrStorage
  properties: {
    principalId: dvrIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}

resource analyzerReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployDataPlaneRoleAssignments) {
  name: guid(dvrStorage.id, analyzerIdentityPrincipalId, 'Storage Blob Data Reader')
  scope: dvrStorage
  properties: {
    principalId: analyzerIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
  }
}

output storageAccountName string = dvrStorage.name
output containerName string = dvrContainer.name
output blobUri string = 'https://${dvrStorage.name}.blob.${environment().suffixes.storage}/${dvrContainer.name}/${blobName}'