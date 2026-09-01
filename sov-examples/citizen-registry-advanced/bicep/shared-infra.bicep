metadata description = 'Shared Infrastructure for Citizen Registry Advanced'

param hsmName string
param vnetName string
param privateLinkSubnetName string
param location string = resourceGroup().location
param ownerTag string
param costControlTag string = 'confidential-computing'
param initialAdminObjectId string

var vnetAddressPrefix = '10.10.0.0/16'
var privateLinkSubnetPrefix = '10.10.1.0/24'
var bastionSubnetPrefix = '10.10.2.0/24'
var appSubnetPrefix = '10.10.3.0/24'

// Create Virtual Network
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: {
    environment: 'demo'
    owner: ownerTag
  }
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: privateLinkSubnetName
        properties: {
          addressPrefix: privateLinkSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'bastion-subnet'
        properties: {
          addressPrefix: bastionSubnetPrefix
        }
      }
      {
        name: 'app-subnet'
        properties: {
          addressPrefix: appSubnetPrefix
        }
      }
    ]
  }
}

// Create Managed HSM
resource managedHsm 'Microsoft.KeyVault/managedHSMs@2023-07-01' = {
  name: hsmName
  location: location
  tags: {
    environment: 'demo'
    owner: ownerTag
    costCenter: costControlTag
    CostControl: 'Ignore'
  }
  sku: {
    family: 'B'
    name: 'Standard_B1'
  }
  properties: {
    tenantId: subscription().tenantId
    initialAdminObjectIds: [
      initialAdminObjectId
    ]
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    enableSoftDelete: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    publicNetworkAccess: 'Enabled'
  }
}

// Private Endpoint for Managed HSM
resource hsmPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${hsmName}-pe'
  location: location
  tags: {
    environment: 'demo'
    owner: ownerTag
  }
  properties: {
    subnet: {
      id: '${vnet.id}/subnets/${privateLinkSubnetName}'
    }
    privateLinkServiceConnections: [
      {
        name: '${hsmName}-pe-connection'
        properties: {
          privateLinkServiceId: managedHsm.id
          groupIds: [
            'managedhsm'
          ]
        }
      }
    ]
  }
}

// Private DNS Zone for Managed HSM
resource hsmPrivateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.managedhsm.azure.net'
  location: 'global'
  tags: {
    environment: 'demo'
    owner: ownerTag
  }
}

// Link Private DNS Zone to VNet
resource hsmDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: hsmPrivateDnsZone
  name: '${vnetName}-link'
  location: 'global'
  tags: {
    environment: 'demo'
    owner: ownerTag
  }
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// DNS A Record for Managed HSM
resource hsmDnsRecord 'Microsoft.Network/privateDnsZones/A@2020-06-01' = {
  parent: hsmPrivateDnsZone
  name: hsmName
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: hsmPrivateEndpoint.properties.customDnsConfigs[0].ipAddresses[0]
      }
    ]
  }
}

output vnetId string = vnet.id
output hsmId string = managedHsm.id
output hsmName string = managedHsm.name
output hsmPrivateEndpointId string = hsmPrivateEndpoint.id
output privateDnsZoneId string = hsmPrivateDnsZone.id
output privateLinkSubnetId string = '${vnet.id}/subnets/${privateLinkSubnetName}'
output bastionSubnetId string = '${vnet.id}/subnets/bastion-subnet'
output appSubnetId string = '${vnet.id}/subnets/app-subnet'
