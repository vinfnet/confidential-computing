@minLength(3)
@maxLength(12)
@description('Prefix for resource naming')
param prefix string

@minLength(3)
@maxLength(24)
@description('Name of the Confidential VM')
param cvmName string

@minLength(1)
@maxLength(64)
@description('Name of the Bastion host')
param bastionName string

@minLength(1)
@maxLength(64)
@description('Name of the Azure Attestation Service')
param attestationName string

@minLength(1)
@maxLength(64)
@description('Name of the virtual network')
param vnetName string

@description('Azure region')
param location string = resourceGroup().location

@description('Confidential VM SKU')
@allowed([
  'Standard_DC1as_v5'
  'Standard_DC2as_v5'
  'Standard_DC1as_v6'
  'Standard_DC2as_v6'
  'Standard_DC4as_v6'
])
param cvmSize string = 'Standard_DC2as_v5'

@description('Owner tag (UPN)')
param ownerTag string

@description('Shared Infrastructure Resource Group Name')
param sharedInfraRgName string

@description('Managed HSM-backed Disk Encryption Set Resource ID for confidential OS disks')
param diskEncryptionSetId string

@description('Enable Confidential OS Disk Encryption')
param confidentialOsDisk bool = true

@description('Enable Azure Attestation integration')
param attestationEnabled bool = true

@description('SSH public key for the Confidential VM administrator')
param sshPublicKey string

@description('Administrator username for both Confidential VMs')
param adminUsername string = 'azureuser'

@description('Base64-encoded cloud-init script for application bootstrap')
param customData string = ''

@description('Name of the SQL Server Confidential VM')
param sqlVmName string

@description('Base64-encoded cloud-init script for SQL Server bootstrap')
param sqlCustomData string = ''

// Variables
var appSubnetName = 'app-subnet'
var bastionSubnetName = 'AzureBastionSubnet'
var dbSubnetName = 'db-subnet'
var addressPrefix = '10.0.0.0/16'
var appSubnetPrefix = '10.0.3.0/24'
var bastionSubnetPrefix = '10.0.2.0/24'
var dbSubnetPrefix = '10.0.4.0/24'
var vmOsPublisher = 'Canonical'
var vmOsOffer = '0001-com-ubuntu-confidential-vm-jammy'
var vmOsSku = '22_04-lts-cvm'
var vmOsVersion = 'latest'
var vmDataDiskSize = 64
var sqlPrivateIp = '10.0.3.5'
var sharedVnetName = '${prefix}-shared-vnet'

resource sharedVnet 'Microsoft.Network/virtualNetworks@2023-09-01' existing = {
  scope: resourceGroup(sharedInfraRgName)
  name: sharedVnetName
}

// NAT provides controlled outbound access for package and image bootstrap traffic.
resource appNatPublicIp 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: '${vnetName}-nat-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource appNatGateway 'Microsoft.Network/natGateways@2023-09-01' = {
  name: '${vnetName}-nat'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [
      {
        id: appNatPublicIp.id
      }
    ]
  }
}

// Common tags
var commonTags = {
  environment: 'demo'
  application: 'citizen-registry-advanced'
  tier: 'app-instance'
  owner: ownerTag
  deploymentSource: 'bicep'
}

// Create Virtual Network for app instance
resource appVnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  tags: commonTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: appSubnetName
        properties: {
          addressPrefix: appSubnetPrefix
          networkSecurityGroup: {
            id: appNsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          natGateway: {
            id: appNatGateway.id
          }
        }
      }
      {
        name: bastionSubnetName
        properties: {
          addressPrefix: bastionSubnetPrefix
          networkSecurityGroup: {
            id: bastionNsg.id
          }
        }
      }
      {
        name: dbSubnetName
        properties: {
          addressPrefix: dbSubnetPrefix
          networkSecurityGroup: {
            id: dbNsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource appToSharedPeering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-09-01' = {
  parent: appVnet
  name: 'app-to-shared'
  properties: {
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: false
    allowGatewayTransit: false
    useRemoteGateways: false
    remoteVirtualNetwork: {
      id: sharedVnet.id
    }
  }
}

// Network Security Groups
resource appNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-app-nsg'
  location: location
  tags: commonTags
  properties: {
    securityRules: [
      {
        name: 'AllowHttpsFromBastion'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: bastionSubnetPrefix
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowSshFromBastion'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: bastionSubnetPrefix
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowSqlFromAppSubnet'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '1433'
          sourceAddressPrefix: appSubnetPrefix
          destinationAddressPrefix: appSubnetPrefix
          access: 'Allow'
          priority: 115
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowDbAccess'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '1433'
          sourceAddressPrefix: appSubnetPrefix
          destinationAddressPrefix: dbSubnetPrefix
          access: 'Allow'
          priority: 120
          direction: 'Outbound'
        }
      }
      {
        name: 'DenyInboundInternet'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4096
          direction: 'Inbound'
        }
      }
    ]
  }
}

resource bastionNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-bastion-nsg'
  location: location
  tags: commonTags
  properties: {
    securityRules: [
      {
        name: 'AllowHttpsInbound'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowGatewayManager'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowLoadBalancer'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowBastionCommunication'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRanges: [
            '8080'
            '5701'
          ]
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowSshRdpOutbound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRanges: [
            '22'
            '3389'
          ]
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowAzureCloud'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureCloud'
          access: 'Allow'
          priority: 110
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource dbNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${prefix}-db-nsg'
  location: location
  tags: commonTags
  properties: {
    securityRules: [
      {
        name: 'AllowSqlFromApp'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '1433'
          sourceAddressPrefix: appSubnetPrefix
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'DenyInbound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4096
          direction: 'Inbound'
        }
      }
    ]
  }
}

// Managed Identity for CVM
resource cvmIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-cvm-identity'
  location: location
  tags: commonTags
}

// Network Interface for CVM
resource cvmNic 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: '${cvmName}-nic'
  location: location
  tags: commonTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: '10.0.3.4'
          subnet: {
            id: '${appVnet.id}/subnets/${appSubnetName}'
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: appNsg.id
    }
  }
}

// Confidential VM (C-vn2 with SEV-SNP TEE)
resource confidentialVm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: cvmName
  location: location
  tags: commonTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${cvmIdentity.id}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: cvmSize
    }
    osProfile: {
      computerName: cvmName
      adminUsername: adminUsername
      customData: customData
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: vmOsPublisher
        offer: vmOsOffer
        sku: vmOsSku
        version: vmOsVersion
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: {
            securityEncryptionType: confidentialOsDisk ? 'DiskWithVMGuestState' : 'DiskWithoutVMGuestState'
            diskEncryptionSet: {
              id: diskEncryptionSetId
            }
          }
        }
      }
      dataDisks: [
        {
          createOption: 'Empty'
          diskSizeGB: vmDataDiskSize
          lun: 0
          managedDisk: {
            storageAccountType: 'Premium_LRS'
          }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: cvmNic.id
          properties: {
            primary: true
          }
        }
      ]
    }
    securityProfile: {
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
      encryptionAtHost: true
      securityType: 'ConfidentialVM'
    }
  }
}

// SQL Server Confidential VM on the same private app subnet.
resource sqlNic 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: '${sqlVmName}-nic'
  location: location
  tags: commonTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: sqlPrivateIp
          subnet: {
            id: '${appVnet.id}/subnets/${appSubnetName}'
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: appNsg.id
    }
  }
}

resource sqlVm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: sqlVmName
  location: location
  tags: commonTags
  properties: {
    hardwareProfile: {
      vmSize: cvmSize
    }
    osProfile: {
      computerName: sqlVmName
      adminUsername: adminUsername
      customData: sqlCustomData
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: vmOsPublisher
        offer: vmOsOffer
        sku: vmOsSku
        version: vmOsVersion
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: {
            securityEncryptionType: confidentialOsDisk ? 'DiskWithVMGuestState' : 'DiskWithoutVMGuestState'
            diskEncryptionSet: {
              id: diskEncryptionSetId
            }
          }
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: sqlNic.id
          properties: {
            primary: true
          }
        }
      ]
    }
    securityProfile: {
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
      encryptionAtHost: true
      securityType: 'ConfidentialVM'
    }
  }
}

// Bastion Host
resource bastionPublicIp 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: '${bastionName}-pip'
  location: location
  tags: commonTags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource bastionHost 'Microsoft.Network/bastionHosts@2023-09-01' = {
  name: bastionName
  location: location
  tags: commonTags
  sku: {
    name: 'Standard'
  }
  properties: {
    enableTunneling: true
    ipConfigurations: [
      {
        name: 'IpConf'
        properties: {
          subnet: {
            id: '${appVnet.id}/subnets/${bastionSubnetName}'
          }
          publicIPAddress: {
            id: bastionPublicIp.id
          }
        }
      }
    ]
    scaleUnits: 2
  }
}

// Azure Attestation Service Provider
resource attestationProvider 'Microsoft.Attestation/attestationProviders@2021-06-01' = if (attestationEnabled) {
  name: attestationName
  location: location
  tags: commonTags
  #disable-next-line BCP187 // The 2021-06-01 API accepts this live-validated property.
  sku: {
    name: 'Standard'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}

// Outputs
output cvmId string = confidentialVm.id
output cvmName string = confidentialVm.name
output cvmPrivateIp string = cvmNic.properties.ipConfigurations[0].properties.privateIPAddress
output sqlVmId string = sqlVm.id
output sqlVmName string = sqlVm.name
output sqlVmPrivateIp string = sqlPrivateIp
output bastionId string = bastionHost.id
output bastionName string = bastionHost.name
output attestationEndpoint string = attestationEnabled ? attestationProvider!.properties.attestUri : ''
output attestationId string = attestationEnabled ? attestationProvider!.id : ''
output vnetId string = appVnet.id
output appSubnetId string = '${appVnet.id}/subnets/${appSubnetName}'
output dbSubnetId string = '${appVnet.id}/subnets/${dbSubnetName}'
