targetScope = 'resourceGroup'

@description('Azure region containing the existing private CVM demo.')
param location string = resourceGroup().location

@description('Base resource name from the existing deployment.')
param baseName string

@description('Existing virtual network name.')
param virtualNetworkName string

@description('Existing network security group name.')
param networkSecurityGroupName string

@description('Existing Key Vault name containing the VMID-bound application key.')
param keyVaultName string

@description('SSH public key for Bastion access to the standard VM.')
@secure()
param sshPublicKey string

@description('Linux administrator account used only through Azure Bastion.')
param adminUsername string = 'azureuser'

resource vnet 'Microsoft.Network/virtualNetworks@2024-07-01' existing = {
  name: virtualNetworkName
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-07-01' existing = {
  name: networkSecurityGroupName
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-standard-id'
  location: location
}

resource accessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2024-11-01' = {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: identity.properties.principalId
        permissions: {
          keys: [
            'get'
            'release'
          ]
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-07-01' = {
  name: '${baseName}-standard-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'private'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'CvmSubnet')
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsg.id
    }
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' = {
  name: '${baseName}-standard-vm'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
    hardwareProfile: {
      vmSize: 'Standard_D2as_v6'
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
          }
        }
      ]
    }
    osProfile: {
      adminUsername: adminUsername
      computerName: '${baseName}-standard'
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              keyData: sshPublicKey
              path: '/home/${adminUsername}/.ssh/authorized_keys'
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        offer: 'ubuntu-24_04-lts'
        publisher: 'Canonical'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
        osType: 'Linux'
      }
    }
  }
  dependsOn: [
    accessPolicy
  ]
}

output vmName string = vm.name
output vmId string = vm.id
output identityClientId string = identity.properties.clientId
