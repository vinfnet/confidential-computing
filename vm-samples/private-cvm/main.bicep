targetScope = 'resourceGroup'

@description('Short lowercase prefix used for globally unique resource names.')
@minLength(3)
@maxLength(8)
param prefix string = 'demo'

@description('Azure region that supports DCas_v5 confidential VMs and Azure Bastion.')
param location string = resourceGroup().location

@description('Shared MAA host for the deployment region, without https://.')
param maaEndpoint string

@description('Object ID of the operator. Used to create keys and run the explicit negative release test.')
param operatorObjectId string

@description('Object ID of the Confidential VM Orchestrator service principal.')
param cvmOrchestratorObjectId string

@description('Existing Disk Encryption Set principal ID, when rerunning an established deployment.')
param existingDesPrincipalId string = ''

@description('SSH public key for the CVM administrator.')
@secure()
param sshPublicKey string

@description('Create the HSM keys and confidential disk encryption set.')
param deployKeys bool = false

@description('Create the application data key after the CVM exists.')
param deployDataKey bool = false

@description('Exact x-ms-azurevm-vmid value required by the application key release policy.')
param applicationKeyVmId string = ''

@description('Create or update Azure Bastion during the foundation pass only.')
param deployBastion bool = true

@description('Create the CVM after key and role propagation has completed.')
param deployVm bool = false

@description('Confidential VM size. DCas_v5 uses AMD SEV-SNP, matching this sample policy.')
param vmSize string = 'Standard_DC2as_v5'

@description('Linux administrator account used only through Azure Bastion.')
param adminUsername string = 'azureuser'

@description('Public key used by the Storage SFTP local user.')
param storageSftpPublicKey string

@description('Base64-encoded private key stored as a Key Vault secret for the CVM identity.')
@secure()
param storageSftpPrivateKeyBase64 string

var suffix = uniqueString(resourceGroup().id)
var baseName = '${prefix}-${take(suffix, 6)}'
var compactName = take(toLower(replace('${prefix}${suffix}', '-', '')), 18)
var applicationDataKeyName = !empty(applicationKeyVmId) ? 'private-data-key-${take(toLower(replace(applicationKeyVmId, '-', '')), 12)}' : 'private-data-key-pending'
var keyReleasePolicy = {
  version: '1.0.0'
  anyOf: [
    {
      authority: 'https://${maaEndpoint}'
      allOf: [
        {
          claim: 'x-ms-isolation-tee.x-ms-compliance-status'
          equals: 'azure-compliant-cvm'
        }
        {
          claim: 'x-ms-isolation-tee.x-ms-attestation-type'
          equals: 'sevsnpvm'
        }
        {
          claim: 'x-ms-azurevm-vmid'
          equals: applicationKeyVmId
        }
      ]
    }
  ]
}
var encodedReleasePolicy = replace(replace(replace(base64(string(keyReleasePolicy)), '+', '-'), '/', '_'), '=', '')
var diskReleasePolicy = {
  version: '1.0.0'
  anyOf: [
    {
      authority: 'https://${maaEndpoint}'
      allOf: [
        {
          claim: 'x-ms-compliance-status'
          equals: 'azure-compliant-cvm'
        }
      ]
    }
  ]
}
var encodedDiskReleasePolicy = replace(replace(replace(base64(string(diskReleasePolicy)), '+', '-'), '/', '_'), '=', '')
resource natPublicIp 'Microsoft.Network/publicIPAddresses@2024-07-01' = {
  name: '${baseName}-nat-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource natGateway 'Microsoft.Network/natGateways@2024-07-01' = {
  name: '${baseName}-nat'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [
      {
        id: natPublicIp.id
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-07-01' = {
  name: '${baseName}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'CvmSubnet'
        properties: {
          addressPrefix: '10.20.1.0/24'
                natGateway: {
                  id: natGateway.id
                }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'PrivateEndpointSubnet'
        properties: {
          addressPrefix: '10.20.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: '10.20.3.0/26'
        }
      }
    ]
  }
}

resource bastionPublicIp 'Microsoft.Network/publicIPAddresses@2024-07-01' = {
  name: '${baseName}-bastion-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource bastion 'Microsoft.Network/bastionHosts@2024-07-01' = if (deployBastion) {
  name: '${baseName}-bastion'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    enableIpConnect: true
    enableTunneling: true
    scaleUnits: 2
    ipConfigurations: [
      {
        name: 'bastion-ipconfig'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: bastionPublicIp.id
          }
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'AzureBastionSubnet')
          }
        }
      }
    ]
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: '${compactName}kv'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'premium'
    }
    enablePurgeProtection: true
    enableRbacAuthorization: false
    enabledForDiskEncryption: true
    publicNetworkAccess: 'Disabled'
    softDeleteRetentionInDays: 10
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: operatorObjectId
        permissions: {
          keys: [
            'create'
            'decrypt'
            'encrypt'
            'get'
            'release'
            'unwrapKey'
            'wrapKey'
          ]
          secrets: [
            'get'
            'set'
          ]
        }
      }
      {
        tenantId: subscription().tenantId
        objectId: cvmIdentity.properties.principalId
        permissions: {
          keys: [
            'encrypt'
            'get'
            'release'
          ]
          secrets: [
            'get'
          ]
        }
      }
      {
        tenantId: subscription().tenantId
        objectId: cvmOrchestratorObjectId
        permissions: {
          keys: [
            'get'
            'release'
          ]
        }
      }
      ...(!empty(existingDesPrincipalId) ? [
        {
          tenantId: subscription().tenantId
          objectId: existingDesPrincipalId
          permissions: {
            keys: [
              'get'
              'unwrapKey'
              'wrapKey'
            ]
          }
        }
      ] : [])
    ]
  }
}

resource cvmIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-cvm-id'
  location: location
}

resource diskKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' = if (deployKeys) {
  parent: keyVault
  name: 'confidential-os-disk-key-v2'
  properties: {
    attributes: {
      enabled: true
      exportable: true
    }
    keyOps: [
      'wrapKey'
      'unwrapKey'
    ]
    keySize: 3072
    kty: 'RSA-HSM'
    release_policy: {
      contentType: 'application/json; charset=utf-8'
      data: encodedDiskReleasePolicy
    }
  }
}

resource dataKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' = if (deployDataKey && !empty(applicationKeyVmId)) {
  parent: keyVault
  name: applicationDataKeyName
  properties: {
    attributes: {
      enabled: true
      exportable: true
    }
    keyOps: [
      'encrypt'
      'decrypt'
    ]
    keySize: 2048
    kty: 'RSA-HSM'
    release_policy: {
      contentType: 'application/json; charset=utf-8'
      data: encodedReleasePolicy
    }
  }
}

resource diskEncryptionSet 'Microsoft.Compute/diskEncryptionSets@2024-03-02' = if (deployKeys) {
  name: '${baseName}-des'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    activeKey: {
      keyUrl: diskKey!.properties.keyUriWithVersion
      sourceVault: {
        id: keyVault.id
      }
    }
    encryptionType: 'ConfidentialVmEncryptedWithCustomerKey'
  }
}

resource diskEncryptionAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2024-11-01' = if (deployKeys) {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: diskEncryptionSet!.identity.principalId
        permissions: {
          keys: [
            'get'
            'unwrapKey'
            'wrapKey'
          ]
        }
      }
    ]
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: '${prefix}${take(suffix, 13)}st'
  location: location
  sku: {
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    isHnsEnabled: true
    isSftpEnabled: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
  }
}

resource storageSftpKeySecret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'storage-sftp-private-key'
  properties: {
    attributes: {
      enabled: true
    }
    value: storageSftpPrivateKeyBase64
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource encryptedContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobService
  name: 'encrypted-data'
  properties: {
    publicAccess: 'None'
  }
}

resource storageLocalUser 'Microsoft.Storage/storageAccounts/localUsers@2025-01-01' = {
  parent: storage
  name: 'cvmdata'
  properties: {
    allowAclAuthorization: false
    hasSshKey: true
    homeDirectory: encryptedContainer.name
    permissionScopes: [
      {
        permissions: 'rwc'
        resourceName: encryptedContainer.name
        service: 'blob'
      }
    ]
    sshAuthorizedKeys: [
      {
        description: 'private-cvm'
        key: storageSftpPublicKey
      }
    ]
  }
}

resource cvmNsg 'Microsoft.Network/networkSecurityGroups@2024-07-01' = {
  name: '${baseName}-cvm-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowSshFromVnet'
        properties: {
          access: 'Allow'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          direction: 'Inbound'
          priority: 100
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
        }
      }
    ]
  }
}

resource cvmNic 'Microsoft.Network/networkInterfaces@2024-07-01' = if (deployVm) {
  name: '${baseName}-cvm-nic'
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
      id: cvmNsg.id
    }
  }
}

resource cvm 'Microsoft.Compute/virtualMachines@2024-11-01' = if (deployVm) {
  name: '${baseName}-cvm'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${cvmIdentity.id}': {}
    }
  }
  properties: {
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: false
      }
    }
    hardwareProfile: {
      vmSize: vmSize
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
    osProfile: {
      adminUsername: adminUsername
      computerName: '${baseName}-cvm'
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
    securityProfile: {
      securityType: 'ConfidentialVM'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: {
        offer: 'ubuntu-24_04-lts'
        publisher: 'Canonical'
        sku: 'cvm'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: {
          securityProfile: {
            diskEncryptionSet: {
              id: diskEncryptionSet.id
            }
            securityEncryptionType: 'DiskWithVMGuestState'
          }
          storageAccountType: 'StandardSSD_LRS'
        }
        osType: 'Linux'
      }
    }
  }
  dependsOn: [
    diskEncryptionAccessPolicy
  ]
}

resource keyVaultDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
}

resource blobDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}

resource keyVaultDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: keyVaultDns
  name: '${baseName}-kv-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource blobDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: blobDns
  name: '${baseName}-blob-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-07-01' = {
  name: '${baseName}-kv-pe'
  location: location
  properties: {
    subnet: {
      id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'PrivateEndpointSubnet')
    }
    privateLinkServiceConnections: [
      {
        name: 'key-vault'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource keyVaultPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = {
  parent: keyVaultPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'key-vault'
        properties: {
          privateDnsZoneId: keyVaultDns.id
        }
      }
    ]
  }
}

resource blobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-07-01' = {
  name: '${baseName}-blob-pe'
  location: location
  properties: {
    subnet: {
      id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'PrivateEndpointSubnet')
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

resource blobPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = {
  parent: blobPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobDns.id
        }
      }
    ]
  }
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${baseName}-logs'
  location: location
  properties: {
    retentionInDays: 30
    sku: {
      name: 'PerGB2018'
    }
  }
}

resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  name: 'key-release-audit'
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
  }
}

output bastionName string = '${baseName}-bastion'
output keyVaultName string = keyVault.name
output storageAccountName string = storage.name
output encryptedContainerName string = encryptedContainer.name
output logAnalyticsName string = logAnalytics.name
output virtualNetworkName string = vnet.name
output cvmName string = deployVm ? cvm.name : '${baseName}-cvm'
output cvmId string = deployVm ? cvm.id : ''
output cvmIdentityClientId string = cvmIdentity.properties.clientId
output dataKeyName string = applicationDataKeyName
output maaEndpoint string = maaEndpoint
output storageSftpKeySecretName string = storageSftpKeySecret.name
output storageSftpUserName string = storageLocalUser.name
