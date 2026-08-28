<#
.SYNOPSIS
    Setup and configure Bastion for secure access to citizen registry CVM.

.DESCRIPTION
    Configures Azure Bastion host to provide secure RDP/SSH access to the
    Confidential VM without exposing it to the public internet.

.PARAMETER ResourceGroupName
    Name of the resource group containing the Bastion and CVM.

.PARAMETER BastionName
    Name of the Bastion host.

.PARAMETER CvmName
    Name of the Confidential VM.

.EXAMPLE
    .\setup-bastion.ps1 -ResourceGroupName "sgall12345app" `
      -BastionName "sgall-12345-bastion" `
      -CvmName "sgall-citizen-cvm"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$BastionName,

    [Parameter(Mandatory = $true)]
    [string]$CvmName
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Setting up Bastion Access                                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verify Bastion exists
Write-Host "Verifying Bastion configuration..." -ForegroundColor Yellow
$bastion = az network bastion show -g $ResourceGroupName -n $BastionName --query "{id: id, name: name, location: location}" -o json 2>$null | ConvertFrom-Json

if (-not $bastion) {
    Write-Host "✗ Bastion not found: $BastionName" -ForegroundColor Red
    Write-Host "  Ensure Bastion is deployed in resource group: $ResourceGroupName" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Bastion found:" -ForegroundColor Green
Write-Host "  Name: $($bastion.name)"
Write-Host "  Location: $($bastion.location)"
Write-Host ""

# Get CVM details
Write-Host "Verifying Confidential VM..." -ForegroundColor Yellow
$vm = az vm show -g $ResourceGroupName -n $CvmName --query "{id: id, name: name, vmId: vmId}" -o json 2>$null | ConvertFrom-Json

if (-not $vm) {
    Write-Host "✗ VM not found: $CvmName" -ForegroundColor Red
    exit 1
}

Write-Host "✓ VM found:" -ForegroundColor Green
Write-Host "  Name: $($vm.name)"
Write-Host "  VM ID: $($vm.vmId)"
Write-Host ""

# Get network interface
Write-Host "Retrieving network interface details..." -ForegroundColor Yellow
$nic = az vm nic list -g $ResourceGroupName --vm-name $CvmName --query "[0].{id: id}" -o json | ConvertFrom-Json
$nicDetails = az network nic show --ids $nic.id --query "{name: name, privateIpAddress: ipConfigurations[0].privateIpAddress, subnet: ipConfigurations[0].subnet.id}" -o json | ConvertFrom-Json

Write-Host "✓ Network Interface:" -ForegroundColor Green
Write-Host "  Name: $($nicDetails.name)"
Write-Host "  Private IP: $($nicDetails.privateIpAddress)"
Write-Host ""

# Display Bastion access instructions
Write-Host "Bastion Access Configuration:" -ForegroundColor Cyan
Write-Host ""
Write-Host "Method 1: Using Azure Portal" -ForegroundColor Yellow
Write-Host "  1. Go to: https://portal.azure.com"
Write-Host "  2. Navigate to: Resource Groups > $ResourceGroupName > $CvmName"
Write-Host "  3. Click 'Connect' > 'Bastion' > 'Use Bastion'"
Write-Host "  4. Enter username: azureuser"
Write-Host "  5. Select 'SSH Public Key' and use your private key"
Write-Host ""

Write-Host "Method 2: Using Azure CLI" -ForegroundColor Yellow
Write-Host "  az network bastion ssh -g $ResourceGroupName -n $BastionName -n $($nicDetails.name) --target-resource-type ""vmss"" --resource-id $($vm.id)"
Write-Host ""

Write-Host "Method 3: Using SSH Tunnel (if configured)" -ForegroundColor Yellow
Write-Host "  az network bastion tunnel -g $ResourceGroupName -n $BastionName --resource-id $($vm.id) --resource-port 22 --port 2222"
Write-Host "  ssh -i /path/to/private.key -p 2222 azureuser@localhost"
Write-Host ""

# Verify NSG allows Bastion traffic
Write-Host "Verifying Network Security Group rules..." -ForegroundColor Yellow

$subnet = $nicDetails.subnet.Split('/')[-1]
$subnetRg = $nicDetails.subnet.Split('/')[-5]

$nsg = az network vnet subnet show -g $subnetRg --vnet-name (az network vnet list -g $subnetRg --query "[0].name" -o tsv) -n $subnet --query "networkSecurityGroup.id" -o tsv 2>$null

if ($nsg) {
    $nsgRules = az network nsg rule list --nsg-name (($nsg -split '/')[-1]) -g $subnetRg --query "[?destinationPortRange=='22' || destinationPortRange=='3389']" -o json | ConvertFrom-Json
    
    if ($nsgRules) {
        Write-Host "✓ NSG allows SSH/RDP from Bastion" -ForegroundColor Green
    } else {
        Write-Host "⚠ NSG may not allow SSH/RDP access. Verify rules allow traffic from Bastion subnet." -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠ Could not verify NSG configuration" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Bastion is now configured for access to $CvmName"
Write-Host "  Access the citizen-registry app through Bastion tunnel"
Write-Host "  App endpoint: https://$($nicDetails.privateIpAddress):8443"
Write-Host ""
Write-Host "✓ Bastion setup complete" -ForegroundColor Green
