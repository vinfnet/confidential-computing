<#
.SYNOPSIS
Stage Upgrade-AdoServer.ps1 onto the Azure DevOps Server CVM and open a Bastion
RDP session so you can run the (visible) upgrade interactively.

.DESCRIPTION
The ADO Server CVM is only reachable through Bastion and the installer needs its
UI, so this wrapper does the plumbing from your workstation:

  1. Uses `az vm run-command` to write Upgrade-AdoServer.ps1 into C:\Temp on the
     server VM (no file share / SCP needed).
  2. Opens an `az network bastion rdp` session to that VM.

Then, inside the RDP session, open an ELEVATED PowerShell and run:

    Set-Location C:\Temp
    ./Upgrade-AdoServer.ps1                 # defaults to 2022.2 (.NET 8 agent)

.PARAMETER SubscriptionId
Azure subscription id. Defaults to the env value or the known RnD subscription.

.PARAMETER ResourceGroup
Resource group of the ADO Server CVM. Default SGALLDHFAY.

.PARAMETER VmName
Name of the ADO Server CVM. Default sgalldhfay.

.PARAMETER BastionName
Bastion host name. Default <vmname>vnet-bastion.

.PARAMETER SkipRdp
Only stage the script; do not open the RDP session.

.EXAMPLE
./Invoke-AdoServerUpgrade.ps1

.EXAMPLE
./Invoke-AdoServerUpgrade.ps1 -ResourceGroup SGALLDHFAY -VmName sgalldhfay -SkipRdp
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = $(if ($env:AZURE_SUBSCRIPTION_ID) { $env:AZURE_SUBSCRIPTION_ID } else { "68432aaa-6eba-435c-bc7c-1d998d835e80" }),

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup = "SGALLDHFAY",

    [Parameter(Mandatory = $false)]
    [string]$VmName = "sgalldhfay",

    [Parameter(Mandatory = $false)]
    [string]$BastionName = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipRdp
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$localScript = Join-Path $scriptDir "Upgrade-AdoServer.ps1"
if (-not (Test-Path $localScript)) {
    throw "Cannot find Upgrade-AdoServer.ps1 next to this wrapper at $localScript."
}

if ([string]::IsNullOrWhiteSpace($BastionName)) {
    $BastionName = "$VmName" + "vnet-bastion"
}

Write-Step "Ensuring VM is running"
az vm start -g $ResourceGroup -n $VmName --subscription $SubscriptionId -o none 2>$null
# 'already running' returns non-zero; ignore.

Write-Step "Staging Upgrade-AdoServer.ps1 onto $VmName (C:\Temp)"

# Build a run-command script that recreates the file on the server from a base64
# blob (avoids any quoting/encoding issues with the multi-line content).
$bytes   = [System.IO.File]::ReadAllBytes($localScript)
$b64     = [Convert]::ToBase64String($bytes)
$stager  = @"
`$dir = 'C:\Temp'
if (-not (Test-Path `$dir)) { New-Item -Path `$dir -ItemType Directory -Force | Out-Null }
`$b64 = '$b64'
`$bytes = [Convert]::FromBase64String(`$b64)
[System.IO.File]::WriteAllBytes((Join-Path `$dir 'Upgrade-AdoServer.ps1'), `$bytes)
Write-Output "Staged to C:\Temp\Upgrade-AdoServer.ps1 (`$(`$bytes.Length) bytes)"
"@

$stagerFile = Join-Path $env:TEMP "stage-upgrade-ado.ps1"
Set-Content -Path $stagerFile -Value $stager -Encoding utf8 -NoNewline

$result = az vm run-command invoke `
    -g $ResourceGroup -n $VmName --subscription $SubscriptionId `
    --command-id RunPowerShellScript `
    --scripts "@$stagerFile" `
    --query "value[0].message" -o tsv

Write-Host $result -ForegroundColor Green
Remove-Item $stagerFile -ErrorAction SilentlyContinue

if ($SkipRdp) {
    Write-Step "Done (staging only)"
    Write-Host "Open RDP later, then in an elevated PowerShell on the VM run:" -ForegroundColor Yellow
    Write-Host "  Set-Location C:\Temp; ./Upgrade-AdoServer.ps1        # defaults to 2022.2 (.NET 8 agent)" -ForegroundColor Yellow
    return
}

Write-Step "Opening Bastion RDP to $VmName"
Write-Host "In the RDP session, open an ELEVATED PowerShell and run:" -ForegroundColor Yellow
Write-Host "  Set-Location C:\Temp" -ForegroundColor Yellow
Write-Host "  ./Upgrade-AdoServer.ps1        # defaults to 2022.2 (.NET 8 agent)" -ForegroundColor Yellow

$vmResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$VmName"
az network bastion rdp `
    --name $BastionName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --target-resource-id $vmResourceId
