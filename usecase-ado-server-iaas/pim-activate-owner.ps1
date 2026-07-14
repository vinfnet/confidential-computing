<#
.SYNOPSIS
    Self-activate an eligible Microsoft Entra PIM role (default: Owner) at
    subscription scope so subsequent role assignments / Key Vault key import
    can succeed. Reversible: the activation expires after -DurationHours.
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId = "68432aaa-6eba-435c-bc7c-1d998d835e80",
    [string]$RoleName = "Owner",
    [int]$DurationHours = 8,
    [string]$Justification = "Confidential ACI ADO agent SKR deploy: assign Key Vault crypto roles + import HSM wrap key.",
    [switch]$WhatIfOnly
)

$ErrorActionPreference = "Stop"

$me = (az ad signed-in-user show --query id -o tsv).Trim()
if (-not $me) { throw "Could not resolve signed-in user object id." }
Write-Host "Signed-in user objectId: $me" -ForegroundColor DarkGray

# Find the caller's eligible PIM schedule for the requested role at this subscription scope.
$scope = "/subscriptions/$SubscriptionId"
$url = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=asTarget()"
$elig = (az rest --method get --url $url -o json | ConvertFrom-Json).value |
    Where-Object { $_.properties.principalId -eq $me -and $_.properties.expandedProperties.roleDefinition.displayName -eq $RoleName } |
    Select-Object -First 1

if (-not $elig) {
    Write-Host "No eligible '$RoleName' PIM assignment found for this user at $scope." -ForegroundColor Yellow
    Write-Host "Eligible roles for this user:" -ForegroundColor DarkGray
    (az rest --method get --url $url -o json | ConvertFrom-Json).value |
        Where-Object { $_.properties.principalId -eq $me } |
        ForEach-Object { "  - {0} @ {1}" -f $_.properties.expandedProperties.roleDefinition.displayName, $_.properties.scope }
    throw "No eligible '$RoleName' role to activate."
}

$roleDefId = $elig.properties.roleDefinitionId
$schedId = $elig.properties.roleEligibilityScheduleId
Write-Host "Found eligible '$RoleName' (roleDefId=$roleDefId)" -ForegroundColor Green

# Is it already active? (avoid duplicate activation requests)
$active = az role assignment list --assignee $me --scope $scope --query "[?roleDefinitionName=='$RoleName'] | [0].roleDefinitionName" -o tsv 2>$null
if ($active) {
    Write-Host "'$RoleName' is already active at $scope. Nothing to do." -ForegroundColor Green
    return
}

$reqName = [guid]::NewGuid().ToString()
$start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$body = @{
    properties = @{
        principalId                      = $me
        roleDefinitionId                 = $roleDefId
        requestType                      = "SelfActivate"
        linkedRoleEligibilityScheduleId  = $schedId
        justification                    = $Justification
        scheduleInfo                     = @{
            startDateTime = $start
            expiration    = @{ type = "AfterDuration"; duration = "PT${DurationHours}H" }
        }
    }
} | ConvertTo-Json -Depth 8

if ($WhatIfOnly) {
    Write-Host "WhatIf: would PUT roleAssignmentScheduleRequest ${reqName}:" -ForegroundColor Cyan
    Write-Host $body
    return
}

$putUrl = "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$reqName`?api-version=2020-10-01"
$tmp = New-TemporaryFile
try {
    Set-Content -Path $tmp -Value $body -Encoding utf8
    Write-Host "Activating '$RoleName' for ${DurationHours}h..." -ForegroundColor Cyan
    $resp = az rest --method put --url $putUrl --body "@$tmp" --headers "Content-Type=application/json" -o json | ConvertFrom-Json
    Write-Host "Activation status: $($resp.properties.status)" -ForegroundColor Green
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
