<#
.SYNOPSIS
Deploy a confidential-node AKS cluster with the virtual nodes add-on and a hello-world workload.

.DESCRIPTION
Creates a new resource group named <prefix><5-random-letters>, provisions an AKS cluster with:
- Azure CNI networking and dedicated subnets for AKS and ACI virtual nodes
- A standard system pool and an AMD SEV-SNP confidential user pool
- The AKS virtual nodes add-on backed by Azure Container Instances
- A public hello-world workload scheduled onto the virtual node

The script checks local dependencies, validates Azure RBAC before provisioning,
attempts to detect PIM eligibility for required roles, registers required resource providers,
and prints a deployment summary including the hello-world endpoint.

.PARAMETER Prefix
Prefix used for resource naming. The resource group will be named <prefix><5 letters>.

.PARAMETER Region
Optional Azure region. If omitted, the script tries supported candidate regions and prefers eastus2.

.PARAMETER SubscriptionId
Optional subscription ID. If omitted, uses the current Azure CLI subscription.

.PARAMETER ConfidentialVmSize
VM size for the confidential node pool. Default: Standard_DC2as_v5.

.PARAMETER SystemVmSize
VM size for the system node pool. Default: Standard_D2as_v7.

.PARAMETER SystemNodeCount
Node count for the system pool. Default: 1.

.PARAMETER ConfidentialNodeCount
Node count for the confidential pool. Default: 1.

.PARAMETER SkipExternalSmokeTest
Skip the external HTTP check against the public load balancer.

.PARAMETER VisualAttestationUrl
Optional explicit URL (or FQDN) for the visual attestation container to display in the final summary.

.PARAMETER VisualAttestationResourceGroup
Resource group used to auto-discover a visual attestation container FQDN when VisualAttestationUrl is not provided.

.PARAMETER VisualAttestationContainerPrefix
Container name prefix used to auto-discover a visual attestation container FQDN.

.PARAMETER AutoActivatePim
Automatically submit a native Azure PowerShell PIM self-activation request for the first eligible role.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Prefix,

    [string]$Region = "",
    [string]$SubscriptionId = "",
    [string]$ConfidentialVmSize = "Standard_DC2as_v5",
    [string]$SystemVmSize = "Standard_D2as_v7",
    [int]$SystemNodeCount = 1,
    [int]$ConfidentialNodeCount = 1,
    [switch]$SkipExternalSmokeTest,
    [string]$VisualAttestationUrl = "",
    [string]$VisualAttestationResourceGroup = "sgall-acrqlyusoeg-rg",
    [string]$VisualAttestationContainerPrefix = "cc-attest-conf-",
    [switch]$AutoActivatePim
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Write-Detail {
    param([string]$Message)
    Write-Host $Message -ForegroundColor DarkGray
}

function New-RandomLetters {
    param([int]$Count = 5)
    -join ((97..122) | Get-Random -Count $Count | ForEach-Object { [char]$_ })
}

function New-SafeName {
    param(
        [string]$Raw,
        [int]$MaxLength,
        [string]$Fallback = "sample"
    )

    $value = ($Raw.ToLowerInvariant() -replace "[^a-z0-9-]", "")
    $value = $value.Trim('-')
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $Fallback
    }
    if ($value.Length -gt $MaxLength) {
        $value = $value.Substring(0, $MaxLength).Trim('-')
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = $Fallback
    }
    return $value
}

function Invoke-Az {
    param([string]$CommandText)
    Write-Detail "-> $CommandText"
    $result = Invoke-Expression $CommandText
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $CommandText"
    }
    return $result
}

function Read-Confirmation {
    param(
        [string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $response = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $DefaultYes
    }

    switch -Regex ($response.Trim()) {
        '^(y|yes)$' { return $true }
        '^(n|no)$' { return $false }
        default {
            Write-Host "Please answer yes or no." -ForegroundColor Yellow
            return Read-Confirmation -Prompt $Prompt -DefaultYes:$DefaultYes
        }
    }
}

function Ensure-Command {
    param(
        [string]$CommandName,
        [string]$InstallHint,
        [scriptblock]$Installer = $null
    )

    if (Get-Command $CommandName -ErrorAction SilentlyContinue) {
        return
    }

    Write-Host "$CommandName was not found on PATH." -ForegroundColor Yellow
    if ($Installer -and (Read-Confirmation -Prompt "Install $CommandName now?" -DefaultYes $true)) {
        & $Installer
        if (Get-Command $CommandName -ErrorAction SilentlyContinue) {
            return
        }
    }

    throw "$CommandName is required before this script can continue. $InstallHint"
}

function Ensure-AzureCli {
    Ensure-Command -CommandName "az" -InstallHint "Install Azure CLI from https://learn.microsoft.com/cli/azure/install-azure-cli-windows and rerun the script." -Installer {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "winget is not available for unattended Azure CLI installation. Install Azure CLI from https://learn.microsoft.com/cli/azure/install-azure-cli-windows."
        }
        winget install -e --id Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements
    }
}

function Ensure-AzPowerShell {
    $requiredCommands = @(
        'Connect-AzAccount',
        'Get-AzContext',
        'Set-AzContext',
        'Invoke-AzRestMethod',
        'Get-AzRoleAssignment',
        'Get-AzRoleDefinition',
        'Get-AzRoleEligibilityScheduleInstance',
        'New-AzRoleAssignmentScheduleRequest'
    )

    foreach ($commandName in $requiredCommands) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "Azure PowerShell cmdlet '$commandName' is required. Install or update the Az modules before running this script."
        }
    }
}

function Ensure-Kubectl {
    if (Get-Command kubectl -ErrorAction SilentlyContinue) {
        return
    }

    Write-Host "kubectl was not found on PATH." -ForegroundColor Yellow
    if (-not (Read-Confirmation -Prompt "Install kubectl using 'az aks install-cli'?" -DefaultYes $true)) {
        throw "kubectl is required before this script can continue."
    }

    Invoke-Az "az aks install-cli --only-show-errors"
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        throw "kubectl installation did not complete successfully."
    }
}

function Ensure-AksPreviewExtension {
    try {
        $null = Invoke-Az "az extension show --name aks-preview --output json" | ConvertFrom-Json
        return
    } catch {
        Write-Host "Azure CLI extension 'aks-preview' is not installed." -ForegroundColor Yellow
    }

    if (-not (Read-Confirmation -Prompt "Install Azure CLI extension 'aks-preview' now?" -DefaultYes $true)) {
        throw "The aks-preview extension is required for consistent virtual nodes behavior in this sample."
    }

    Invoke-Az "az extension add --name aks-preview --upgrade --only-show-errors"
}

function Ensure-AzureLogin {
    try {
        $null = Invoke-Az "az account show --output json" | ConvertFrom-Json
    } catch {
        Write-Host "Azure CLI is not logged in." -ForegroundColor Yellow
        Invoke-Az "az login --output none"
    }
}

function Ensure-AzLogin {
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($context) {
            return
        }
    } catch {
    }

    Write-Host "Azure PowerShell is not logged in." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
}

function Get-CurrentAccount {
    Invoke-Az "az account show --output json" | ConvertFrom-Json
}

function Get-OwnerUpn {
    $upn = ""
    try {
        $upn = (Invoke-Az "az ad signed-in-user show --query userPrincipalName --output tsv").Trim()
    } catch {
    }
    if (-not $upn) {
        $upn = (Invoke-Az "az account show --query user.name --output tsv").Trim()
    }
    return $upn
}

function Get-SignedInObjectId {
    try {
        return (Invoke-Az "az ad signed-in-user show --query id --output tsv").Trim()
    } catch {
        return ""
    }
}

function Test-RoleAssignmentPermission {
    param(
        [string]$SubscriptionId,
        [string]$Upn
    )

    $scope = "/subscriptions/$SubscriptionId"
    $allowedRoles = @(
        "Owner",
        "User Access Administrator",
        "Role Based Access Control Administrator"
    )

    $assignments = @(Get-AzRoleAssignment -SignInName $Upn -ExpandPrincipalGroups -ErrorAction Stop |
        Where-Object {
            ($allowedRoles -contains $_.RoleDefinitionName) -and
            $_.Scope -and
            $scope.StartsWith([string]$_.Scope, [System.StringComparison]::OrdinalIgnoreCase)
        })
    $permissionsResponse = Invoke-AzRestMethod -Path "$scope/providers/Microsoft.Authorization/permissions?api-version=2015-07-01" -Method GET
    $permissions = ($permissionsResponse.Content | ConvertFrom-Json).value

    $grantsRoleAssignmentWrite = $false

    foreach ($entry in @($permissions)) {
        $actions = @($entry.actions)
        $notActions = @($entry.notActions)
        $allowsWrite = ($actions -contains "*") -or ($actions -contains "Microsoft.Authorization/*") -or ($actions -contains "Microsoft.Authorization/roleAssignments/*") -or ($actions -contains "Microsoft.Authorization/roleAssignments/write")
        $deniesWrite = ($notActions -contains "Microsoft.Authorization/*") -or ($notActions -contains "Microsoft.Authorization/roleAssignments/*") -or ($notActions -contains "Microsoft.Authorization/roleAssignments/write")

        if ($allowsWrite -and -not $deniesWrite) {
            $grantsRoleAssignmentWrite = $true
            break
        }
    }

    [pscustomobject]@{
        Scope = $scope
        AllowedRoles = $allowedRoles
        MatchingAssignments = $assignments
        CanAssignRoles = $assignments.Count -gt 0 -and $grantsRoleAssignmentWrite
        HasMatchingRole = $assignments.Count -gt 0
        HasEffectiveWritePermission = $grantsRoleAssignmentWrite
    }
}

function Get-PimEligibleRoleSchedules {
    param(
        [string]$SubscriptionId,
        [string]$PrincipalObjectId,
        [string[]]$RoleNames
    )

    if ([string]::IsNullOrWhiteSpace($PrincipalObjectId)) {
        return @()
    }

    $scope = "/subscriptions/$SubscriptionId"
    $allowedDefinitions = @{}
    foreach ($roleName in $RoleNames) {
        $definition = Get-AzRoleDefinition -Name $roleName -ErrorAction SilentlyContinue
        if ($definition) {
            $allowedDefinitions[[string]$definition.Id] = $roleName
        }
    }

    if ($allowedDefinitions.Count -eq 0) {
        return @()
    }

    $schedules = @(Get-AzRoleEligibilityScheduleInstance -Scope $scope -Filter "asTarget()" -ErrorAction Stop)
    $matches = foreach ($schedule in $schedules) {
        if ($schedule.PrincipalId -ne $PrincipalObjectId) {
            continue
        }
        if ($schedule.Scope -and -not $schedule.Scope.StartsWith($scope, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $matchedRole = $null
        foreach ($allowedId in $allowedDefinitions.Keys) {
            if ([string]$schedule.RoleDefinitionId -match [regex]::Escape($allowedId)) {
                $matchedRole = $allowedDefinitions[$allowedId]
                break
            }
        }

        if ($matchedRole) {
            [pscustomobject]@{
                RoleName = $matchedRole
                RoleDefinitionId = [string]$schedule.RoleDefinitionId
                Scope = [string]$schedule.Scope
            }
        }
    }

    return @($matches | Sort-Object RoleName -Unique)
}

function Invoke-PimSelfActivation {
    param(
        [string]$Scope,
        [string]$PrincipalObjectId,
        [string]$RoleDefinitionId,
        [string]$RoleName
    )

    $requestName = [guid]::NewGuid().Guid
    $startTime = (Get-Date).ToUniversalTime().ToString("o")
    $justification = "Activate $RoleName for AKS virtual nodes sample deployment"

    New-AzRoleAssignmentScheduleRequest `
        -Name $requestName `
        -Scope $Scope `
        -PrincipalId $PrincipalObjectId `
        -RequestType SelfActivate `
        -RoleDefinitionId $RoleDefinitionId `
        -ScheduleInfoStartDateTime $startTime `
        -ExpirationType AfterDuration `
        -ExpirationDuration PT8H `
        -Justification $justification | Out-Null
}

function Assert-DeploymentRoles {
    param(
        [string]$SubscriptionId,
        [string]$Upn,
        [string]$PrincipalObjectId
    )

    Write-Header "Checking required Azure roles"

    $permission = Test-RoleAssignmentPermission -SubscriptionId $SubscriptionId -Upn $Upn
    if ($permission.CanAssignRoles) {
        $roles = ($permission.MatchingAssignments | Select-Object -ExpandProperty roleDefinitionName -Unique) -join ", "
        Write-Host "Verified role-assignment capability at $($permission.Scope)" -ForegroundColor Green
        Write-Host "Active role(s): $roles"
        return
    }

    $eligibleSchedules = @(Get-PimEligibleRoleSchedules -SubscriptionId $SubscriptionId -PrincipalObjectId $PrincipalObjectId -RoleNames $permission.AllowedRoles)
    if ($eligibleSchedules.Count -gt 0) {
        $eligibleRoleNames = $eligibleSchedules.RoleName | Sort-Object -Unique
        Write-Host "No active role currently grants roleAssignments/write at $($permission.Scope)." -ForegroundColor Yellow
        Write-Host "PIM appears to offer these eligible roles: $($eligibleRoleNames -join ', ')" -ForegroundColor Yellow

        $activationTarget = $eligibleSchedules | Where-Object { $_.RoleName -eq 'Owner' } | Select-Object -First 1
        if (-not $activationTarget) {
            $activationTarget = $eligibleSchedules | Select-Object -First 1
        }

        $shouldActivate = $false
        if ($activationTarget) {
            $shouldActivate = $AutoActivatePim -or (Read-Confirmation -Prompt "Activate PIM role '$($activationTarget.RoleName)' now using Azure PowerShell?" -DefaultYes $true)
        }

        if ($activationTarget -and $shouldActivate) {
            Invoke-PimSelfActivation -Scope $permission.Scope -PrincipalObjectId $PrincipalObjectId -RoleDefinitionId $activationTarget.RoleDefinitionId -RoleName $activationTarget.RoleName

            $deadline = (Get-Date).AddMinutes(5)
            do {
                Start-Sleep -Seconds 10
                $permission = Test-RoleAssignmentPermission -SubscriptionId $SubscriptionId -Upn $Upn
                if ($permission.CanAssignRoles) {
                    $roles = ($permission.MatchingAssignments | Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ", "
                    Write-Host "Verified role-assignment capability after PIM activation." -ForegroundColor Green
                    Write-Host "Active role(s): $roles"
                    return
                }
            } while ((Get-Date) -lt $deadline)

            Write-Host "PIM activation request submitted, but the role is not active yet." -ForegroundColor Yellow
        }

        Write-Host "Activate one of those roles for this subscription, wait for it to become active, then return here." -ForegroundColor Yellow
        [void](Read-Host "Press Enter after PIM activation to retry the permission check")

        $permission = Test-RoleAssignmentPermission -SubscriptionId $SubscriptionId -Upn $Upn
        if ($permission.CanAssignRoles) {
            $roles = ($permission.MatchingAssignments | Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ", "
            Write-Host "Verified role-assignment capability after PIM activation." -ForegroundColor Green
            Write-Host "Active role(s): $roles"
            return
        }
    }

    $expected = $permission.AllowedRoles -join ", "
    $detail = if ($permission.HasMatchingRole -and -not $permission.HasEffectiveWritePermission) {
        "A matching role assignment exists, but the current token does not have effective Microsoft.Authorization/roleAssignments/write yet. Refresh Azure CLI authentication after PIM activation and rerun the script."
    } else {
        "No active assignment was found that can grant roleAssignments/write at the required scope."
    }

    $message = @(
        "Missing required Azure RBAC permissions before deployment starts.",
        "This script needs one of these active roles at subscription scope: $expected.",
        "Checked scope: $($permission.Scope)",
        $detail,
        "If your organization uses Microsoft Entra PIM, activate one of those roles and rerun the script.",
        "No resources were created because the check ran before provisioning."
    ) -join " `n"

    throw $message
}

function Ensure-ProviderRegistered {
    param([string]$Namespace)

    $state = ""
    try {
        $state = (Invoke-Az "az provider show --namespace $Namespace --query registrationState --output tsv").Trim()
    } catch {
    }

    if ($state -eq "Registered") {
        return
    }

    Write-Host "Registering provider '$Namespace'" -ForegroundColor Yellow
    Invoke-Az "az provider register --namespace $Namespace --output none"

    $deadline = (Get-Date).AddMinutes(10)
    do {
        Start-Sleep -Seconds 10
        $state = (Invoke-Az "az provider show --namespace $Namespace --query registrationState --output tsv").Trim()
        if ($state -eq "Registered") {
            return
        }
    } while ((Get-Date) -lt $deadline)

    throw "Provider '$Namespace' did not reach Registered state in time."
}

function Test-VmSizeAvailability {
    param(
        [string]$Location,
        [string]$VmSize
    )

    try {
        $sku = Get-AzComputeResourceSku -Location $Location -ErrorAction Stop |
            Where-Object { $_.ResourceType -eq 'virtualMachines' -and $_.Name -eq $VmSize } |
            Select-Object -First 1
    } catch {
        return $null
    }

    if ($null -eq $sku) {
        return $null
    }

    $restrictions = @($sku.restrictions)
    $blocked = $false
    foreach ($restriction in $restrictions) {
        if ($restriction.reasonCode -eq "NotAvailableForSubscription") {
            $blocked = $true
            break
        }
        if ($restriction.restrictionInfo -and $restriction.restrictionInfo.locations -and ($restriction.restrictionInfo.locations -contains $Location)) {
            $blocked = $true
            break
        }
    }

    if ($blocked) {
        return $null
    }

    return $sku
}

function Test-ConfidentialSkuAvailability {
    param(
        [string]$Location,
        [string]$VmSize
    )

    return Test-VmSizeAvailability -Location $Location -VmSize $VmSize
}

function Resolve-DeploymentLocation {
    param(
        [string]$RequestedLocation,
        [string]$VmSize
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedLocation)) {
        $requested = $RequestedLocation.Trim().ToLowerInvariant()
        if ($null -eq (Test-ConfidentialSkuAvailability -Location $requested -VmSize $VmSize)) {
            throw "Requested region '$requested' does not currently report $VmSize as available for this subscription. Choose another region or omit -Region to auto-select."
        }
        return $requested
    }

    $candidates = @("eastus2", "centralus", "westus3", "southcentralus", "northeurope")
    foreach ($candidate in $candidates) {
        if ($null -ne (Test-ConfidentialSkuAvailability -Location $candidate -VmSize $VmSize)) {
            return $candidate
        }
    }

    throw "Could not find a candidate region with visible availability for $VmSize. Provide -Region explicitly after checking SKU availability in your subscription."
}

function Resolve-SystemVmSize {
    param(
        [string]$Location,
        [string]$RequestedVmSize
    )

    if ($null -ne (Test-VmSizeAvailability -Location $Location -VmSize $RequestedVmSize)) {
        return $RequestedVmSize
    }

    $fallbacks = @(
        'Standard_D2as_v7',
        'Standard_D2as_v6',
        'Standard_D4as_v7',
        'Standard_D4as_v6',
        'Standard_D4ads_v5'
    )

    foreach ($candidate in $fallbacks) {
        if ($candidate -eq $RequestedVmSize) {
            continue
        }
        if ($null -ne (Test-VmSizeAvailability -Location $Location -VmSize $candidate)) {
            Write-Host "System VM size '$RequestedVmSize' is not currently allowed in '$Location'. Falling back to '$candidate'." -ForegroundColor Yellow
            return $candidate
        }
    }

    throw "Could not find an allowed system node pool VM size in '$Location'. Provide -SystemVmSize explicitly after checking allowed SKUs for this subscription."
}

function Wait-ForManagedIdentity {
    param(
        [string]$ResourceGroup,
        [string]$IdentityName,
        [int]$TimeoutSeconds = 600
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $principalId = (Invoke-Az "az identity show --resource-group $ResourceGroup --name $IdentityName --query principalId --output tsv").Trim()
            if ($principalId) {
                return $principalId
            }
        } catch {
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)

    throw "Managed identity '$IdentityName' was not discoverable in resource group '$ResourceGroup' in time."
}

function Ensure-RoleAssignment {
    param(
        [string]$AssigneeObjectId,
        [string]$RoleName,
        [string]$Scope
    )

    $existing = ""
    try {
        $existing = (Invoke-Az "az role assignment list --assignee-object-id $AssigneeObjectId --scope $Scope --role `"$RoleName`" --query '[0].id' --output tsv").Trim()
    } catch {
    }

    if ($existing) {
        return
    }

    Invoke-Az "az role assignment create --assignee-object-id $AssigneeObjectId --assignee-principal-type ServicePrincipal --role `"$RoleName`" --scope $Scope --output none"
}

function Wait-ForVirtualNode {
    param([int]$TimeoutSeconds = 900)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $nodeNames = kubectl get nodes -l type=virtual-kubelet -o name 2>$null
            if ($LASTEXITCODE -eq 0 -and $nodeNames) {
                return ($nodeNames | Select-Object -First 1).Replace("node/", "")
            }
        } catch {
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for the virtual node to become Ready in Kubernetes."
}

function Wait-ForServiceEndpoint {
    param(
        [string]$Namespace,
        [string]$ServiceName,
        [int]$TimeoutSeconds = 900
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $payload = kubectl get service $ServiceName -n $Namespace -o json 2>$null
        if ($LASTEXITCODE -eq 0 -and $payload) {
            $service = $payload | ConvertFrom-Json
            $ingress = @($service.status.loadBalancer.ingress)
            if ($ingress.Count -gt 0) {
                $ip = [string]$ingress[0].ip
                $hostname = [string]$ingress[0].hostname
                if ($ip) {
                    return $ip
                }
                if ($hostname) {
                    return $hostname
                }
            }
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)

    return ""
}

function Invoke-InternalSmokeTest {
    param(
        [string]$Namespace,
        [string]$ServiceName
    )

    Write-Header "Running in-cluster smoke test"
    kubectl delete pod virtual-node-probe --ignore-not-found | Out-Null
    kubectl run virtual-node-probe --image=curlimages/curl:8.9.1 --restart=Never --command -- sleep 300 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the in-cluster probe pod."
    }

    kubectl wait --for=condition=Ready pod/virtual-node-probe --timeout=300s | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The in-cluster probe pod did not become Ready in time."
    }

    $response = kubectl exec virtual-node-probe -- curl -L --silent --show-error "http://$ServiceName.$Namespace.svc.cluster.local"
    if ($LASTEXITCODE -ne 0) {
        throw "Internal curl probe failed against service '$ServiceName'."
    }

    if ($response -notmatch "Welcome to Azure Container Instances") {
        throw "Internal curl probe completed, but the expected hello-world payload was not returned."
    }

    kubectl delete pod virtual-node-probe --ignore-not-found | Out-Null
}

function Invoke-ExternalSmokeTest {
    param(
        [string]$Endpoint,
        [int]$TimeoutSeconds = 300
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri ("http://{0}" -f $Endpoint) -UseBasicParsing -TimeoutSec 20
            if ($response.Content -match "Welcome to Azure Container Instances") {
                return
            }
        } catch {
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $deadline)

    Write-Warning "The external load balancer endpoint '$Endpoint' did not respond in time. This is common in restricted network environments (VPN, corp firewall). The in-cluster smoke test already confirmed the workload is healthy."
}

function Resolve-VisualAttestationLink {
    param(
        [string]$ExplicitUrl,
        [string]$ResourceGroup,
        [string]$ContainerPrefix
    )

    if ($ExplicitUrl) {
        $trimmed = $ExplicitUrl.Trim()
        if ($trimmed -match '^https?://') {
            return $trimmed
        }
        return "http://$trimmed"
    }

    if (-not $ResourceGroup -or -not $ContainerPrefix) {
        return $null
    }

    try {
        $containers = az container list --resource-group $ResourceGroup --query "[?starts_with(name, '$ContainerPrefix')].{name:name,fqdn:ipAddress.fqdn}" --output json 2>$null | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $containers) {
            return $null
        }

        $candidate = $containers |
            Where-Object { $_.fqdn } |
            Sort-Object name -Descending |
            Select-Object -First 1

        if (-not $candidate) {
            return $null
        }

        return "http://$($candidate.fqdn)"
    }
    catch {
        return $null
    }
}

Write-Header "Preparing deployment"

Ensure-AzureCli
Ensure-AzPowerShell
Ensure-AzureLogin
Ensure-AzLogin
Ensure-Kubectl
Ensure-AksPreviewExtension

if ($SubscriptionId) {
    Invoke-Az "az account set --subscription $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$account = Get-CurrentAccount
$activeSubscriptionId = [string]$account.id
$ownerUpn = Get-OwnerUpn
$principalObjectId = Get-SignedInObjectId

if ([string]::IsNullOrWhiteSpace($ownerUpn)) {
    throw "Could not resolve the current Azure user from Azure CLI."
}

Assert-DeploymentRoles -SubscriptionId $activeSubscriptionId -Upn $ownerUpn -PrincipalObjectId $principalObjectId

Write-Header "Checking subscription prerequisites"
Ensure-ProviderRegistered -Namespace "Microsoft.ContainerService"
Ensure-ProviderRegistered -Namespace "Microsoft.ContainerInstance"
Ensure-ProviderRegistered -Namespace "Microsoft.Network"

$deploymentLocation = Resolve-DeploymentLocation -RequestedLocation $Region -VmSize $ConfidentialVmSize
$SystemVmSize = Resolve-SystemVmSize -Location $deploymentLocation -RequestedVmSize $SystemVmSize

$scriptName = $MyInvocation.MyCommand.Name
$gitRemoteUrl = ""
try { $gitRemoteUrl = (git remote get-url origin) -replace "\.git$", "" } catch {}
if (-not $gitRemoteUrl) {
    $gitRemoteUrl = "https://github.com/Azure-Samples/confidential-computing"
}

$prefixSafe = New-SafeName -Raw $Prefix -MaxLength 10 -Fallback "vnode"
$random5 = New-RandomLetters -Count 5

$resourceGroupName = "$prefixSafe$random5"
$aksName = New-SafeName -Raw "$prefixSafe-aks" -MaxLength 63 -Fallback "vnode-aks"
$vnetName = New-SafeName -Raw "$prefixSafe-vnet" -MaxLength 64 -Fallback "vnode-vnet"
$aksSubnetName = "aks-subnet"
$aciSubnetName = "aci-subnet"
$systemPoolName = "syspool"
$confidentialPoolName = "ccpool"
$namespaceName = "virtualnodes-demo"
$serviceName = "aci-helloworld"
$manifestPath = Join-Path $PSScriptRoot "virtual-node-hello-world.yaml"

$tags = @{
    owner = $ownerUpn
    BuiltBy = $scriptName
    GitRepo = $gitRemoteUrl
    Workload = "virtual-nodes"
    Scenario = "confidential-aks-aci"
}
$tagArgs = ($tags.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join " "

Write-Host "Subscription:  $activeSubscriptionId"
Write-Host "Owner:         $ownerUpn"
Write-Host "Region:        $deploymentLocation"
Write-Host "ResourceGroup: $resourceGroupName"
Write-Host "AKS Cluster:   $aksName"
Write-Host "VNet:          $vnetName"
Write-Host "System Pool:   $SystemNodeCount x $SystemVmSize"
Write-Host "CC Pool:       $ConfidentialNodeCount x $ConfidentialVmSize"

Write-Header "Creating resource group and networking"
Invoke-Az "az group create --name $resourceGroupName --location $deploymentLocation --tags $tagArgs --output table"
Invoke-Az "az network vnet create --resource-group $resourceGroupName --location $deploymentLocation --name $vnetName --address-prefixes 10.240.0.0/12 --subnet-name $aksSubnetName --subnet-prefixes 10.240.0.0/16 --tags $tagArgs --output table"
Invoke-Az "az network vnet subnet create --resource-group $resourceGroupName --vnet-name $vnetName --name $aciSubnetName --address-prefixes 10.241.0.0/16 --output table"

$aksSubnetId = (Invoke-Az "az network vnet subnet show --resource-group $resourceGroupName --vnet-name $vnetName --name $aksSubnetName --query id --output tsv").Trim()
$aciSubnetId = (Invoke-Az "az network vnet subnet show --resource-group $resourceGroupName --vnet-name $vnetName --name $aciSubnetName --query id --output tsv").Trim()
$aciSubnetNsgId = (Invoke-Az "az network vnet subnet show --resource-group $resourceGroupName --vnet-name $vnetName --name $aciSubnetName --query networkSecurityGroup.id --output tsv").Trim()
$vnetId = (Invoke-Az "az network vnet show --resource-group $resourceGroupName --name $vnetName --query id --output tsv").Trim()

Write-Header "Creating AKS cluster"
Invoke-Az @"
az aks create --resource-group $resourceGroupName --name $aksName --location $deploymentLocation --node-count $SystemNodeCount --nodepool-name $systemPoolName --node-vm-size $SystemVmSize --os-sku Ubuntu --enable-managed-identity --generate-ssh-keys --network-plugin azure --vnet-subnet-id $aksSubnetId --service-cidr 10.2.0.0/24 --dns-service-ip 10.2.0.10 --auto-upgrade-channel stable --node-os-upgrade-channel NodeImage --tier standard --tags $tagArgs --only-show-errors
"@

Write-Header "Adding confidential node pool"
Invoke-Az @"
az aks nodepool add --resource-group $resourceGroupName --cluster-name $aksName --name $confidentialPoolName --node-count $ConfidentialNodeCount --node-vm-size $ConfidentialVmSize --os-sku Ubuntu --mode User --labels workload=confidential sku=amd-sev-snp --tags owner=$ownerUpn BuiltBy=$scriptName Workload=virtual-nodes CCType=AMD-SEV-SNP --only-show-errors
"@

Write-Header "Waiting for AKS operation to complete"
Invoke-Az "az aks wait --resource-group $resourceGroupName --name $aksName --updated --interval 15 --timeout 1800"

Write-Header "Enabling virtual nodes"
Invoke-Az "az aks enable-addons --resource-group $resourceGroupName --name $aksName --addons virtual-node --subnet-name $aciSubnetName --only-show-errors"

$nodeResourceGroup = (Invoke-Az "az aks show --resource-group $resourceGroupName --name $aksName --query nodeResourceGroup --output tsv").Trim()
$aciConnectorIdentity = "aciconnectorlinux-$aksName"
$aciConnectorPrincipalId = Wait-ForManagedIdentity -ResourceGroup $nodeResourceGroup -IdentityName $aciConnectorIdentity

Write-Header "Assigning subnet rights to the virtual nodes identity"
Ensure-RoleAssignment -AssigneeObjectId $aciConnectorPrincipalId -RoleName "Network Contributor" -Scope $aciSubnetId
Ensure-RoleAssignment -AssigneeObjectId $aciConnectorPrincipalId -RoleName "Network Contributor" -Scope $vnetId
if ($aciSubnetNsgId) {
    Ensure-RoleAssignment -AssigneeObjectId $aciConnectorPrincipalId -RoleName "Network Contributor" -Scope $aciSubnetNsgId
}

Write-Header "Connecting kubectl"
Invoke-Az "az aks get-credentials --resource-group $resourceGroupName --name $aksName --overwrite-existing --only-show-errors"
kubectl get nodes -o wide
if ($LASTEXITCODE -ne 0) {
    throw "kubectl could not reach the new AKS cluster."
}

# Force the connector to restart after RBAC assignment so it refreshes network access promptly.
kubectl delete pod -n kube-system -l app=aci-connector-linux --ignore-not-found | Out-Null

$virtualNodeName = Wait-ForVirtualNode
Write-Host "Virtual node detected: $virtualNodeName" -ForegroundColor Green

Write-Header "Deploying hello-world workload to the virtual node"
kubectl apply -f $manifestPath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply $manifestPath"
}

kubectl rollout status deployment/$serviceName -n $namespaceName --timeout=900s
if ($LASTEXITCODE -ne 0) {
    throw "The hello-world deployment did not become ready in time."
}

kubectl get pods -n $namespaceName -o wide
if ($LASTEXITCODE -ne 0) {
    throw "Failed to list hello-world pods."
}

Invoke-InternalSmokeTest -Namespace $namespaceName -ServiceName $serviceName

$externalEndpoint = Wait-ForServiceEndpoint -Namespace $namespaceName -ServiceName $serviceName
if (-not $SkipExternalSmokeTest -and $externalEndpoint) {
    Write-Header "Running external smoke test"
    Invoke-ExternalSmokeTest -Endpoint $externalEndpoint
}

$visualAttestationLink = Resolve-VisualAttestationLink -ExplicitUrl $VisualAttestationUrl -ResourceGroup $VisualAttestationResourceGroup -ContainerPrefix $VisualAttestationContainerPrefix

Write-Header "Deployment summary"
Write-Host "Resource group:            $resourceGroupName"
Write-Host "Region:                    $deploymentLocation"
Write-Host "AKS cluster:               $aksName"
Write-Host "Node resource group:       $nodeResourceGroup"
Write-Host "Virtual node identity:     $aciConnectorIdentity"
Write-Host "System pool:               $SystemNodeCount x $SystemVmSize"
Write-Host "Confidential pool:         $ConfidentialNodeCount x $ConfidentialVmSize"
Write-Host "Virtual node subnet:       $aciSubnetId"
Write-Host "Hello-world namespace:     $namespaceName"
Write-Host "Hello-world service:       $serviceName"
if ($externalEndpoint) {
    Write-Host "Public endpoint:           http://$externalEndpoint"
} else {
    Write-Host "Public endpoint:           Pending. Run 'kubectl get service $serviceName -n $namespaceName' to watch for assignment."
}
if ($visualAttestationLink) {
    Write-Host "Visual attestation link:   $visualAttestationLink"
} else {
    Write-Host "Visual attestation link:   Not detected. Pass -VisualAttestationUrl to set it explicitly."
}

Write-Host ""
Write-Host "How to access the sample:" -ForegroundColor Green
if ($externalEndpoint) {
    Write-Host "- Browse to http://$externalEndpoint"
}
if ($visualAttestationLink) {
    Write-Host "- Browse to $visualAttestationLink"
}
Write-Host "- Inspect the pod placement with: kubectl get pods -n $namespaceName -o wide"
Write-Host "- Inspect the virtual node with: kubectl get nodes -l type=virtual-kubelet -o wide"
Write-Host "- List backing container groups with: az container list --resource-group $nodeResourceGroup -o table"
Write-Host ""
Write-Host "This first version validates virtual nodes on a confidential-node AKS cluster and deploys a standard ACI hello-world image. Moving to a confidential ACI image is a follow-on step once you provide a CCE-policy-based container manifest." -ForegroundColor Yellow