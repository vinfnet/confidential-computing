# Function to analyze Customer Managed Keys (CMK) in a resource group
# April 2025
# Tested on Windows (PWSH 7.4.6)
#
# Simon Gallagher, ACC Product Group
# Use at your own risk, no warranties implied, test in a non-production environment first
#
# Usage: 
#   .\DetectCMKStatus.ps1 -ResourceGroupName "myRG"
#   .\DetectCMKStatus.ps1 -ResourceGroupName "myRG" -Csv "C:\reports\cmk-status.csv"
#
# Or dot-source and call the function directly:
#   . .\DetectCMKStatus.ps1
#   Get-CMKStatus -ResourceGroupName "myRG"

param (
    [Parameter(Mandatory)]$ResourceGroupName,
    [Parameter(Mandatory = $false)][string]$Csv
)

function Get-CMKStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $false)]
        [string]$Csv
    )

    $context = Get-AzContext
    if (-not $context) {
        Write-Error "No Azure context found. Please run Connect-AzAccount first."
        return
    }

    Write-Host "Analyzing resource group '$ResourceGroupName' for customer managed keys..." -ForegroundColor Cyan

    $vaults = Get-AzKeyVault -ResourceGroupName $ResourceGroupName
    if (-not $vaults) {
        Write-Warning "No Key Vaults found in resource group '$ResourceGroupName'."
        return
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now = Get-Date

    foreach ($vault in $vaults) {
        $vaultName = $vault.VaultName
        Write-Host "  Scanning Key Vault: $vaultName" -ForegroundColor Gray

        try {
            $keys = Get-AzKeyVaultKey -VaultName $vaultName
        }
        catch {
            Write-Warning "  Unable to access keys in vault '$vaultName': $_"
            continue
        }

        foreach ($key in $keys) {
            try {
                $keyDetail = Get-AzKeyVaultKey -VaultName $vaultName -Name $key.Name
            }
            catch {
                Write-Warning "  Unable to read key '$($key.Name)' in vault '$vaultName': $_"
                continue
            }

            $expires = $keyDetail.Expires

            $status = "OK"
            if ($expires) {
                if ($now -gt $expires) {
                    $status = "EXPIRED"
                }
                elseif ($expires -le $now.AddDays(90)) {
                    $status = "EXPIRING SOON"
                }
            }
            else {
                $status = "No Expiry Set"
            }

            $results.Add([PSCustomObject]@{
                VaultName = $vaultName
                KeyName   = $keyDetail.Name
                KeyType   = $keyDetail.Key.Kty
                KeyOps    = ($keyDetail.Key.KeyOps -join ', ')
                Version   = $keyDetail.Version
                Enabled   = $keyDetail.Enabled
                Created   = if ($keyDetail.Created) { $keyDetail.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                Expires   = if ($expires) { $expires.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                Status    = $status
            })
        }
    }

    if ($results.Count -eq 0) {
        Write-Warning "No keys found in any Key Vault within resource group '$ResourceGroupName'."
        return
    }

    # Color-coded console table
    Write-Host ""
    $fmt = "{0,-20} {1,-25} {2,-8} {3,-10} {4,-22} {5,-22} {6,-15}"
    Write-Host ($fmt -f "VaultName", "KeyName", "Type", "Enabled", "Created", "Expires", "Status") -ForegroundColor White
    Write-Host ($fmt -f ("-" * 20), ("-" * 25), ("-" * 8), ("-" * 10), ("-" * 22), ("-" * 22), ("-" * 15)) -ForegroundColor White

    foreach ($row in $results) {
        $line = "{0,-20} {1,-25} {2,-8} {3,-10} {4,-22} {5,-22} " -f `
            $row.VaultName, $row.KeyName, $row.KeyType, $row.Enabled, $row.Created, $row.Expires

        Write-Host $line -NoNewline
        switch ($row.Status) {
            "EXPIRED"       { Write-Host ("{0,-15}" -f $row.Status) -ForegroundColor Red }
            "EXPIRING SOON" { Write-Host ("{0,-15}" -f $row.Status) -ForegroundColor DarkYellow }
            default         { Write-Host ("{0,-15}" -f $row.Status) -ForegroundColor Green }
        }
    }

    Write-Host ""
    Write-Host "Total keys found: $($results.Count)" -ForegroundColor Cyan

    if ($Csv) {
        try {
            $results | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
            Write-Host "Results exported to: $Csv" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV to '$Csv': $_"
        }
    }
}

# Auto-invoke when run as a script
$params = @{ ResourceGroupName = $ResourceGroupName }
if ($Csv) { $params['Csv'] = $Csv }
Get-CMKStatus @params
