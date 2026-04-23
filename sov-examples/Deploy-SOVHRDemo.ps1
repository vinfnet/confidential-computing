param(
    [Parameter(Mandatory = $false)]
    [string]$Prefix,
    [switch]$Build,
    [switch]$Deploy,
    [switch]$Cleanup,
    [string]$Location = "uaenorth"
)

$ErrorActionPreference = "Stop"

$newScript = Join-Path $PSScriptRoot "Deploy-NorlandCitizenRegistry.ps1"
if (-not (Test-Path $newScript)) {
    throw "Expected script not found: $newScript"
}

Write-Warning "Deploy-SOVHRDemo.ps1 is deprecated. Use Deploy-NorlandCitizenRegistry.ps1 instead."

$forwardArgs = @()
if ($Prefix) { $forwardArgs += @("-Prefix", $Prefix) }
if ($Build) { $forwardArgs += "-Build" }
if ($Deploy) { $forwardArgs += "-Deploy" }
if ($Cleanup) { $forwardArgs += "-Cleanup" }
if ($Location) { $forwardArgs += @("-Location", $Location) }

& $newScript @forwardArgs
exit $LASTEXITCODE
