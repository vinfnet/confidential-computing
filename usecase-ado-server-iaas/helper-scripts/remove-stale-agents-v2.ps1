param(
  [int]$PoolId = 2,
  [string]$Pat,
  [string]$NamePattern = "agent-test"
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'http://localhost'
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$headers = @{
    Authorization     = "Basic $b64"
    'Accept'          = 'application/json'
    'Accept-Encoding' = 'identity'
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("CLEANUP-START")
try {
    $agents = Invoke-RestMethod -Method GET -Headers $headers -TimeoutSec 30 -UseBasicParsing `
        -Uri "$base/_apis/distributedtask/pools/$PoolId/agents?includeCapabilities=false&api-version=7.0"
    foreach ($a in $agents.value) {
        if ($a.name -like "*$NamePattern*") {
            Invoke-RestMethod -Method DELETE -Headers $headers -TimeoutSec 30 -UseBasicParsing `
                -Uri "$base/_apis/distributedtask/pools/$PoolId/agents/$($a.id)?api-version=7.0" | Out-Null
            $lines.Add(("REMOVED name='{0}' id={1}" -f $a.name, $a.id))
        } else {
            $lines.Add(("KEPT name='{0}' status={1}" -f $a.name, $a.status))
        }
    }
} catch {
    $lines.Add("CLEANUP-FAIL " + ($_.Exception.Message -replace '\s+', ' '))
}
$lines.Add("CLEANUP-END")
Write-Output ($lines -join "`n")
