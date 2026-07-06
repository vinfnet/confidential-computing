param(
    [int]$PoolId = 2,
    [string]$Pat
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
$lines.Add("RESULT-START")
try {
    $agents = Invoke-RestMethod -Method GET -Headers $headers -TimeoutSec 30 -UseBasicParsing `
        -Uri "$base/_apis/distributedtask/pools/$PoolId/agents?includeCapabilities=false&api-version=7.0"
    $lines.Add("AGENT-COUNT $($agents.count)")
    foreach ($a in $agents.value) {
        $lines.Add(("AGENT name='{0}' status={1} enabled={2} version={3}" -f $a.name, $a.status, $a.enabled, $a.version))
    }
} catch {
    $lines.Add("LIST-FAIL " + ($_.Exception.Message -replace '\s+', ' '))
}
$lines.Add("RESULT-END")
Write-Output ($lines -join "`n")
