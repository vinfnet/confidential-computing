param(
    [string]$Pool,
    [string]$Pat,
    [string]$Collection = 'DefaultCollection'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# On Azure DevOps Server, the PAT authenticates at the COLLECTION host, not the
# deployment root. The distributedtask/pools API must therefore be reached through
# the collection path (http://localhost/<Collection>/_apis/...); the bare root path
# (http://localhost/_apis/...) returns 401 for a collection-scoped PAT.
$base = "http://localhost/$Collection"
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
# Accept-Encoding: identity prevents the on-prem ADO Server from gzip-compressing
# the response body (Windows PowerShell 5.1 does not auto-decompress, which
# otherwise emits unreadable binary through the run-command output channel).
$headers = @{
    Authorization     = "Basic $b64"
    'Accept'          = 'application/json'
    'Accept-Encoding' = 'identity'
}

function Invoke-Ado {
    param([string]$Method, [string]$Uri, [string]$Body)
    $p = @{ Method = $Method; Uri = $Uri; Headers = $headers; TimeoutSec = 30; UseBasicParsing = $true }
    if ($Body) { $p.Body = $Body; $p.ContentType = 'application/json' }
    return Invoke-RestMethod @p
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("RESULT-START")

# 1. List existing pools (collection scope). A 200 here confirms the PAT authenticates.
$existing = $null
try {
    $pools = Invoke-Ado -Method GET -Uri "$base/_apis/distributedtask/pools?api-version=7.0"
    $lines.Add("AUTH-OK poolcount=" + $pools.count)
    foreach ($p in $pools.value) { $lines.Add(("POOL name='{0}' id={1}" -f $p.name, $p.id)) }
    $existing = $pools.value | Where-Object { $_.name -eq $Pool }
} catch {
    $lines.Add("LIST-FAIL " + ($_.Exception.Message -replace '\s+', ' '))
}

# 2. Create pool if missing
if ($existing) {
    $lines.Add(("POOL-EXISTS name='{0}' id={1}" -f $Pool, $existing.id))
} else {
    try {
        $body = @{ name = $Pool; autoProvision = $true } | ConvertTo-Json -Compress
        $new = Invoke-Ado -Method POST -Uri "$base/_apis/distributedtask/pools?api-version=7.0" -Body $body
        $lines.Add(("POOL-CREATED name='{0}' id={1}" -f $new.name, $new.id))
    } catch {
        $lines.Add("CREATE-FAIL " + ($_.Exception.Message -replace '\s+', ' '))
        if ($_.ErrorDetails.Message) { $lines.Add("CREATE-DETAIL " + ($_.ErrorDetails.Message -replace '\s+', ' ')) }
    }
}

$lines.Add("RESULT-END")
Write-Output ($lines -join "`n")
