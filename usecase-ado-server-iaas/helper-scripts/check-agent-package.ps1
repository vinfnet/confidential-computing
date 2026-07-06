param([string]$Pat)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$headers = @{ Authorization = "Basic $b64"; 'Accept' = 'application/json'; 'Accept-Encoding' = 'identity' }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("PKG-START")
foreach ($base in @('http://localhost/DefaultCollection', 'http://localhost')) {
    $uri = "$base/_apis/distributedtask/packages/agent?platform=linux-x64&`$top=1&api-version=7.0"
    try {
        $r = Invoke-RestMethod -Method GET -Headers $headers -TimeoutSec 20 -UseBasicParsing -Uri $uri
        $lines.Add("BASE $base COUNT=$($r.count)")
        if ($r.value -and $r.value.Count -gt 0) {
            $p = $r.value[0]
            $lines.Add("  platform=$($p.platform) version=$($p.version)")
            $du = "$($p.downloadUrl)"
            if ($du.Length -gt 80) { $du = $du.Substring(0,80) + '...' }
            $lines.Add("  downloadUrl=$du")
        }
    } catch {
        $sc = $_.Exception.Response.StatusCode.value__
        $lines.Add("BASE $base HTTP=$sc ERR=" + ($_.Exception.Message -replace '\s+',' '))
    }
}
$lines.Add("PKG-END")
Write-Output ($lines -join "`n")
