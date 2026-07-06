$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== Listening ports (8080/8443/443) ==="
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 8080,8443,443,80 } |
    Select-Object LocalAddress, LocalPort | Sort-Object LocalPort -Unique | Format-Table | Out-String | Write-Output

Write-Output "=== TFS/ADO config (registry) ==="
$reg = 'HKLM:\SOFTWARE\Microsoft\TeamFoundationServer'
if (Test-Path $reg) {
    Get-ChildItem $reg -Recurse -ErrorAction SilentlyContinue | Out-String | Write-Output
}

Write-Output "=== Probe local ADO endpoints ==="
foreach ($u in @('http://localhost:8080/tfs','http://localhost:8080/tfs/_apis/connectionData','http://localhost:8080/DefaultCollection')) {
    try {
        $r = Invoke-WebRequest -Uri $u -UseDefaultCredentials -UseBasicParsing -TimeoutSec 10
        Write-Output ("{0} -> HTTP {1}" -f $u, $r.StatusCode)
    } catch {
        Write-Output ("{0} -> ERROR {1}" -f $u, $_.Exception.Message)
    }
}

Write-Output "=== Collections via API ==="
try {
    $c = Invoke-RestMethod -Uri 'http://localhost:8080/tfs/_apis/projectcollections?api-version=6.0' -UseDefaultCredentials -TimeoutSec 15
    $c.value | Select-Object name, id | Out-String | Write-Output
} catch {
    Write-Output ("projectcollections -> ERROR {0}" -f $_.Exception.Message)
}
