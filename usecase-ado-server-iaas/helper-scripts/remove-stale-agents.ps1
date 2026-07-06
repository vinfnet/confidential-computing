param(
  [int]$PoolId = 2,
  [string]$Pat,
  [string]$NamePattern = "agent-test"
)
$ErrorActionPreference = "Stop"
$base = "http://localhost/_apis/distributedtask/pools/$PoolId/agents"
$headers = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat")) }
$list = Invoke-RestMethod -Uri "$base?api-version=6.0" -Headers $headers -Method Get
Write-Host "CLEANUP-START"
foreach ($a in $list.value) {
  if ($a.name -like "*$NamePattern*") {
    $del = "$base/$($a.id)?api-version=6.0"
    Invoke-RestMethod -Uri $del -Headers $headers -Method Delete | Out-Null
    Write-Host "REMOVED name='$($a.name)' id=$($a.id)"
  } else {
    Write-Host "KEPT name='$($a.name)' status=$($a.status)"
  }
}
Write-Host "CLEANUP-END"
