param(
    [string]$Base = 'https://localhost:8443',
    [string]$Collection = 'DefaultCollection',
    [string]$Project = 'ACC-demo',
    [string]$RepoId = 'e2161cfe-d44a-4335-9790-40895f12aa56',
    [string]$Branch = 'refs/heads/main',
    [string]$Comment = 'Add hello-world ACI pipeline (build + deploy driven in ADO)',
    [string]$OutFile = "$env:TEMP\ado_push.txt"
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$pat = if ($env:ADO_PAT) { $env:ADO_PAT } else { $env:AZP_TOKEN }
if (-not $pat) { throw 'ADO_PAT not set' }
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat"))
$H = @{ Authorization = "Basic $b64"; Accept = 'application/json' }
$out = New-Object System.Collections.Generic.List[string]

$root = Join-Path $PSScriptRoot '..\pipelines\secretapp-helloworld' | Resolve-Path
# localRelativePath -> repoPath
$map = [ordered]@{
    'repo-root\azure-pipelines.yml' = '/azure-pipelines.yml'
    'app\Dockerfile'                = '/app/Dockerfile'
    'app\index.html'                = '/app/index.html'
    'deploy\aci-helloworld.json'    = '/deploy/aci-helloworld.json'
    'deploy\aci-helloworld-confidential.json' = '/deploy/aci-helloworld-confidential.json'
}

# Current tip of the branch (oldObjectId required by the push API)
$refs = Invoke-RestMethod -Uri "$Base/$Collection/$Project/_apis/git/repositories/$RepoId/refs?filter=heads/main&api-version=6.0" -Headers $H -SkipCertificateCheck
$tip = ($refs.value | Where-Object { $_.name -eq $Branch }).objectId
if (-not $tip) { throw "Could not resolve tip of $Branch" }
$out.Add("TIP=$tip")

# Discover which of the target paths already exist -> edit vs add
$changes = New-Object System.Collections.Generic.List[object]
foreach ($kv in $map.GetEnumerator()) {
    $local = Join-Path $root $kv.Key
    $repoPath = $kv.Value
    if (-not (Test-Path $local)) { throw "Missing local file: $local" }
    $content = Get-Content -Raw -Path $local
    $exists = $true
    try {
        Invoke-RestMethod -Uri "$Base/$Collection/$Project/_apis/git/repositories/$RepoId/items?path=$([uri]::EscapeDataString($repoPath))&api-version=6.0" -Headers $H -SkipCertificateCheck | Out-Null
    } catch { $exists = $false }
    $changeType = if ($exists) { 'edit' } else { 'add' }
    $out.Add("CHANGE|$changeType|$repoPath")
    $changes.Add(@{
        changeType = $changeType
        item       = @{ path = $repoPath }
        newContent = @{ content = $content; contentType = 'rawtext' }
    })
}

$body = @{
    refUpdates = @(@{ name = $Branch; oldObjectId = $tip })
    commits    = @(@{ comment = $Comment; changes = $changes })
} | ConvertTo-Json -Depth 30

try {
    $res = Invoke-RestMethod -Method POST -Uri "$Base/$Collection/$Project/_apis/git/repositories/$RepoId/pushes?api-version=6.0" -Headers $H -SkipCertificateCheck -Body $body -ContentType 'application/json'
    $out.Add("PUSH-OK commit=$($res.commits[0].commitId)")
} catch {
    $code = -1; $msg = ''
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($_.ErrorDetails.Message) { $msg = ($_.ErrorDetails.Message -replace '\s+', ' ') }
    $out.Add("PUSH-FAIL $code $($msg.Substring(0,[Math]::Min(400,$msg.Length)))")
}

$out | Set-Content -Path $OutFile
