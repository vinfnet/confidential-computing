param(
    [Parameter(Mandatory)] [string]$Action,
    [string]$Base = 'https://localhost:8443',
    [string]$Collection = 'DefaultCollection',
    [string]$Project = 'SecretApp',
    [string]$ApiVersion = '6.0-preview',
    [string]$OutFile = "$env:TEMP\ado_out.txt",
    [hashtable]$Extra
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$pat = if ($env:ADO_PAT) { $env:ADO_PAT } else { $env:AZP_TOKEN }
if (-not $pat) { throw 'Neither ADO_PAT nor AZP_TOKEN is set' }
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat"))
$H = @{ Authorization = "Basic $b64"; Accept = 'application/json' }
$out = New-Object System.Collections.Generic.List[string]

function Ado {
    param([string]$Method, [string]$Uri, $BodyObj, [string]$ContentType = 'application/json')
    $p = @{ Method = $Method; Uri = $Uri; Headers = $H; SkipCertificateCheck = $true; TimeoutSec = 60 }
    if ($null -ne $BodyObj) {
        if ($ContentType -eq 'application/json') { $p.Body = ($BodyObj | ConvertTo-Json -Depth 30 -Compress) }
        else { $p.Body = $BodyObj }
        $p.ContentType = $ContentType
    }
    return Invoke-RestMethod @p
}

$colBase = "$Base/$Collection/_apis"
$projApi = "$Base/$Collection/$Project/_apis"

switch ($Action) {
    'projects' {
        $r = Ado GET "$colBase/projects?api-version=6.0-preview.4"
        foreach ($p in $r.value) { $out.Add("PROJECT|$($p.name)|$($p.id)|$($p.state)") }
        $out.Add("COUNT|$($r.count)")
    }
    'repos' {
        $r = Ado GET "$projApi/git/repositories?api-version=6.0"
        foreach ($g in $r.value) { $out.Add("REPO|$($g.name)|$($g.id)|default=$($g.defaultBranch)|size=$($g.size)") }
        $out.Add("COUNT|$($r.count)")
    }
    'repo-items' {
        $repo = $Extra.Repo
        try {
            $r = Ado GET "$projApi/git/repositories/$repo/items?recursionLevel=Full&api-version=6.0"
            foreach ($i in $r.value) { $out.Add("ITEM|$($i.path)|$($i.gitObjectType)") }
            $out.Add("COUNT|$($r.count)")
        } catch {
            $out.Add("EMPTY-OR-ERR|$([int]$_.Exception.Response.StatusCode)")
        }
    }
    'pools' {
        $r = Ado GET "$Base/_apis/distributedtask/pools?api-version=6.0-preview"
        foreach ($p in $r.value) { $out.Add("POOL|$($p.name)|$($p.id)") }
        $out.Add("COUNT|$($r.count)")
    }
    'serviceendpoints' {
        $r = Ado GET "$projApi/serviceendpoint/endpoints?api-version=$ApiVersion-preview.4"
        foreach ($e in $r.value) { $out.Add("EP|$($e.name)|$($e.id)|$($e.type)") }
        $out.Add("COUNT|$($r.count)")
    }
    default { $out.Add("UNKNOWN-ACTION|$Action") }
}

$out | Set-Content -Path $OutFile
