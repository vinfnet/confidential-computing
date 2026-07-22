# =============================================================================
# Create-HelloWorldPipeline.ps1
#
# Creates the "hello-world-aci" YAML pipeline definition on a self-hosted Azure
# DevOps Server and (optionally) queues a run on the confidential build pool.
#
# This script is designed to run ON THE ADO SERVER itself (it talks to
# http://localhost/<collection>), which is how you reach a private ADO Server
# CVM that has no public IP — invoke it with `az vm run-command`:
#
#   az vm run-command invoke -g <rg> -n <adoServerVm> `
#     --command-id RunPowerShellScript `
#     --scripts "@usecase-ado-server-iaas/pipelines/hello-world-aci/Create-HelloWorldPipeline.ps1" `
#     --parameters "Pat=$env:AZP_TOKEN" "Project=Confidential-IaaS-ADO" `
#                  "RepoName=Confidential-IaaS-ADO" "Pool=confidential-build-pool" `
#                  "YamlPath=azure-pipelines.yml" "Queue=true" `
#     --query "value[0].message" -o tsv
#
# The repo must already contain azure-pipelines.yml at -YamlPath (push the
# hello-world-aci folder to the repo first — see the README "From scratch").
#
# PAT scopes required: Build (Read & execute), Code (Read), Agent Pools (Read).
# =============================================================================
param(
    [Parameter(Mandatory = $true)]  [string]$Pat,
    [Parameter(Mandatory = $false)] [string]$Collection = 'DefaultCollection',
    [Parameter(Mandatory = $false)] [string]$Project    = 'Confidential-IaaS-ADO',
    [Parameter(Mandatory = $false)] [string]$RepoName   = '',            # defaults to the project's repo of the same name
    [Parameter(Mandatory = $false)] [string]$Pool       = 'confidential-build-pool',
    [Parameter(Mandatory = $false)] [string]$YamlPath   = 'azure-pipelines.yml',
    [Parameter(Mandatory = $false)] [string]$DefinitionName = 'hello-world-aci',
    [Parameter(Mandatory = $false)] [string]$DefaultBranch  = 'refs/heads/main',
    [Parameter(Mandatory = $false)] [string]$Queue      = 'false'        # 'true' to also queue a build after create
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$base = "http://localhost/$Collection"
$b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$Pat"))
$headers = @{ Authorization = "Basic $b64"; 'Accept' = 'application/json'; 'Accept-Encoding' = 'identity' }
$pn   = [uri]::EscapeDataString($Project)
$out  = New-Object System.Collections.Generic.List[string]
$out.Add('CREATE-PIPELINE-START')

function Invoke-Ado {
    param([string]$Method, [string]$Uri, $Body)
    $args = @{ Method = $Method; Uri = $Uri; Headers = $headers; TimeoutSec = 60; UseBasicParsing = $true }
    if ($null -ne $Body) { $args.Body = ($Body | ConvertTo-Json -Depth 20); $args.ContentType = 'application/json' }
    return Invoke-RestMethod @args
}

try {
    if (-not $RepoName) { $RepoName = $Project }

    # 1. Resolve the git repo id.
    $repos = Invoke-Ado GET "$base/$pn/_apis/git/repositories?api-version=7.0"
    $repo  = $repos.value | Where-Object { $_.name -eq $RepoName } | Select-Object -First 1
    if (-not $repo) { throw "Repo '$RepoName' not found in project '$Project'." }
    $out.Add("REPO id=$($repo.id) name=$($repo.name)")

    # 2. Resolve the agent queue id for the pool (queues are project-scoped).
    $queues = Invoke-Ado GET "$base/$pn/_apis/distributedtask/queues?api-version=7.0"
    $queue  = $queues.value | Where-Object { $_.name -eq $Pool } | Select-Object -First 1
    if (-not $queue) { throw "Agent queue '$Pool' not found in project '$Project'. Add the pool to the project first." }
    $out.Add("QUEUE id=$($queue.id) name=$($queue.name)")

    # 3. Create (or reuse) the YAML build definition bound to that queue.
    $defs = Invoke-Ado GET "$base/$pn/_apis/build/definitions?api-version=7.0"
    $def  = $defs.value | Where-Object { $_.name -eq $DefinitionName } | Select-Object -First 1
    if ($def) {
        $out.Add("DEFINITION-EXISTS id=$($def.id) name=$($def.name)")
        $defId = $def.id
    } else {
        $body = @{
            name       = $DefinitionName
            type       = 'build'
            quality    = 'definition'
            repository = @{
                id            = $repo.id
                type          = 'TfsGit'
                name          = $repo.name
                defaultBranch = $DefaultBranch
            }
            process = @{
                type         = 2          # 2 = YAML process
                yamlFilename = $YamlPath
            }
            queue = @{ id = $queue.id }
        }
        $created = Invoke-Ado POST "$base/$pn/_apis/build/definitions?api-version=7.0" $body
        $defId   = $created.id
        $out.Add("DEFINITION-CREATED id=$defId name=$($created.name) yaml=$YamlPath")
    }

    # 4. Optionally queue a run.
    if ($Queue -eq 'true') {
        $qBody = @{ definition = @{ id = $defId } }
        $build = Invoke-Ado POST "$base/$pn/_apis/build/builds?api-version=7.0" $qBody
        $out.Add("BUILD-QUEUED id=$($build.id) number=$($build.buildNumber) status=$($build.status) url=$($build._links.web.href)")
    }

    $out.Add('CREATE-PIPELINE-OK')
} catch {
    $code = ''
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    $out.Add("CREATE-PIPELINE-FAIL ($code) " + ($_.Exception.Message -replace '\s+', ' '))
}
$out.Add('CREATE-PIPELINE-END')
Write-Output ($out -join "`n")
