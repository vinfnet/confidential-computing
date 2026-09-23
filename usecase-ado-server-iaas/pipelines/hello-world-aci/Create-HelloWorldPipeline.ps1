# =============================================================================
# Create-HelloWorldPipeline.ps1
#
# Ensures a project, repository, project queue, and two YAML pipeline definitions
# exist on a self-hosted Azure DevOps Server.
#
# This script is designed to run ON THE ADO SERVER itself (it talks to
# http://localhost/<collection>), which is how you reach a private ADO Server
# CVM that has no public IP — invoke it with `az vm run-command`:
#
#   az vm run-command invoke -g <rg> -n <adoServerVm> `
#     --command-id RunPowerShellScript `
#     --scripts "@usecase-ado-server-iaas/pipelines/hello-world-aci/Create-HelloWorldPipeline.ps1" `
#     --parameters "Pat=$env:AZP_TOKEN" "Project=ADO-IaaS-ACC-Demo" `
#                  "RepoName=ADO-IaaS-ACC-Demo" "Pool=confidential-build-pool" `
#                  "RootYamlPath=azure-pipelines.yml" `
#                  "ContosoYamlPath=usecase-ado-server-iaas/pipelines/visual-attestation-demo/azure-pipelines.yml" `
#                  "QueueDefinitions=true" `
#     --query "value[0].message" -o tsv
#
# The YAML files must be pushed before newly created definitions are queued.
#
# PAT scopes required: Project and Team (Read, write, & manage), Build (Read &
# execute), Code (Read, write, & manage), and Agent Pools (Read & manage).
# =============================================================================
param(
    [Parameter(Mandatory = $true)]  [string]$Pat,
    [Parameter(Mandatory = $false)] [string]$Collection = 'DefaultCollection',
    [Parameter(Mandatory = $false)] [string]$Project    = 'ADO-IaaS-ACC-Demo',
    [Parameter(Mandatory = $false)] [string]$RepoName   = '',            # defaults to the project's repo of the same name
    [Parameter(Mandatory = $false)] [string]$Pool       = 'confidential-build-pool',
    [Parameter(Mandatory = $false)] [string]$RootYamlPath = 'azure-pipelines.yml',
    [Parameter(Mandatory = $false)] [string]$RootDefinitionName = 'root-application',
    [Parameter(Mandatory = $false)] [string]$ContosoYamlPath = 'usecase-ado-server-iaas/pipelines/visual-attestation-demo/azure-pipelines.yml',
    [Parameter(Mandatory = $false)] [string]$ContosoDefinitionName = 'contoso-application',
    [Parameter(Mandatory = $false)] [string]$DefaultBranch  = 'refs/heads/main',
    [Parameter(Mandatory = $false)] [string]$QueueDefinitions = 'false'
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
    $request = @{ Method = $Method; Uri = $Uri; Headers = $headers; TimeoutSec = 60; UseBasicParsing = $true }
    if ($null -ne $Body) { $request.Body = ($Body | ConvertTo-Json -Depth 20); $request.ContentType = 'application/json' }
    return Invoke-RestMethod @request
}

function Ensure-Definition {
    param([string]$Name, [string]$YamlPath, $Repository, $Queue, $Definitions)

    $summary = $Definitions.value | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    $body = @{
        name       = $Name
        type       = 'build'
        quality    = 'definition'
        repository = @{
            id            = $Repository.id
            type          = 'TfsGit'
            name          = $Repository.name
            defaultBranch = $DefaultBranch
        }
        process = @{ type = 2; yamlFilename = $YamlPath }
        queue   = @{ id = $Queue.id }
    }

    if ($summary) {
        $current = Invoke-Ado GET "$base/$pn/_apis/build/definitions/$($summary.id)?api-version=7.0" $null
        $body.id = $current.id
        $body.revision = $current.revision
        $updated = Invoke-Ado PUT "$base/$pn/_apis/build/definitions/$($current.id)?api-version=7.0" $body
        $out.Add("DEFINITION-UPDATED id=$($updated.id) name=$Name yaml=$YamlPath")
        return @{ Id = $updated.id; Created = $false }
    }

    $created = Invoke-Ado POST "$base/$pn/_apis/build/definitions?api-version=7.0" $body
    $out.Add("DEFINITION-CREATED id=$($created.id) name=$Name yaml=$YamlPath")
    return @{ Id = $created.id; Created = $true }
}

try {
    if (-not $RepoName) { $RepoName = $Project }

    # 1. Ensure the project exists.
    $projects = Invoke-Ado GET "$base/_apis/projects?api-version=7.0" $null
    $projectInfo = $projects.value | Where-Object { $_.name -eq $Project } | Select-Object -First 1
    if (-not $projectInfo) {
        $projectBody = @{
            name = $Project
            capabilities = @{
                versioncontrol  = @{ sourceControlType = 'Git' }
                processTemplate = @{ templateTypeId = 'adcc42ab-9882-485e-a3ed-7678f01f66bc' }
            }
        }
        $operation = Invoke-Ado POST "$base/_apis/projects?api-version=7.0" $projectBody
        do {
            Start-Sleep -Seconds 2
            $operation = Invoke-Ado GET "$base/_apis/operations/$($operation.id)?api-version=7.0" $null
        } while ($operation.status -in @('notSet', 'queued', 'inProgress'))
        if ($operation.status -ne 'succeeded') { throw "Project creation failed with status '$($operation.status)'." }
        $projectInfo = Invoke-Ado GET "$base/_apis/projects/$([uri]::EscapeDataString($Project))?api-version=7.0" $null
        $out.Add("PROJECT-CREATED id=$($projectInfo.id) name=$Project")
    } else {
        $out.Add("PROJECT-EXISTS id=$($projectInfo.id) name=$Project")
    }

    # 2. Ensure the git repository exists.
    $repos = Invoke-Ado GET "$base/$pn/_apis/git/repositories?api-version=7.0"
    $repo  = $repos.value | Where-Object { $_.name -eq $RepoName } | Select-Object -First 1
    if (-not $repo) {
        $repo = Invoke-Ado POST "$base/$pn/_apis/git/repositories?api-version=7.0" @{ name = $RepoName; project = @{ id = $projectInfo.id } }
        $out.Add("REPO-CREATED id=$($repo.id) name=$($repo.name)")
    }
    $out.Add("REPO id=$($repo.id) name=$($repo.name)")

    # 3. Ensure the collection pool is exposed as a project queue.
    $queues = Invoke-Ado GET "$base/$pn/_apis/distributedtask/queues?api-version=7.0"
    $queue  = $queues.value | Where-Object { $_.name -eq $Pool } | Select-Object -First 1
    if (-not $queue) {
        $pools = Invoke-Ado GET "$base/_apis/distributedtask/pools?api-version=7.0" $null
        $poolInfo = $pools.value | Where-Object { $_.name -eq $Pool } | Select-Object -First 1
        if (-not $poolInfo) { throw "Collection agent pool '$Pool' does not exist. Run create-ado-pool.ps1 first." }
        $queue = Invoke-Ado POST "$base/$pn/_apis/distributedtask/queues?api-version=7.0" @{ name = $Pool; pool = @{ id = $poolInfo.id } }
        $out.Add("QUEUE-CREATED id=$($queue.id) name=$($queue.name)")
    }
    $out.Add("QUEUE id=$($queue.id) name=$($queue.name)")

    # 4. Ensure both YAML definitions use the selected repository and queue.
    $defs = Invoke-Ado GET "$base/$pn/_apis/build/definitions?api-version=7.0"
    $rootDefinition = Ensure-Definition -Name $RootDefinitionName -YamlPath $RootYamlPath -Repository $repo -Queue $queue -Definitions $defs
    $contosoDefinition = Ensure-Definition -Name $ContosoDefinitionName -YamlPath $ContosoYamlPath -Repository $repo -Queue $queue -Definitions $defs

    # 5. Authorize these definitions to use the confidential project queue.
    $permissionBody = @{ pipelines = @(
        @{ id = $rootDefinition.Id; authorized = $true },
        @{ id = $contosoDefinition.Id; authorized = $true }
    ) }
    Invoke-Ado PATCH "$base/$pn/_apis/pipelines/pipelinepermissions/queue/$($queue.id)?api-version=7.0-preview.1" $permissionBody | Out-Null
    $out.Add("QUEUE-PERMISSION authorizedDefinitions=2 queue=$($queue.name)")

    # Explicitly grant the project build service repository read permission.
    $identityName = "$Project Build Service"
    $identityUri = "$base/_apis/identities?searchFilter=General&filterValue=$([uri]::EscapeDataString($identityName))&queryMembership=None&api-version=7.0"
    $identities = Invoke-Ado GET $identityUri $null
    $buildIdentity = $identities.value |
        Where-Object { $_.providerDisplayName -like "$Project Build Service*" -or $_.customDisplayName -like "$Project Build Service*" } |
        Select-Object -First 1
    if (-not $buildIdentity) {
        throw "Build service identity '$identityName' was not found; verify project creation before queuing builds."
    }
    $gitNamespaceId = '52d39943-cb85-4d7f-8fa8-c6baac873819'
    $repoToken = "repoV2/$($projectInfo.id)/$($repo.id)"
    $repoPermissionBody = @{
        token = $repoToken
        merge = $true
        accessControlEntries = @(
            @{ descriptor = $buildIdentity.descriptor; allow = 2; deny = 0 }
        )
    }
    Invoke-Ado POST "$base/_apis/accesscontrolentries/$gitNamespaceId?api-version=7.0" $repoPermissionBody | Out-Null
    $out.Add("REPO-PERMISSION read=true identity='$($buildIdentity.providerDisplayName)'")

    # Newly introduced YAML files may not trigger from the push that added them.
    if ($QueueDefinitions -eq 'true') {
        foreach ($definition in @($rootDefinition, $contosoDefinition)) {
            $build = Invoke-Ado POST "$base/$pn/_apis/build/builds?api-version=7.0" @{ definition = @{ id = $definition.Id } }
            $out.Add("BUILD-QUEUED definitionId=$($definition.Id) status=$($build.status)")
        }
    }

    $out.Add('CREATE-PIPELINE-OK')
} catch {
    $code = ''
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    $out.Add("CREATE-PIPELINE-FAIL ($code) " + ($_.Exception.Message -replace '\s+', ' '))
}
$out.Add('CREATE-PIPELINE-END')
Write-Output ($out -join "`n")
