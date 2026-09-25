[CmdletBinding()]
param(
    [string]$BaseUrl = 'https://localhost:9999',
    [Parameter(Mandatory = $true)]
    [string]$SpeechResourceId,
    [Parameter(Mandatory = $true)]
    [string]$SpeechEndpoint,
    [string]$SpeechRegion = 'westeurope',
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [switch]$SkipInstall,
    [switch]$SkipRehearsal
)

$ErrorActionPreference = 'Stop'
$PackageRoot = $PSScriptRoot

foreach ($Command in @('node', 'npm', 'npx', 'ffmpeg', 'ffprobe')) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $Command"
    }
}

Push-Location $PackageRoot
$PreviousBaseUrl = $env:DEMO_BASE_URL
$PreviousSpeechResourceId = $env:AZURE_SPEECH_RESOURCE_ID
$PreviousSpeechEndpoint = $env:AZURE_SPEECH_ENDPOINT
$PreviousSpeechRegion = $env:AZURE_SPEECH_REGION
$PreviousTenantId = $env:AZURE_TENANT_ID
try {
    $env:DEMO_BASE_URL = $BaseUrl
    $env:AZURE_SPEECH_RESOURCE_ID = $SpeechResourceId
    $env:AZURE_SPEECH_ENDPOINT = $SpeechEndpoint
    $env:AZURE_SPEECH_REGION = $SpeechRegion
    $env:AZURE_TENANT_ID = $TenantId
    if (-not $SkipInstall) {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
        npx playwright install chromium
        if ($LASTEXITCODE -ne 0) { throw 'Playwright Chromium installation failed.' }
    }
    npm run analyze
    if ($LASTEXITCODE -ne 0) { throw 'Narration timing analysis failed.' }
    if (-not $SkipRehearsal) {
        npm run rehearse
        if ($LASTEXITCODE -ne 0) { throw 'Browser rehearsal failed.' }
    }
    npm run narrate
    if ($LASTEXITCODE -ne 0) { throw 'Narration synthesis failed.' }
    npm run record
    if ($LASTEXITCODE -ne 0) { throw 'Browser recording failed.' }
    npm run render
    if ($LASTEXITCODE -ne 0) { throw 'Media rendering failed.' }
    npm run verify
    if ($LASTEXITCODE -ne 0) { throw 'Media verification failed.' }
}
finally {
    $env:DEMO_BASE_URL = $PreviousBaseUrl
    $env:AZURE_SPEECH_RESOURCE_ID = $PreviousSpeechResourceId
    $env:AZURE_SPEECH_ENDPOINT = $PreviousSpeechEndpoint
    $env:AZURE_SPEECH_REGION = $PreviousSpeechRegion
    $env:AZURE_TENANT_ID = $PreviousTenantId
    Pop-Location
}

Write-Host "Demo video ready: $PackageRoot\output\citizen-registry-sovereignty-demo.mp4"