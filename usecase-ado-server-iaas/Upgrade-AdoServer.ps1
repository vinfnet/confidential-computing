<#
.SYNOPSIS
Download and interactively (visibly) install/upgrade Azure DevOps Server on the
ADO Server CVM.

.DESCRIPTION
Run this script ON the Azure DevOps Server VM, inside your Bastion RDP session
(elevated PowerShell). It:

  1. Downloads the requested Azure DevOps Server installer to a local folder.
  2. Launches the installer with its normal UI (NOT /quiet), so you can click
     through setup and the Server Configuration Wizard and watch progress.
  3. After the installer exits, reminds you to complete the Configuration Wizard
     (which upgrades the databases) if it did not launch automatically.

Upgrading the server is what changes the pipeline agent version it distributes
(e.g. v3/.NET 6 -> v4/.NET 8). The self-hosted / confidential ACI agents pick up
the new agent package automatically on their next restart - no image rebuild.

.PARAMETER Version
Azure DevOps Server version to install (default 2022.2). Used to resolve the EXE
link from the downloads page when -InstallerUrl is not given. 2022.1 / 2022.2
ship the v4 (.NET 8) agent; 2022 / 2022.0.1 ship v3 (.NET 6).

.PARAMETER InstallerUrl
Explicit direct URL to the Azure DevOps Server installer .exe. When provided it
overrides -Version and skips downloads-page resolution. Get links from the
official downloads page: https://learn.microsoft.com/azure/devops/server/download/azuredevopsserver

Version -> pipeline agent -> bundled .NET (this is what actually determines the
agent .NET version your server hands out):
  - Azure DevOps Server 2022 / 2022.0.1  -> agent v3 -> .NET 6
  - Azure DevOps Server 2022.1 / 2022.2  -> agent v4 -> .NET 8   (latest; use this to get off .NET 6)

By default the script resolves the EXE link for -Version (2022.2) from the
downloads page at run time, so there is no stale hardcoded build URL in source.

.PARAMETER DownloadPath
Local folder on the server to download the installer into. Default C:\Temp.

.PARAMETER SkipDownload
Use an installer already present at -InstallerPath instead of downloading.

.PARAMETER InstallerPath
Full path to an already-downloaded installer .exe (used with -SkipDownload).

.EXAMPLE
# On the ADO Server VM (elevated), install the default (latest, 2022.2 -> .NET 8 agent):
./Upgrade-AdoServer.ps1

.EXAMPLE
# Pick a specific version (resolved from the official downloads page):
./Upgrade-AdoServer.ps1 -Version 2022.1

.EXAMPLE
# Use a specific installer URL directly (skips resolution):
./Upgrade-AdoServer.ps1 -InstallerUrl "https://download.microsoft.com/.../azuredevopsserver2022.2.exe"

.EXAMPLE
# Reuse a file you already copied onto the box:
./Upgrade-AdoServer.ps1 -SkipDownload -InstallerPath "C:\Temp\azuredevopsserver.exe"
#>

[CmdletBinding()]
param(
    # Azure DevOps Server version to install. 2022.1 / 2022.2 ship the v4 (.NET 8)
    # pipeline agent; 2022 / 2022.0.1 ship v3 (.NET 6). Default is the latest.
    [Parameter(Mandatory = $false)]
    [ValidateSet("2022.2", "2022.1", "2022.0.1", "2022")]
    [string]$Version = "2022.2",

    # Explicit installer URL. When set, overrides -Version (no page resolution).
    [Parameter(Mandatory = $false)]
    [string]$InstallerUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$DownloadPath = "C:\Temp",

    [Parameter(Mandatory = $false)]
    [switch]$SkipDownload,

    [Parameter(Mandatory = $false)]
    [string]$InstallerPath = ""
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Resolve-AdoServerInstallerUrl {
    <#
        Scrapes the official Azure DevOps Server downloads page and returns the
        direct .exe URL for the requested version. Avoids baking a per-build GUID
        URL into source (which goes stale). Requires internet access from the box.
    #>
    param([string]$Version)

    $downloadsPage = "https://learn.microsoft.com/en-us/azure/devops/server/download/azuredevopsserver"
    Write-Host "Resolving installer URL for Azure DevOps Server $Version ..." -ForegroundColor DarkGray
    Write-Host "Source: $downloadsPage" -ForegroundColor DarkGray

    try {
        $resp = Invoke-WebRequest -Uri $downloadsPage -UseBasicParsing
    } catch {
        throw "Could not fetch the downloads page to resolve the installer URL. Pass -InstallerUrl explicitly. ($($_.Exception.Message))"
    }

    # Candidate direct-download links (download.microsoft.com / aka.ms / go.microsoft.com fwlink).
    $hrefs = [regex]::Matches($resp.Content, 'href\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
    $candidates = $hrefs | Where-Object {
        $_ -match '(download\.microsoft\.com|aka\.ms|go\.microsoft\.com/fwlink)' -and
        ($_ -match '\.exe($|\?)' -or $_ -match 'fwlink')
    }

    # Prefer a link whose text/URL references the exact version and NOT "Express".
    $verToken = [regex]::Escape($Version)
    $match = $candidates | Where-Object { $_ -match $verToken -and $_ -notmatch 'express' } | Select-Object -First 1
    if (-not $match) {
        # Fall back to a version-tagged anchor block in the raw HTML.
        $anchor = [regex]::Match($resp.Content, "azuredevopsserver$verToken[^`"']*\.exe", 'IgnoreCase')
        if ($anchor.Success) { $match = $anchor.Value }
    }

    if (-not $match) {
        throw "Could not locate a direct .exe link for version $Version on the downloads page. Copy the EXE link from $downloadsPage and pass it via -InstallerUrl."
    }

    if ($match -notmatch '^https?://') { $match = "https://" + $match.TrimStart('/') }
    return $match
}

# --- Preflight --------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script from an ELEVATED PowerShell session on the Azure DevOps Server VM."
}

Write-Step "Azure DevOps Server - interactive upgrade helper"
Write-Host "This launches the installer with its UI (visible, not silent)." -ForegroundColor Yellow
Write-Host "You will click through setup and the Server Configuration Wizard." -ForegroundColor Yellow

# --- Download ---------------------------------------------------------------

if (-not $SkipDownload) {
    if (-not (Test-Path $DownloadPath)) {
        New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
    }

    # Resolve the URL from -Version unless the caller passed one explicitly.
    if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
        Write-Step "Resolving installer URL (version $Version)"
        $InstallerUrl = Resolve-AdoServerInstallerUrl -Version $Version
    }

    $InstallerPath = Join-Path $DownloadPath "azuredevopsserver-installer.exe"

    Write-Step "Downloading installer"
    Write-Host "URL:  $InstallerUrl" -ForegroundColor DarkGray
    Write-Host "Dest: $InstallerPath" -ForegroundColor DarkGray

    # Use BITS when available (shows transfer progress); fall back to Invoke-WebRequest.
    $progressPreference = $ProgressPreference
    try {
        if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
            Start-BitsTransfer -Source $InstallerUrl -Destination $InstallerPath -Description "Azure DevOps Server installer"
        } else {
            $ProgressPreference = 'Continue'
            Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing
        }
    } finally {
        $ProgressPreference = $progressPreference
    }

    if (-not (Test-Path $InstallerPath)) {
        throw "Download did not produce a file at $InstallerPath."
    }
    Write-Host "Downloaded: $((Get-Item $InstallerPath).Length / 1MB) MB" -ForegroundColor Green
} else {
    if ([string]::IsNullOrWhiteSpace($InstallerPath) -or -not (Test-Path $InstallerPath)) {
        throw "-SkipDownload requires -InstallerPath pointing to an existing installer .exe."
    }
    Write-Host "Using existing installer: $InstallerPath" -ForegroundColor DarkGray
}

# --- Unblock + show version -------------------------------------------------

Unblock-File -Path $InstallerPath -ErrorAction SilentlyContinue
try {
    $ver = (Get-Item $InstallerPath).VersionInfo.ProductVersion
    if ($ver) { Write-Host "Installer product version: $ver" -ForegroundColor DarkGray }
} catch {}

# --- Launch installer VISIBLY (no /quiet) -----------------------------------

Write-Step "Launching installer UI"
Write-Host "Complete the setup wizard in the window that opens. This script waits until it exits." -ForegroundColor Yellow

# No /quiet, no /silent: the installer shows its normal UI.
$proc = Start-Process -FilePath $InstallerPath -PassThru
$proc.WaitForExit()
$exitCode = $proc.ExitCode

Write-Host "Installer exited with code $exitCode." -ForegroundColor ($(if ($exitCode -eq 0) { "Green" } else { "Yellow" }))

# --- Configuration Wizard reminder -----------------------------------------

Write-Step "Next: Server Configuration Wizard (database upgrade)"
$wizardCandidates = @(
    "${env:ProgramFiles}\Azure DevOps Server 2022\Tools\TfsMgmt.exe",
    "${env:ProgramFiles}\Azure DevOps Server 2022\Tools\Deploy\TfsConfig.exe"
)
$wizard = $wizardCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($wizard) {
    Write-Host "Found management tool: $wizard" -ForegroundColor DarkGray
    Write-Host "If the Configuration Wizard did not open automatically, launch it to run the upgrade:" -ForegroundColor Yellow
    Write-Host "  Start-Process `"$wizard`"" -ForegroundColor Yellow
} else {
    Write-Host "Open the Azure DevOps Server Administration Console and run the upgrade wizard to complete the database upgrade." -ForegroundColor Yellow
}

Write-Step "After the upgrade completes"
Write-Host "- The server now distributes a newer pipeline agent." -ForegroundColor Green
Write-Host "- Restart your confidential ACI / virtual-node agents so they pull the new agent package:" -ForegroundColor Green
Write-Host "    kubectl rollout restart deployment/ado-confidential-agent -n ado-agents   # AKS virtual nodes" -ForegroundColor DarkGray
Write-Host "    (or redeploy the standalone confidential ACI agents)" -ForegroundColor DarkGray
Write-Host "- Verify the distributed agent version with usecase-ado-server-iaas/check-agent-package.ps1" -ForegroundColor Green
