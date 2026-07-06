param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,

    [string]$WorkingDirectory = 'C:\Install\AzureDevOpsServer',

    [string]$UnattendFile = 'C:\Install\AzureDevOpsServer\ado-server-basic.ini',

    [string]$LogDirectory = 'C:\Install\AzureDevOpsServer\Logs',

    [ValidateSet('2022', '2020')]
    [string]$ServerVersion = '2022',

    [string]$ProjectCollectionName = 'DefaultCollection',

    [string]$ServiceAccountName = 'NT AUTHORITY\NETWORK SERVICE',

    [ValidateSet('HTTP', 'HTTPS')]
    [string]$WebBinding = 'HTTP',

    [ValidateSet('SqlExpress', 'ExistingSqlServer')]
    [string]$SqlMode = 'SqlExpress',

    [switch]$SilentInstaller,

    [int]$ToolsWaitMinutes = 30,

    [bool]$StageOfflineBundle = $true,

    [string]$LayoutPath = 'C:\Install\AzureDevOpsServerOffline',

    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

function Get-TfsConfigPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $candidatePaths = @(
        "${env:ProgramFiles}\Azure DevOps Server $Version\Tools\TfsConfig.exe",
        "${env:ProgramFiles(x86)}\Azure DevOps Server $Version\Tools\TfsConfig.exe",
        "${env:ProgramFiles}\Microsoft Team Foundation Server $Version\Tools\TfsConfig.exe",
        "${env:ProgramFiles(x86)}\Microsoft Team Foundation Server $Version\Tools\TfsConfig.exe"
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    $searchRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        "$env:SystemDrive\"
    ) | Where-Object { $_ } | Select-Object -Unique

    $foundPath = Get-ChildItem -Path $searchRoots -Filter TfsConfig.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'Azure DevOps Server|Microsoft Team Foundation Server' } |
        Select-Object -ExpandProperty FullName -First 1

    if ($foundPath) {
        return $foundPath
    }

    return $null
}

function Wait-ForTfsConfigPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMinutes
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)

    do {
        $path = Get-TfsConfigPath -Version $Version
        if ($path) {
            return $path
        }

        if ((Get-Date) -ge $deadline) {
            return $null
        }

        Write-Host "Waiting for Azure DevOps Server tools to finish installing..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 30
    } while ($true)
}

function Get-UnattendInputs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectionName,

        [Parameter(Mandatory = $true)]
        [string]$ServiceAccount,

        [Parameter(Mandatory = $true)]
        [string]$Binding,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $inputs = @{
        ProjectCollectionName = $CollectionName
        ServiceAccountName = $ServiceAccount
        WebSiteBinding = $Binding
    }

    if ($Mode -eq 'ExistingSqlServer') {
        $inputs['InstallSqlServerExpress'] = 'False'
    }

    return ($inputs.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
}

function Test-PendingReboot {
    $rebootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )

    foreach ($rebootPath in $rebootPaths) {
        if (Test-Path -LiteralPath $rebootPath) {
            return $true
        }
    }

    $sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pendingRename = (Get-ItemProperty -LiteralPath $sessionManager -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pendingRename) {
        return $true
    }

    return $false
}

New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null

if (-not (Test-Path -LiteralPath $InstallerPath)) {
    throw "Installer not found: $InstallerPath"
}

if (Test-PendingReboot) {
    Write-Warning "A pending reboot is present on this machine. Azure DevOps Server installs frequently fail with exit code 1603 (0x643) when a reboot is pending."
    Write-Host "Reboot the server, then rerun this script before installing. Aborting so the install is not attempted in a known-bad state."
    return
}

$installerLog = Join-Path $LogDirectory 'azure-devops-server-install.log'
$layoutLog = Join-Path $LogDirectory 'azure-devops-server-layout.log'
$configureLog = Join-Path $LogDirectory 'azure-devops-server-configure.log'
$unattendInputs = Get-UnattendInputs -CollectionName $ProjectCollectionName -ServiceAccount $ServiceAccountName -Binding $WebBinding -Mode $SqlMode

# By default, pre-stage the full offline bundle so the install is deterministic and not dependent
# on a live download mid-install. The web installer is a WiX Burn bootstrapper that supports /layout.
$installFromPath = $InstallerPath

if ($StageOfflineBundle) {
    New-Item -ItemType Directory -Path $LayoutPath -Force | Out-Null

    Write-Host "Pre-staging offline bundle to: $LayoutPath"
    $layoutArguments = @(
        '/layout'
        "`"$LayoutPath`""
        '/quiet'
        "/log `"$layoutLog`""
    )
    Start-Process -FilePath $InstallerPath -ArgumentList $layoutArguments -Wait

    $stagedInstaller = Get-ChildItem -Path $LayoutPath -Filter '*.exe' -File -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending |
        Select-Object -ExpandProperty FullName -First 1

    if ($stagedInstaller) {
        Write-Host "Offline bundle staged. Installing from: $stagedInstaller"
        $installFromPath = $stagedInstaller
    } else {
        Write-Warning "Could not find a staged installer under $LayoutPath. Falling back to the original installer path."
    }
}

if ($SilentInstaller) {
    Write-Host "Running installer silently: $installFromPath"
    $installerArguments = @(
        '/quiet'
        '/install'
        '/norestart'
        "/log `"$installerLog`""
    )
} else {
    Write-Host "Running installer with visible progress: $installFromPath"
    $installerArguments = @(
        '/passive'
        '/install'
        '/norestart'
        "/log `"$installerLog`""
    )
}

$installProcess = Start-Process -FilePath $installFromPath -ArgumentList $installerArguments -Wait -PassThru
$installExitCode = $installProcess.ExitCode
Write-Host ("Installer exit code: 0x{0:X} ({0})" -f $installExitCode)

# 0x643 / 1603 is a fatal MSI failure that is often transient (pending reboot, or /passive on a
# restricted image). Retry once interactively so the real error surfaces and the child MSIs get a
# clean, fully-attended run.
if ($installExitCode -eq 1603) {
    Write-Warning "Installer returned 1603 (0x643), a fatal MSI error. Retrying once in interactive mode so the failure is visible."
    $interactiveLog = Join-Path $LogDirectory 'azure-devops-server-install-interactive.log'
    $interactiveArguments = @(
        '/install'
        '/norestart'
        "/log `"$interactiveLog`""
    )
    Write-Host "Running installer interactively: $installFromPath"
    $installProcess = Start-Process -FilePath $installFromPath -ArgumentList $interactiveArguments -Wait -PassThru
    $installExitCode = $installProcess.ExitCode
    Write-Host ("Interactive installer exit code: 0x{0:X} ({0})" -f $installExitCode)
}

if ($installExitCode -eq 3010) {
    Write-Warning "Installer completed but requires a reboot (exit code 3010). Reboot the server, then rerun this script to finish configuration."
    return
}

if ($installExitCode -ne 0) {
    Write-Warning ("Installer did not complete successfully (exit code 0x{0:X} / {0})." -f $installExitCode)
    Write-Host "Review the install log for the failing package: $installerLog"
    Write-Host "Also check the per-package MSI logs written under `$env:TEMP for the 'Return value 3' line."
    return
}

Write-Host "Installer process exited. Waiting up to $ToolsWaitMinutes minute(s) for Azure DevOps Server tools to be installed..."
$tfsConfigPath = Wait-ForTfsConfigPath -Version $ServerVersion -TimeoutMinutes $ToolsWaitMinutes

if (-not $tfsConfigPath) {
    Write-Warning "Azure DevOps Server tools (TfsConfig.exe) were not found within $ToolsWaitMinutes minute(s)."
    Write-Host "The web installer bootstrapper often returns before the product install completes. Once installation finishes, rerun with -SkipInstall style usage or simply rerun this script; the download step will be skipped and configuration will continue."
    Write-Host "You can also increase the wait with -ToolsWaitMinutes, or complete the configuration wizard manually."
    return
}

Write-Host "Creating unattend file: $UnattendFile"
& $tfsConfigPath unattend /create /type:NewServerBasic /unattendfile:$UnattendFile /inputs:$unattendInputs

Write-Host ''
Write-Host 'The generated unattend file is the supported place to finalize deployment settings for a Basic install.'
Write-Host 'If your environment needs a different SQL Server choice than the default, edit the unattend file before running configure.'
Write-Host ''

if (-not $SkipVerify) {
    Write-Host "Verifying configuration with unattend file: $UnattendFile"
    & $tfsConfigPath unattend /configure /unattendfile:$UnattendFile /verify /continue | Tee-Object -FilePath $configureLog
    Write-Host ''
}

Write-Host ''
Write-Host 'If verification succeeds, run the configuration step:'
Write-Host "& `"$tfsConfigPath`" unattend /configure /unattendfile:`"$UnattendFile`""