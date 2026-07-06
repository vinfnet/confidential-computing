$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

& "$scriptRoot\Install-AdoServerOneShot.ps1" `
    -InstallerPath 'C:\Install\mul_azure_devops_server_x64_web_installer_1758aa41.exe' `
    -ProjectCollectionName 'DefaultCollection' `
    -ServiceAccountName 'NT AUTHORITY\NETWORK SERVICE' `
    -WebBinding 'HTTP' `
    -SqlMode 'SqlExpress'