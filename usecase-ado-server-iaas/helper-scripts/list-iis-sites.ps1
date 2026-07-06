Import-Module WebAdministration -ErrorAction SilentlyContinue
Write-Output "SITES-START"
Get-ChildItem IIS:\Sites | ForEach-Object {
    $siteName = $_.Name
    Write-Output ("SITE name='{0}' id={1} state={2}" -f $_.Name, $_.Id, $_.State)
    $_.Bindings.Collection | ForEach-Object {
        Write-Output ("  BINDING proto={0} info='{1}'" -f $_.protocol, $_.bindingInformation)
    }
}
Write-Output "APPPOOLS"
Get-ChildItem IIS:\AppPools | ForEach-Object { Write-Output ("  POOL name='{0}' state={1}" -f $_.Name, $_.State) }
Write-Output "SITES-END"
