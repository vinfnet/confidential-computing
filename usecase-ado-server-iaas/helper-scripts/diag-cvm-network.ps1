# Diagnostics: is ADO Server listening on port 80, and does the firewall allow the ACI subnet?
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("DIAG-START")

# 1. Is anything listening on port 80?
try {
    $l = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction Stop |
        Select-Object -First 3 -Property LocalAddress, LocalPort, OwningProcess
    foreach ($c in $l) {
        $pname = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $lines.Add("LISTEN $($c.LocalAddress):$($c.LocalPort) pid=$($c.OwningProcess) proc=$pname")
    }
    if (-not $l) { $lines.Add("LISTEN-NONE port80") }
} catch { $lines.Add("LISTEN-ERR " + ($_.Exception.Message -replace '\s+',' ')) }

# 2. Firewall profile state
try {
    $fp = Get-NetFirewallProfile | Select-Object Name, Enabled
    foreach ($p in $fp) { $lines.Add("FWPROFILE $($p.Name) enabled=$($p.Enabled)") }
} catch { $lines.Add("FWPROFILE-ERR " + ($_.Exception.Message -replace '\s+',' ')) }

# 3. Inbound allow rules for port 80
try {
    $rules = Get-NetFirewallPortFilter -Protocol TCP |
        Where-Object { $_.LocalPort -eq 80 } |
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' } |
        Select-Object -First 5 -Property DisplayName, Profile
    foreach ($r in $rules) { $lines.Add("FWRULE-ALLOW-80 '$($r.DisplayName)' profile=$($r.Profile)") }
    if (-not $rules) { $lines.Add("FWRULE-ALLOW-80-NONE") }
} catch { $lines.Add("FWRULE-ERR " + ($_.Exception.Message -replace '\s+',' ')) }

# 4. Local self-test of the collection URL
try {
    $r = Invoke-WebRequest -Uri "http://localhost/DefaultCollection/_apis/connectionData" -UseBasicParsing -TimeoutSec 15
    $lines.Add("LOCAL-HTTP status=$($r.StatusCode)")
} catch {
    $sc = $_.Exception.Response.StatusCode.value__
    $lines.Add("LOCAL-HTTP status=$sc msg=" + ($_.Exception.Message -replace '\s+',' '))
}

$lines.Add("DIAG-END")
Write-Output ($lines -join "`n")
