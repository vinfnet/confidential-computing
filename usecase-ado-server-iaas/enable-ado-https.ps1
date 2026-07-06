# Enable HTTPS on the Azure DevOps Server (IIS) with a self-signed cert bound to port 443,
# and allow inbound 443 through the firewall. Idempotent.
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction Stop

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("HTTPS-START")

$siteName = "Azure DevOps Server"
$dns = @("10.0.0.4", $env:COMPUTERNAME, "localhost")

# 1. Reuse an existing self-signed cert for 10.0.0.4 if present, else create one.
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq "CN=10.0.0.4" -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName $dns -CertStoreLocation Cert:\LocalMachine\My `
        -FriendlyName "ADO Server HTTPS (self-signed)" -NotAfter (Get-Date).AddYears(3) `
        -KeyExportPolicy Exportable -KeySpec Signature
    $lines.Add("CERT-CREATED thumbprint=$($cert.Thumbprint)")
} else {
    $lines.Add("CERT-EXISTS thumbprint=$($cert.Thumbprint)")
}

# 2. Ensure an HTTPS (443) binding exists on the site.
$binding = Get-WebBinding -Name $siteName -Protocol "https" -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name $siteName -Protocol "https" -Port 443 -IPAddress "*"
    $lines.Add("BINDING-CREATED https:443")
} else {
    $lines.Add("BINDING-EXISTS https:443")
}

# 3. Attach the cert to the 443 binding via netsh (robust across IIS versions).
$appid = "{$([Guid]::NewGuid().ToString())}"
& netsh http delete sslcert ipport=0.0.0.0:443 2>$null | Out-Null
$add = & netsh http add sslcert ipport=0.0.0.0:443 certhash=$($cert.Thumbprint) appid=$appid 2>&1
$lines.Add("SSLCERT-BIND " + ($add -join ' '))

# 4. Firewall: allow inbound 443.
$fw = Get-NetFirewallRule -DisplayName "ADO Server HTTPS 443" -ErrorAction SilentlyContinue
if (-not $fw) {
    New-NetFirewallRule -DisplayName "ADO Server HTTPS 443" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 443 -Profile Any | Out-Null
    $lines.Add("FW-RULE-CREATED 443")
} else {
    $lines.Add("FW-RULE-EXISTS 443")
}

# 5. Local HTTPS self-test (skip cert validation).
try {
    add-type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest w, int p) { return true; } }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $r = Invoke-WebRequest -Uri "https://localhost/DefaultCollection/_apis/connectionData" -UseBasicParsing -TimeoutSec 20
    $lines.Add("LOCAL-HTTPS status=$($r.StatusCode)")
} catch {
    $sc = $_.Exception.Response.StatusCode.value__
    $lines.Add("LOCAL-HTTPS status=$sc msg=" + ($_.Exception.Message -replace '\s+',' '))
}

$lines.Add("HTTPS-END")
Write-Output ($lines -join "`n")
