param(
    [Parameter(Mandatory)] [string] $BaseUrl,
    [string] $SeedFile = (Join-Path $PSScriptRoot "citizen-registry-app\seed-data.sql")
)

$ErrorActionPreference = "Stop"
$lines = Get-Content -Path $SeedFile
$rx = [regex]"VALUES \(N'([^']*)', N'([^']*)', N'([^']*)', '([^']*)', N'([^']*)', N'([^']*)', N'([^']*)', N'([^']*)', N'([^']*)', (\d+), N'([^']*)', N'([^']*)', N'([^']*)', (\d)\);"

$ok = 0; $fail = 0
foreach ($line in $lines) {
    $m = $rx.Match($line)
    if (-not $m.Success) { continue }
    $form = @{
        national_id       = $m.Groups[1].Value
        first_name        = $m.Groups[2].Value
        last_name         = $m.Groups[3].Value
        date_of_birth     = $m.Groups[4].Value
        sex               = $m.Groups[5].Value
        region            = $m.Groups[6].Value
        municipality      = $m.Groups[7].Value
        address_line      = $m.Groups[8].Value
        postal_code       = $m.Groups[9].Value
        household_size    = $m.Groups[10].Value
        marital_status    = $m.Groups[11].Value
        employment_status = $m.Groups[12].Value
        tax_bracket       = $m.Groups[13].Value
    }
    if ($m.Groups[14].Value -eq '1') { $form['registered_voter'] = 'on' }
    try {
        Invoke-WebRequest -Uri ($BaseUrl.TrimEnd('/') + "/citizen/new") -Method POST -Body $form -TimeoutSec 30 -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop | Out-Null
        $ok++
    } catch {
        # A 302 redirect back to / is success for a form POST
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 302) { $ok++ }
        else { $fail++; Write-Host "  FAIL $($form.national_id): $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}
Write-Host "Seeded: $ok  Failed: $fail" -ForegroundColor Cyan
