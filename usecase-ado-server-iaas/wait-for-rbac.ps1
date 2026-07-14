<#
Waits for the freshly-activated PIM Owner role to propagate through ARM's
authorization store, then grants the signed-in user "Key Vault Crypto Officer"
on the target vault (needed to import the SKR wrap key). Retries with backoff.
Run async; it self-terminates on success or after the max attempts.
#>
param(
    [string]$VaultName = "sgallcaciskr314e",
    [string]$Me = "3a2c0db5-79a1-47ef-ac17-694e2c6370cf",
    [int]$MaxAttempts = 40,
    [int]$DelaySeconds = 30
)

$vid = (az keyvault show -n $VaultName --query id -o tsv).Trim()
for ($i = 1; $i -le $MaxAttempts; $i++) {
    $err = az role assignment create --assignee-object-id $Me --assignee-principal-type User `
        --role "Key Vault Crypto Officer" --scope $vid --output none 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SUCCESS on attempt $i : Key Vault Crypto Officer granted."
        exit 0
    }
    Write-Host "attempt $i/$MaxAttempts : still propagating (roleAssignments/write denied). Waiting ${DelaySeconds}s..."
    Start-Sleep -Seconds $DelaySeconds
}
Write-Host "FAILED: Owner did not propagate after $($MaxAttempts * $DelaySeconds) seconds."
exit 1
