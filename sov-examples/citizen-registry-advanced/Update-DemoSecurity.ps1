<#
.SYNOPSIS
    Apply post-deployment security updates to the Citizen Registry CVMs.

.DESCRIPTION
    Updates the application and SQL confidential VMs with workload-specific safeguards:
    - The H100 application CVM receives all available non-kernel security updates. Any
      kernel or NVIDIA package transaction is rejected so the validated driver/kernel
      pairing remains unchanged.
    - The SQL CVM receives all available package updates, including SQL Server and only
      confidential azure-fde kernel packages. It is restarted and validated afterward.

    Ubuntu Pro is required for ESM application fixes on the application CVM. Pass
    -EnableUbuntuPro to convert the Azure VM license and attach the guest entitlement.

.PARAMETER Prefix
    Resource prefix used by Deploy-AppInstance.ps1.

.PARAMETER ResourceGroupName
    Resource group containing both demo CVMs.

.PARAMETER SubscriptionId
    Azure subscription containing the deployment. Defaults to the current Azure CLI
    subscription.

.PARAMETER EnableUbuntuPro
    Enable Azure Ubuntu Pro on the application CVM so ESM fixes can be installed. This
    can add Azure licensing cost.

.PARAMETER ShutdownAfterUpdate
    Deallocate both CVMs after successful patching and validation.

.EXAMPLE
    .\Update-DemoSecurity.ps1 -Prefix yourprefix `
      -ResourceGroupName yourprefix12345app `
      -SubscriptionId 00000000-0000-0000-0000-000000000000 `
      -EnableUbuntuPro

.EXAMPLE
    .\Update-DemoSecurity.ps1 -Prefix yourprefix `
      -ResourceGroupName yourprefix12345app `
      -EnableUbuntuPro -ShutdownAfterUpdate
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]{3,12}$')]
    [string]$Prefix,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId,

    [switch]$EnableUbuntuPro,
    [switch]$ShutdownAfterUpdate
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $SubscriptionId = az account show --query id --output tsv
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    throw 'No Azure subscription was supplied and Azure CLI has no active subscription.'
}

$account = az account show --subscription $SubscriptionId --output json | ConvertFrom-Json
if (-not $account -or $account.id -ne $SubscriptionId) {
    throw "Azure CLI could not select subscription '$SubscriptionId'."
}

$appVmName = "$Prefix-citizen-cvm"
$sqlVmName = "$Prefix-sql-cvm"

function Get-VmPowerState {
    param([Parameter(Mandatory = $true)] [string]$VmName)

    $status = az vm get-instance-view `
        --subscription $SubscriptionId `
        --resource-group $ResourceGroupName `
        --name $VmName `
        --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code" `
        --output tsv

    return $status
}

function Invoke-GuestScript {
    param(
        [Parameter(Mandatory = $true)] [string]$VmName,
        [Parameter(Mandatory = $true)] [string]$Script,
        [Parameter(Mandatory = $true)] [string]$SuccessMarker
    )

    $scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) "$VmName-$([guid]::NewGuid().ToString('N')).sh"
    [System.IO.File]::WriteAllText($scriptPath, $Script, [System.Text.UTF8Encoding]::new($false))
    try {
        $result = az vm run-command invoke `
            --subscription $SubscriptionId `
            --resource-group $ResourceGroupName `
            --name $VmName `
            --command-id RunShellScript `
            --scripts "@$scriptPath" `
            --only-show-errors `
            --output json | ConvertFrom-Json

        $message = ($result.value.message -join "`n")
        Write-Host $message
        if ($message -notmatch [regex]::Escape($SuccessMarker)) {
            throw "Guest maintenance failed on '$VmName'; success marker '$SuccessMarker' was not returned."
        }
    } finally {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

foreach ($vmName in @($appVmName, $sqlVmName)) {
    if ((Get-VmPowerState -VmName $vmName) -ne 'PowerState/running') {
        throw "VM '$vmName' must be running before maintenance."
    }
}

if ($EnableUbuntuPro -and $PSCmdlet.ShouldProcess($appVmName, 'Enable Azure Ubuntu Pro')) {
    az vm update `
        --subscription $SubscriptionId `
        --resource-group $ResourceGroupName `
        --name $appVmName `
        --license-type UBUNTU_PRO `
        --only-show-errors `
        --output none
}

$appMaintenance = @'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l

wait_for_apt() {
  for attempt in $(seq 1 120); do
    if ! pgrep -x apt-get >/dev/null && ! pgrep -x dpkg >/dev/null && ! pgrep -x unattended-upgr >/dev/null; then
      return 0
    fi
    if [ "$attempt" -eq 120 ]; then
      echo APT_LOCK_TIMEOUT
      return 1
    fi
    sleep 5
  done
}

wait_for_apt
active_kernel=$(uname -r)

if ! pro status --format json 2>/dev/null | python3 -c "import json,sys; raise SystemExit(0 if json.load(sys.stdin).get('attached') else 1)"; then
  pro auto-attach
fi

apt-get update -qq
security_json=$(pro security-status --format json 2>/dev/null)
mapfile -t packages < <(printf '%s' "$security_json" | python3 -c "import json,sys; d=json.load(sys.stdin); packages=sorted({p['package'] for p in d['packages'] if not p['package'].startswith(('linux-', 'nvidia-', 'libnvidia-'))}); sys.stdout.write('\n'.join(packages))")

if [ "${#packages[@]}" -gt 0 ]; then
  simulation=$(apt-get -s install --only-upgrade "${packages[@]}")
  if printf '%s\n' "$simulation" | grep '^Inst ' | grep -Eq ' (linux-|nvidia-|libnvidia-)'; then
    echo ABORT_KERNEL_OR_NVIDIA_PACKAGE_DETECTED
    exit 1
  fi
  cctv_was_active=0
  if systemctl is-active --quiet citizen-cctv-anonymizer; then
    cctv_was_active=1
    systemctl stop citizen-cctv-anonymizer
  fi
  restore_cctv() {
    if [ "$cctv_was_active" -eq 1 ]; then systemctl start citizen-cctv-anonymizer || true; fi
  }
  trap restore_cctv EXIT
  apt-get install -y --only-upgrade "${packages[@]}"
  restore_cctv
  trap - EXIT
fi

audit=$(dpkg --audit)
test -z "$audit"
test "$(uname -r)" = "$active_kernel"
nvidia-smi --query-gpu=driver_version,name --format=csv,noheader
for service in nginx citizen-registry citizen-gpu-attestation citizen-cctv-anonymizer; do
  test "$(systemctl is-active "$service")" = active
done

remaining=$(pro security-status --format json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for p in d['packages'] if not p['package'].startswith(('linux-', 'nvidia-', 'libnvidia-'))))")
test "$remaining" = 0
printf 'APP_ACTIVE_KERNEL=%s\n' "$(uname -r)"
printf 'APP_REBOOT_REQUIRED='; test -f /var/run/reboot-required && echo yes || echo no
echo APP_SECURITY_MAINTENANCE_PASS
'@

if ($PSCmdlet.ShouldProcess($appVmName, 'Apply non-kernel security updates')) {
    Invoke-GuestScript -VmName $appVmName -Script $appMaintenance -SuccessMarker 'APP_SECURITY_MAINTENANCE_PASS'
}

$sqlMaintenance = @'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export ACCEPT_EULA=Y
export NEEDRESTART_MODE=l

for attempt in $(seq 1 120); do
  if ! pgrep -x apt-get >/dev/null && ! pgrep -x dpkg >/dev/null && ! pgrep -x unattended-upgr >/dev/null; then break; fi
  if [ "$attempt" -eq 120 ]; then echo APT_LOCK_TIMEOUT; exit 1; fi
  sleep 5
done

if [ -n "$(dpkg --audit)" ]; then
  echo 'dpkg has an interrupted transaction; repair it before rerunning maintenance.'
  dpkg --audit
  exit 1
fi

source_file=/etc/apt/sources.list.d/mssql-server-2022.list
key_file=/usr/share/keyrings/microsoft-prod.gpg
expected_fingerprint=BC528686B50D79E339D3721CEB3E94ADBE1229CF
actual_fingerprint=$(gpg --batch --no-default-keyring --keyring "$key_file" --list-keys --with-colons 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')
test "$actual_fingerprint" = "$expected_fingerprint"
if ! grep -q "signed-by=$key_file" "$source_file"; then
  sed -i "s#^deb \[#deb [signed-by=$key_file #" "$source_file"
fi

apt_output=$(apt-get update 2>&1)
printf '%s\n' "$apt_output"
if printf '%s\n' "$apt_output" | grep -Eq 'NO_PUBKEY|signature verification|Failed to fetch'; then
  echo APT_REPOSITORY_VALIDATION_FAILED
  exit 1
fi

simulation=$(apt-get -s dist-upgrade)
if printf '%s\n' "$simulation" | grep '^Remv '; then
  echo ABORT_PACKAGE_REMOVAL_DETECTED
  exit 1
fi
if printf '%s\n' "$simulation" | grep '^Inst ' | grep -E ' linux-' | grep -vE 'azure-fde|linux-(base|libc-dev|cloud-tools-common|tools-common)'; then
  echo ABORT_NON_FDE_KERNEL_DETECTED
  exit 1
fi

apt-get dist-upgrade -y
dpkg --configure -a
test -z "$(dpkg --audit)"
test "$(systemctl is-active mssql-server)" = active
test "$(apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep -c '^Inst ' || true)" = 0
printf 'SQL_INSTALLED_FDE_META=%s\n' "$(dpkg-query -W -f='${Version}' linux-azure-fde)"
printf 'SQL_SERVER_VERSION=%s\n' "$(dpkg-query -W -f='${Version}' mssql-server)"
echo SQL_SECURITY_INSTALL_PASS
'@

if ($PSCmdlet.ShouldProcess($sqlVmName, 'Apply complete package and SQL Server updates')) {
    Invoke-GuestScript -VmName $sqlVmName -Script $sqlMaintenance -SuccessMarker 'SQL_SECURITY_INSTALL_PASS'
    az vm restart `
        --subscription $SubscriptionId `
        --resource-group $ResourceGroupName `
        --name $sqlVmName `
        --only-show-errors
}

$sqlValidation = @'
#!/usr/bin/env bash
set -euo pipefail
security_json=$(pro security-status --format json 2>/dev/null)
security_updates=$(printf '%s' "$security_json" | python3 -c "import json,sys; s=json.load(sys.stdin)['summary']; print(s['num_standard_security_updates'] + s['num_esm_apps_updates'] + s['num_esm_infra_updates'])")
test "$security_updates" = 0
test "$(apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep -c '^Inst ' || true)" = 0
test -z "$(dpkg --audit)"
case "$(uname -r)" in
  *-azure-fde) ;;
  *) echo ACTIVE_KERNEL_IS_NOT_AZURE_FDE; exit 1 ;;
esac
test "$(systemctl is-active mssql-server)" = active
ss -lnt | grep -q ':1433 '
printf 'SQL_ACTIVE_KERNEL=%s\n' "$(uname -r)"
printf 'SQL_SERVER_VERSION=%s\n' "$(dpkg-query -W -f='${Version}' mssql-server)"
echo SQL_SECURITY_VALIDATION_PASS
'@

if ($PSCmdlet.ShouldProcess($sqlVmName, 'Validate rebooted SQL CVM')) {
    Invoke-GuestScript -VmName $sqlVmName -Script $sqlValidation -SuccessMarker 'SQL_SECURITY_VALIDATION_PASS'
}

if ($ShutdownAfterUpdate) {
    foreach ($vmName in @($appVmName, $sqlVmName)) {
        if ($PSCmdlet.ShouldProcess($vmName, 'Deallocate VM')) {
            az vm deallocate `
                --subscription $SubscriptionId `
                --resource-group $ResourceGroupName `
                --name $vmName `
                --only-show-errors
        }
    }
}

Write-Host 'Citizen Registry security maintenance completed successfully.' -ForegroundColor Green