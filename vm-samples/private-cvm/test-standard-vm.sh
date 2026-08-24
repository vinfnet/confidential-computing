#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 3 && "$1" != *=* ]]; then
  key_vault_name="$1"
  key_name="$2"
  identity_client_id="$3"
  shift 3
fi

for argument in "$@"; do
  case "$argument" in
    keyVaultName=*) key_vault_name="${argument#*=}" ;;
    keyName=*) key_name="${argument#*=}" ;;
    identityClientId=*) identity_client_id="${argument#*=}" ;;
    *) echo "Unknown argument: $argument" >&2; exit 2 ;;
  esac
done

: "${key_vault_name:?keyVaultName is required}"
: "${key_name:?keyName is required}"
: "${identity_client_id:?identityClientId is required}"

token_response="$(curl -fsS -G \
  -H Metadata:true \
  --data-urlencode api-version=2018-02-01 \
  --data-urlencode resource=https://vault.azure.net \
  --data-urlencode client_id="$identity_client_id" \
  http://169.254.169.254/metadata/identity/oauth2/token)"
access_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$token_response")"

key_response="$(curl -fsS \
  -H "Authorization: Bearer $access_token" \
  "https://${key_vault_name}.vault.azure.net/keys/${key_name}?api-version=7.4")"
key_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["key"]["kid"])' <<<"$key_response")"

echo "Managed identity authorization: SUCCEEDED"
echo "Key metadata: $key_id"

if [[ -e /dev/tpmrm0 ]]; then
  echo "vTPM device: PRESENT"
else
  echo "vTPM device: ABSENT"
fi

isolation="$(systemd-detect-virt --cvm 2>/dev/null || true)"
if [[ -n "$isolation" && "$isolation" != "none" ]]; then
  echo "Confidential isolation: $isolation"
else
  echo "Confidential isolation: NONE"
fi

response_file="$(mktemp)"
http_status="$(curl -sS -o "$response_file" -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $access_token" \
  -H 'Content-Type: application/json' \
  --data "$(python3 -c 'import json,sys; print(json.dumps({"target": sys.argv[1]}))' "$access_token")" \
  "${key_id}/release?api-version=7.4")"

echo "Key release HTTP status: $http_status"
cat "$response_file"
echo

if [[ "$http_status" == "200" ]]; then
  echo "ERROR: Standard VM unexpectedly released the VMID-bound key" >&2
  exit 1
fi

if grep -qiE 'attestation|release requirements|Forbidden' "$response_file"; then
  echo "STANDARD_VM_SKR_BLOCKED"
  exit 0
fi

echo "ERROR: Release failed for an unexpected reason" >&2
exit 1