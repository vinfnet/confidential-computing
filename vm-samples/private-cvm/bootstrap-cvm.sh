#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 9 && "$1" != *=* ]]; then
    key_vault_name="$1"
    storage_account_name="$2"
    container_name="$3"
    key_name="$4"
    storage_sftp_key_secret_name="$5"
    storage_sftp_user_name="$6"
    identity_client_id="$7"
    maa_endpoint="$8"
    expected_vm_id="$9"
    shift 9
fi

for argument in "$@"; do
  case "$argument" in
    keyVaultName=*) key_vault_name="${argument#*=}" ;;
    storageAccountName=*) storage_account_name="${argument#*=}" ;;
    containerName=*) container_name="${argument#*=}" ;;
    keyName=*) key_name="${argument#*=}" ;;
    storageSftpKeySecretName=*) storage_sftp_key_secret_name="${argument#*=}" ;;
    storageSftpUserName=*) storage_sftp_user_name="${argument#*=}" ;;
    identityClientId=*) identity_client_id="${argument#*=}" ;;
    maaEndpoint=*) maa_endpoint="${argument#*=}" ;;
    expectedVmId=*) expected_vm_id="${argument#*=}" ;;
    *) echo "Unknown argument: $argument" >&2; exit 2 ;;
  esac
done

: "${key_vault_name:?keyVaultName is required}"
: "${storage_account_name:?storageAccountName is required}"
: "${container_name:?containerName is required}"
: "${key_name:?keyName is required}"
: "${storage_sftp_key_secret_name:?storageSftpKeySecretName is required}"
: "${storage_sftp_user_name:?storageSftpUserName is required}"
: "${identity_client_id:?identityClientId is required}"
: "${maa_endpoint:?maaEndpoint is required}"
: "${expected_vm_id:?expectedVmId is required}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3 python3-pip python3-venv tpm2-tools

install -d -m 0755 /opt/private-cvm
if [[ ! -d /opt/cvm-attestation-tools/.git ]]; then
  git clone --depth 1 https://github.com/Azure/cvm-attestation-tools.git /opt/cvm-attestation-tools
  git clone --depth 1 https://github.com/microsoft/TSS.MSR.git /opt/cvm-attestation-tools/cvm-attestation/TSS_MSR
fi

python3 -m venv /opt/private-cvm/venv
/opt/private-cvm/venv/bin/pip install --quiet --upgrade pip
/opt/private-cvm/venv/bin/pip install --quiet requests cryptography paramiko
/opt/private-cvm/venv/bin/pip install --quiet -r /opt/cvm-attestation-tools/cvm-attestation/requirements.txt

cat >/opt/private-cvm/demo.py <<'PYTHON'
#!/usr/bin/env python3
import argparse
import base64
import io
import json
import sys
from pathlib import Path

import requests
import paramiko
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_unwrap_with_padding
from cryptography.hazmat.primitives.serialization import load_der_private_key

sys.path.insert(0, "/opt/cvm-attestation-tools/cvm-attestation")
from src.attestation_client import AttestationClient, AttestationClientParameters, Verifier
from src.isolation import IsolationType
from src.logger import Logger
from src.os_info import OsInfo
from src.tpm_wrapper import TssWrapper
import src.tpm_wrapper as tpm_wrapper


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def jwk_integer(value):
    return int.from_bytes(b64url_decode(value), "big")


def managed_identity_token(resource, client_id):
    response = requests.get(
        "http://169.254.169.254/metadata/identity/oauth2/token",
        params={
            "api-version": "2018-02-01",
            "resource": resource,
            "client_id": client_id,
        },
        headers={"Metadata": "true"},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def key_metadata(config, token):
    response = requests.get(
        f"https://{config.key_vault_name}.vault.azure.net/keys/{config.key_name}",
        params={"api-version": "7.4"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def key_vault_secret(config, vault_token, secret_name):
    response = requests.get(
        f"https://{config.key_vault_name}.vault.azure.net/secrets/{secret_name}",
        params={"api-version": "7.4"},
        headers={"Authorization": f"Bearer {vault_token}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["value"]


def open_storage_sftp(config, vault_token):
    private_key_text = base64.b64decode(
        key_vault_secret(config, vault_token, config.storage_sftp_key_secret_name)
    ).decode("utf-8")
    private_key = paramiko.RSAKey.from_private_key(io.StringIO(private_key_text))
    transport = paramiko.Transport((f"{config.storage_account_name}.blob.core.windows.net", 22))
    transport.connect(
        username=f"{config.storage_account_name}.{config.storage_sftp_user_name}",
        pkey=private_key,
    )
    return transport, paramiko.SFTPClient.from_transport(transport)


def seed(config):
    vault_token = managed_identity_token("https://vault.azure.net", config.identity_client_id)
    metadata = key_metadata(config, vault_token)
    key_id = metadata["key"]["kid"]
    plaintext = b"This plaintext was released only inside the attested confidential VM."
    response = requests.post(
        f"{key_id}/encrypt",
        params={"api-version": "7.4"},
        headers={"Authorization": f"Bearer {vault_token}"},
        json={"alg": "RSA-OAEP-256", "value": b64url_encode(plaintext)},
        timeout=30,
    )
    response.raise_for_status()
    document = {
        "algorithm": "RSA-OAEP-256",
        "keyId": key_id,
        "ciphertext": response.json()["value"],
    }
    transport, sftp = open_storage_sftp(config, vault_token)
    try:
        with sftp.file("protected.json", "w") as remote_file:
            remote_file.write(json.dumps(document))
    finally:
        sftp.close()
        transport.close()
    print(f"Stored encrypted payload in {config.container_name}/protected.json")
    print(f"Key used: {key_id}")


def attest(config):
    endpoint = f"https://{config.maa_endpoint}/attest/AzureGuest?api-version=2020-10-01"
    parameters = AttestationClientParameters(
        endpoint=endpoint,
        verifier=Verifier.MAA,
        isolation_type=IsolationType.SEV_SNP,
        claims=None,
    )
    result = AttestationClient(Logger("private-cvm").get_logger(), parameters).attest_guest()
    if not result:
        raise RuntimeError("MAA returned no guest-attestation token")
    token = result.decode("utf-8").strip() if isinstance(result, bytes) else str(result).strip()
    claims = json.loads(b64url_decode(token.split(".")[1]))
    attested_vm_id = claims.get("x-ms-azurevm-vmid", "").upper()
    if attested_vm_id != config.expected_vm_id.upper():
        raise RuntimeError(
            f"MAA VMID mismatch: expected {config.expected_vm_id}, got {attested_vm_id or '(missing)'}"
        )
    print(f"MAA token VMID: {attested_vm_id}")
    return token


def tpm_decrypt_wrapping_key(encrypted_key, use_oaep=True):
    os_info = OsInfo()
    tss = TssWrapper(Logger("private-cvm-tpm").get_logger())
    pcr_select = tss.get_pcr_select(os_info.pcr_list)
    pcrs = tss.get_pcr_values(os_info.pcr_list)
    tpm = tpm_wrapper.Tpm()
    tpm.connect()
    try:
        trial = tpm.StartAuthSession(
            None,
            None,
            tpm_wrapper.crypto.randomBytes(20),
            None,
            tpm_wrapper.TPM_SE.TRIAL,
            tpm_wrapper.NullSymDef,
            tpm_wrapper.TPM_ALG_ID.SHA256,
        )
        pcr_digest = tss.sha256_hash_update(pcrs)
        tpm.PolicyPCR(trial.handle, bytes.fromhex(pcr_digest), pcr_select)
        policy_digest = tpm.PolicyGetDigest(trial.handle)
        attributes = (
            tpm_wrapper.TPMA_OBJECT.decrypt
            | tpm_wrapper.TPMA_OBJECT.fixedTPM
            | tpm_wrapper.TPMA_OBJECT.fixedParent
            | tpm_wrapper.TPMA_OBJECT.sensitiveDataOrigin
            | tpm_wrapper.TPMA_OBJECT.noDA
        )
        parameters = tpm_wrapper.TPMS_RSA_PARMS(
            tpm_wrapper.TPMT_SYM_DEF_OBJECT(),
            tpm_wrapper.TPMS_NULL_ASYM_SCHEME(),
            2048,
            0,
        )
        public = tpm_wrapper.TPMT_PUBLIC(
            tpm_wrapper.TPM_ALG_ID.SHA256,
            attributes,
            policy_digest,
            parameters,
            tpm_wrapper.TPM2B_PUBLIC_KEY_RSA(),
        )
        primary = tpm.withSession(tpm_wrapper.NullPwSession).CreatePrimary(
            tpm_wrapper.Owner,
            tpm_wrapper.TPMS_SENSITIVE_CREATE(),
            public,
            None,
            pcr_select,
        )
        policy = tpm.StartAuthSession(
            None,
            None,
            tpm_wrapper.crypto.randomBytes(20),
            None,
            tpm_wrapper.TPM_SE.POLICY,
            tpm_wrapper.NullSymDef,
            tpm_wrapper.TPM_ALG_ID.SHA256,
        )
        session = tpm_wrapper.Session(policy.handle, policy.nonceTPM)
        tpm.PolicyPCR(policy.handle, bytes.fromhex(pcr_digest), pcr_select)
        scheme = (
            tpm_wrapper.TPMS_SCHEME_OAEP(tpm_wrapper.TPM_ALG_ID.SHA1)
            if use_oaep
            else tpm_wrapper.TPMS_SCHEME_RSAES()
        )
        return bytes(
            tpm.withSession(session).RSA_Decrypt(
                primary.getHandle(), encrypted_key, scheme, None
            )
        )
    finally:
        try:
            tss.cleanSlots(tpm, tpm_wrapper.TPM_HT.TRANSIENT)
            tss.cleanSlots(tpm, tpm_wrapper.TPM_HT.LOADED_SESSION)
        finally:
            tpm.close()


def unwrap_key_hsm(value):
    wrapped = json.loads(b64url_decode(value)) if isinstance(value, str) else value
    if wrapped.get("header", {}).get("enc") != "CKM_RSA_AES_KEY_WRAP":
        raise RuntimeError("Unsupported key_hsm encryption format")
    ciphertext = b64url_decode(wrapped["ciphertext"])
    encrypted_aes_key = ciphertext[:256]
    wrapped_private_key = ciphertext[256:]
    aes_key = None
    for use_oaep in (True, False):
        try:
            aes_key = tpm_decrypt_wrapping_key(encrypted_aes_key, use_oaep)
            break
        except Exception:
            if not use_oaep:
                raise
    try:
        private_der = aes_key_unwrap_with_padding(aes_key, wrapped_private_key)
    except Exception:
        private_der = aes_key_unwrap(aes_key, wrapped_private_key)
    return load_der_private_key(private_der, password=None)


def released_private_key(jws):
    payload = json.loads(b64url_decode(jws.split(".")[1]))
    key = payload["response"]["key"]["key"]
    if "key_hsm" in key:
        return unwrap_key_hsm(key["key_hsm"])
    public = rsa.RSAPublicNumbers(jwk_integer(key["e"]), jwk_integer(key["n"]))
    numbers = rsa.RSAPrivateNumbers(
        p=jwk_integer(key["p"]),
        q=jwk_integer(key["q"]),
        d=jwk_integer(key["d"]),
        dmp1=jwk_integer(key["dp"]),
        dmq1=jwk_integer(key["dq"]),
        iqmp=jwk_integer(key["qi"]),
        public_numbers=public,
    )
    return numbers.private_key()


def decrypt(config):
    vault_token = managed_identity_token("https://vault.azure.net", config.identity_client_id)
    transport, sftp = open_storage_sftp(config, vault_token)
    try:
        with sftp.file("protected.json", "r") as remote_file:
            document = json.loads(remote_file.read().decode("utf-8"))
    finally:
        sftp.close()
        transport.close()

    maa_token = attest(config)
    metadata = key_metadata(config, vault_token)
    key_id = metadata["key"]["kid"]
    release = requests.post(
        f"{key_id}/release",
        params={"api-version": "7.4"},
        headers={"Authorization": f"Bearer {vault_token}"},
        json={"target": maa_token},
        timeout=60,
    )
    if release.status_code != 200:
        raise RuntimeError(f"Secure Key Release failed ({release.status_code}): {release.text}")

    private_key = released_private_key(release.json()["value"])
    plaintext = private_key.decrypt(
        b64url_decode(document["ciphertext"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print("Secure Key Release succeeded; plaintext follows:")
    print(plaintext.decode("utf-8"))
    print(f"Key Vault request ID: {release.headers.get('x-ms-request-id', 'not returned')}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["seed", "decrypt"])
    parser.add_argument("--key-vault-name", required=True)
    parser.add_argument("--storage-account-name", required=True)
    parser.add_argument("--container-name", required=True)
    parser.add_argument("--key-name", required=True)
    parser.add_argument("--storage-sftp-key-secret-name", required=True)
    parser.add_argument("--storage-sftp-user-name", required=True)
    parser.add_argument("--identity-client-id", required=True)
    parser.add_argument("--maa-endpoint", required=True)
    parser.add_argument("--expected-vm-id", required=True)
    config = parser.parse_args()
    seed(config) if config.action == "seed" else decrypt(config)


if __name__ == "__main__":
    main()
PYTHON

cat >/opt/private-cvm/run-demo <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec /opt/private-cvm/venv/bin/python /opt/private-cvm/demo.py "\${1:-decrypt}" \\
  --key-vault-name "$key_vault_name" \\
  --storage-account-name "$storage_account_name" \\
  --container-name "$container_name" \\
  --key-name "$key_name" \\
    --storage-sftp-key-secret-name "$storage_sftp_key_secret_name" \\
    --storage-sftp-user-name "$storage_sftp_user_name" \\
  --identity-client-id "$identity_client_id" \\
    --maa-endpoint "$maa_endpoint" \\
    --expected-vm-id "$expected_vm_id"
EOF
chmod 0755 /opt/private-cvm/run-demo

if [[ ! -e /dev/tpmrm0 ]]; then
  echo "Expected confidential VM vTPM device /dev/tpmrm0 was not found" >&2
  exit 1
fi

/opt/private-cvm/run-demo seed
/opt/private-cvm/run-demo decrypt
echo "PRIVATE_CVM_DEMO_SUCCESS"