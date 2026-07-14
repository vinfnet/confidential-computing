#!/usr/bin/env python3
"""
Attestation-gated Azure DevOps PAT release for a confidential (SEV-SNP) ACI agent.

This runs ONCE at container start, BEFORE the Azure Pipelines agent registers.
It proves the container is a genuine, non-debuggable Azure SEV-SNP confidential
UVM running the exact approved CCE policy, and only then releases the RSA wrap
key that decrypts the sealed PAT bundle. The plaintext PAT is written to a
tmpfs file (AZP_TOKEN_FILE) and never touches the image, the ARM deployment,
container env in the clear, or Kubernetes/etcd.

Security properties (why this beats a plain Key Vault secret fetch):
  * The wrap key carries an AKV Secure Key Release (SKR) policy requiring:
        x-ms-attestation-type        == sevsnpvm
        x-ms-compliance-status       == azure-compliant-uvm
        x-ms-sevsnpvm-is-debuggable  == false
        x-ms-sevsnpvm-hostdata       == sha256(cce-policy)
    A managed-identity token alone cannot release the key — AKV also demands a
    fresh MAA attestation token that satisfies every claim above. So even a
    leaked identity credential used from a non-confidential/debuggable context
    cannot obtain the PAT.
  * The key is released wrapped (CKM_RSA_AES_KEY_WRAP) to an ephemeral RSA key
    generated inside this TEE, so it never leaves the enclave in the clear.

Fails CLOSED: any error exits non-zero and no PAT is written, so the agent
never registers unless the release genuinely succeeded inside the TEE.
"""

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
)

# --- required configuration (all pinned into the CCE policy) ---------------
MAA_ENDPOINT = os.environ["MAA_ENDPOINT"]        # e.g. <region>.attest.azure.net (bare host)
AKV_ENDPOINT = os.environ["AKV_ENDPOINT"]        # e.g. <vault-name>.vault.azure.net (bare host)
KEY_NAME = os.environ["SKR_KEY_NAME"]            # wrap-key name in AKV
SEALED_PAT_B64 = os.environ["SEALED_PAT_B64"]    # base64 of the SEAL bundle

# --- optional configuration -------------------------------------------------
GET_SNP_REPORT = os.environ.get("GET_SNP_REPORT", "/usr/local/bin/get-snp-report")
AZP_TOKEN_FILE = os.environ.get("AZP_TOKEN_FILE", "/azp/.token")
SEAL_AAD = os.environ.get("SEAL_AAD", "ado-pat/v1").encode("ascii")

REPORT_LEN = 0x4A0


def log(msg: str) -> None:
    sys.stderr.write(f"[skr-pat] {msg}\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# base64url helpers
# ---------------------------------------------------------------------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int_to_b64url(i: int) -> str:
    return _b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))


# ---------------------------------------------------------------------------
# Ephemeral RSA wrap key — AKV /release wraps the released key to this public
# key using CKM_RSA_AES_KEY_WRAP so it never leaves the TEE in the clear.
# ---------------------------------------------------------------------------
_EPHEMERAL_PRIV = None
EPHEMERAL_JWK_PUB = None


def _ensure_ephemeral_key():
    global _EPHEMERAL_PRIV, EPHEMERAL_JWK_PUB
    if _EPHEMERAL_PRIV is not None:
        return
    _EPHEMERAL_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = _EPHEMERAL_PRIV.public_key().public_numbers()
    EPHEMERAL_JWK_PUB = {
        "kty": "RSA",
        "kid": "ado-agent-ephemeral-wrap",
        "key_ops": ["wrapKey", "encrypt"],
        "alg": "RSA-OAEP-256",
        "n": _int_to_b64url(pub.n),
        "e": _int_to_b64url(pub.e),
    }


# ---------------------------------------------------------------------------
# SEV-SNP report + MAA attestation
# ---------------------------------------------------------------------------
def fetch_snp_report(report_data: bytes) -> bytes:
    proc = subprocess.run(
        [GET_SNP_REPORT, report_data.hex()],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"get-snp-report failed: {proc.stderr!r}")
    hex_out = "".join(
        c for c in proc.stdout.decode("ascii", "replace") if c in "0123456789abcdefABCDEF"
    )
    return bytes.fromhex(hex_out)[:REPORT_LEN]


def load_uvm() -> dict:
    explicit = os.environ.get("UVM_SECURITY_CONTEXT_DIR")
    ctx = explicit if (explicit and os.path.isdir(explicit)) else None
    if not ctx:
        for entry in os.listdir("/"):
            if entry.startswith("security-context-") and os.path.isdir("/" + entry):
                ctx = "/" + entry
                break
    if not ctx:
        raise RuntimeError("UVM_SECURITY_CONTEXT_DIR not found")
    return {
        "host_amd_cert_b64": (Path(ctx) / "host-amd-cert-base64").read_text().strip(),
        "reference_info_b64": (Path(ctx) / "reference-info-base64").read_text().strip(),
    }


def get_maa_token() -> str:
    # The 'keys' claim is REQUIRED for AKV /release: MAA copies the runtime
    # data into the issued JWT under x-ms-runtime.keys, and AKV uses one of
    # those public keys as the RSA half of CKM_RSA_AES_KEY_WRAP.
    _ensure_ephemeral_key()
    runtime = {
        "client": "ado-agent-skr-pat",
        "ts": int(time.time()),
        "keys": [EPHEMERAL_JWK_PUB],
    }
    runtime_bytes = json.dumps(runtime).encode("utf-8")
    report_data = hashlib.sha256(runtime_bytes).digest() + b"\x00" * 32

    report = fetch_snp_report(report_data)
    uvm = load_uvm()
    thim = json.loads(base64.b64decode(uvm["host_amd_cert_b64"]))
    vcek_chain = (thim.get("vcekCert", "") + thim.get("certificateChain", "")).encode("utf-8")
    endorsements = json.dumps(
        {"Uvm": [_b64url(base64.b64decode(uvm["reference_info_b64"]))]}
    ).encode("utf-8")

    inner = {
        "SnpReport": _b64url(report),
        "VcekCertChain": _b64url(vcek_chain),
        "Endorsements": _b64url(endorsements),
    }
    body = {
        "report": _b64url(json.dumps(inner).encode("utf-8")),
        "runtimeData": {"data": _b64url(runtime_bytes), "dataType": "JSON"},
    }
    url = f"https://{MAA_ENDPOINT}/attest/SevSnpVm?api-version=2022-08-01"
    r = requests.post(url, json=body, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"MAA returned HTTP {r.status_code}: {r.text[:500]}")
    token = r.json().get("token")
    if not token:
        raise RuntimeError(f"MAA returned no token: {r.text[:500]}")
    return token


# ---------------------------------------------------------------------------
# Managed-identity token for AKV (IMDS is reachable inside the ACI TEE)
# ---------------------------------------------------------------------------
def get_akv_token() -> str:
    params = {"api-version": "2018-02-01", "resource": "https://vault.azure.net"}
    client_id = os.environ.get("AZP_MI_CLIENT_ID", "").strip()
    if client_id:
        params["client_id"] = client_id
    r = requests.get(
        "http://169.254.169.254/metadata/identity/oauth2/token",
        params=params,
        headers={"Metadata": "true"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Secure Key Release + unwrap
# ---------------------------------------------------------------------------
def release_key(maa_token: str, akv_token: str):
    akv_host = AKV_ENDPOINT.replace("https://", "").rstrip("/")
    info = requests.get(
        f"https://{akv_host}/keys/{KEY_NAME}?api-version=7.4",
        headers={"Authorization": f"Bearer {akv_token}"},
        timeout=15,
    ).json()
    kid = info.get("key", {}).get("kid", "")
    key_version = kid.rstrip("/").split("/")[-1]

    resp = requests.post(
        f"https://{akv_host}/keys/{KEY_NAME}/{key_version}/release?api-version=7.4",
        headers={"Authorization": f"Bearer {akv_token}", "Content-Type": "application/json"},
        json={"target": maa_token, "enc": "RSA_AES_KEY_WRAP_256"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"AKV release failed HTTP {resp.status_code}: {resp.text[:600]}")
    jws = resp.json()["value"]
    payload = json.loads(_b64url_decode(jws.split(".")[1]))
    jwk = payload["response"]["key"]["key"]
    if "key_hsm" in jwk:
        return unwrap_ckm_rsa_aes(jwk["key_hsm"])
    return jwk_to_private_key(jwk)


def unwrap_ckm_rsa_aes(key_hsm_b64: str):
    """CKM_RSA_AES_KEY_WRAP unwrap of the AKV /release HSM payload:
        [0 .. rsa_len)   RSA-OAEP-SHA256(AES-256 key)
        [rsa_len .. end) AES key wrap of PKCS#8 DER of the RSA private key
    """
    blob = _b64url_decode(key_hsm_b64)
    if blob[:1] == b"{":
        try:
            env = json.loads(blob)
            ct_b64 = env.get("ciphertext") or env.get("encrypted_key") or env.get("value")
            if ct_b64 is None:
                raise RuntimeError(f"key_hsm envelope has no ciphertext field: {list(env.keys())}")
            blob = _b64url_decode(ct_b64)
        except json.JSONDecodeError:
            pass
    rsa_len = (_EPHEMERAL_PRIV.key_size + 7) // 8
    wrapped_aes = blob[:rsa_len]
    wrapped_key = blob[rsa_len:]
    aes_key = _EPHEMERAL_PRIV.decrypt(
        wrapped_aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    # AKV uses AES-KW (RFC 3394); fall back to KWP (RFC 5649) if needed.
    try:
        pkcs8_der = aes_key_unwrap(aes_key, wrapped_key)
    except Exception as exc:
        log(f"aes_key_unwrap failed ({exc}); trying aes_key_unwrap_with_padding")
        pkcs8_der = aes_key_unwrap_with_padding(aes_key, wrapped_key)
    return serialization.load_der_private_key(pkcs8_der, password=None)


def jwk_to_private_key(jwk: dict):
    def _i(name):
        return int.from_bytes(_b64url_decode(jwk[name]), "big")

    pub = rsa.RSAPublicNumbers(_i("e"), _i("n"))
    priv = rsa.RSAPrivateNumbers(_i("p"), _i("q"), _i("d"), _i("dp"), _i("dq"), _i("qi"), pub)
    return priv.private_key()


# ---------------------------------------------------------------------------
# Sealed bundle unseal
# ---------------------------------------------------------------------------
def unseal_pat(rsa_priv) -> str:
    """Sealed bundle format (versioned, length-prefixed):
        [ 0..3 ]    magic       b"SEAL"
        [ 4..7 ]    version     uint32 LE  (=1)
        [ 8..11]    wrap_len    uint32 LE
        [12..]      wrapped_dek RSA-OAEP-SHA256(DEK)     ; DEK is 32 random bytes
        [..]        nonce_len   uint32 LE  (=12)
        [..]        nonce       12-byte AES-GCM IV
        [..]        ct_len      uint32 LE
        [..]        ciphertext  AES-256-GCM(plaintext, aad=SEAL_AAD)
    Plaintext is JSON {"pat": "<token>"}.
    """
    raw = base64.b64decode(SEALED_PAT_B64)
    if raw[:4] != b"SEAL":
        raise RuntimeError("Sealed bundle magic mismatch")
    version = struct.unpack_from("<I", raw, 4)[0]
    if version != 1:
        raise RuntimeError(f"Unsupported sealed-bundle version {version}")
    off = 8
    wl = struct.unpack_from("<I", raw, off)[0]
    off += 4
    wrapped = raw[off:off + wl]
    off += wl
    nl = struct.unpack_from("<I", raw, off)[0]
    off += 4
    nonce = raw[off:off + nl]
    off += nl
    cl = struct.unpack_from("<I", raw, off)[0]
    off += 4
    ct = raw[off:off + cl]

    dek = rsa_priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if len(dek) != 32:
        raise RuntimeError("Unwrapped DEK is not 32 bytes")
    plaintext = AESGCM(dek).decrypt(nonce, ct, SEAL_AAD)
    bundle = json.loads(plaintext)
    pat = bundle.get("pat")
    if not pat:
        raise RuntimeError("Sealed bundle has no 'pat' field")
    return pat


def main() -> int:
    try:
        log("attesting to MAA and requesting Secure Key Release...")
        maa_token = get_maa_token()
        akv_token = get_akv_token()
        rsa_priv = release_key(maa_token, akv_token)
        pat = unseal_pat(rsa_priv)
    except Exception as exc:  # fail CLOSED — never write a PAT on any failure
        log(f"FATAL: attestation-gated PAT release failed: {exc}")
        return 1

    token_path = Path(AZP_TOKEN_FILE)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    # Write with owner-only permissions on a tmpfs mount.
    fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pat.encode("utf-8"))
    finally:
        os.close(fd)
    log(f"PAT released and written to {AZP_TOKEN_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
