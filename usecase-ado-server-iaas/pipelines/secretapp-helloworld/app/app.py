"""
SecretApp — runtime web UI for an ACI Confidential Container group locked down
with a CCE policy from `az confcom acipolicygen` and an encrypted "sealed" data
bundle that is ONLY unwrapped after Secure Key Release (SKR) succeeds inside the
TEE.

The container has no interactive access:
  * the CCE policy has no exec_processes entries, so `az container exec` is
    rejected by the ACI control plane; the image runs as a non-root user;
  * the only writable surface is an in-memory tmpfs at /run/sealed where the
    entrypoint wrote the decrypted welcome secret + a manifest proving SKR ran.

Routes:
  * GET  /            — attestation page (Jinja template, no JS deps).
  * POST /api/attest  — fetch a fresh SEV-SNP report, post to MAA, return claims.
  * GET  /api/sealed  — JSON view of the unsealed metadata + welcome secret.
  * GET  /healthz     — liveness probe (returns 200 OK only).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request


GET_SNP_REPORT = os.environ.get("GET_SNP_REPORT", "/usr/local/bin/get-snp-report")
MAA_ENDPOINT   = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
MAA_API        = os.environ.get("MAA_API_VERSION", "2022-08-01")
SEALED_DIR     = Path(os.environ.get("SEALED_DIR", "/run/sealed"))
PORT           = int(os.environ.get("PORT", "8080"))
APP_NAME       = "secretapp"
APP_VERSION    = "1.0.0"

REPORT_LEN = 0x4A0  # AMD SEV-SNP ATTESTATION_REPORT size

CLAIM_EXPLANATIONS = {
    "iss": "Issuer URL of the MAA endpoint that signed this token.",
    "iat": "Issued At (Unix epoch seconds).",
    "exp": "Expiration (Unix epoch seconds).",
    "x-ms-attestation-type": "TEE type ('sevsnpvm' on ACI Confidential).",
    "x-ms-compliance-status": "MAA verdict ('azure-compliant-uvm' on success).",
    "x-ms-sevsnpvm-hostdata": "Host data injected at launch — on ACI CC this is the SHA-256 of the CCE policy. Pinned in the SKR release policy.",
    "x-ms-sevsnpvm-is-debuggable": "Must be false for production CVMs.",
    "x-ms-sevsnpvm-launchmeasurement": "SHA-384 of the initial guest memory contents — the cryptographic identity of the boot image.",
}


def _explain(key: str) -> str:
    if key in CLAIM_EXPLANATIONS:
        return CLAIM_EXPLANATIONS[key]
    if key.startswith("x-ms-sevsnpvm-"):
        return "SEV-SNP attestation report field surfaced by MAA."
    if key.startswith("x-ms-"):
        return "MAA-issued claim."
    return "Standard JWT or caller-supplied claim."


# ---------------------------------------------------------------------------
# JWT + attestation helpers
# ---------------------------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Token does not have 3 segments (got {len(parts)})")
    return json.loads(_b64url_decode(parts[0])), json.loads(_b64url_decode(parts[1]))


def annotate_claims(payload: dict):
    rows = []
    for key, value in payload.items():
        rows.append({"key": key, "value": value, "explanation": _explain(key)})
    rows.sort(key=lambda r: (not r["key"].startswith("x-ms-"), r["key"]))
    return rows


def _find_security_context_dir():
    explicit = os.environ.get("UVM_SECURITY_CONTEXT_DIR")
    if explicit and os.path.isdir(explicit):
        return explicit
    try:
        for entry in os.listdir("/"):
            if entry.startswith("security-context-") and os.path.isdir(os.path.join("/", entry)):
                return os.path.join("/", entry)
    except OSError:
        pass
    return None


def load_uvm_information() -> dict:
    ctx_dir = _find_security_context_dir()
    if ctx_dir:
        def _read(name):
            p = Path(ctx_dir) / name
            return p.read_text().strip() if p.exists() else ""
        return {"host_amd_cert_b64": _read("host-amd-cert-base64"),
                "reference_info_b64": _read("reference-info-base64"), "source": ctx_dir}
    return {"host_amd_cert_b64": "", "reference_info_b64": "", "source": "none"}


def fetch_snp_report(report_data: bytes) -> bytes:
    proc = subprocess.run([GET_SNP_REPORT, report_data.hex()],
                          capture_output=True, timeout=15, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"get-snp-report exited {proc.returncode}: "
                           f"{proc.stderr.decode('utf-8', 'replace')[:400]}")
    hex_output = "".join(c for c in proc.stdout.decode("ascii", "replace") if c in "0123456789abcdefABCDEF")
    report = bytes.fromhex(hex_output)
    if len(report) < REPORT_LEN:
        raise RuntimeError(f"SNP report too short: {len(report)} bytes")
    return report[:REPORT_LEN]


def perform_attestation(user_nonce=None) -> dict:
    nonce = user_nonce or secrets.token_hex(16)
    runtime_obj = {"nonce": nonce, "client": APP_NAME, "version": APP_VERSION}
    runtime_bytes = json.dumps(runtime_obj).encode("utf-8")
    report_data = hashlib.sha256(runtime_bytes).digest() + b"\x00" * 32

    snp_report = fetch_snp_report(report_data)
    uvm = load_uvm_information()
    if not uvm["host_amd_cert_b64"]:
        raise RuntimeError("UVM host AMD certificate not found — not running on ACI Confidential SKU.")
    thim_certs = json.loads(base64.b64decode(uvm["host_amd_cert_b64"]))
    vcek_chain = (thim_certs.get("vcekCert", "") + thim_certs.get("certificateChain", "")).encode("utf-8")

    inner = {"SnpReport": _b64url(snp_report), "VcekCertChain": _b64url(vcek_chain)}
    if uvm["reference_info_b64"]:
        ref_info = base64.b64decode(uvm["reference_info_b64"])
        inner["Endorsements"] = _b64url(json.dumps({"Uvm": [_b64url(ref_info)]}).encode("utf-8"))

    body = {"report": _b64url(json.dumps(inner).encode("utf-8")),
            "runtimeData": {"data": _b64url(runtime_bytes), "dataType": "JSON"}}
    url = f"https://{MAA_ENDPOINT}/attest/SevSnpVm?api-version={MAA_API}"
    resp = requests.post(url, json=body, timeout=30, headers={"User-Agent": APP_NAME})
    if resp.status_code != 200:
        raise RuntimeError(f"MAA POST {url} returned HTTP {resp.status_code}: {resp.text[:400]}")
    token = resp.json().get("token")
    if not token:
        raise RuntimeError(f"MAA response missing 'token': {resp.text[:400]}")

    header, payload = decode_jwt(token)
    return {"endpoint": f"https://{MAA_ENDPOINT}", "nonce": nonce, "token": token,
            "header": header, "payload": payload, "claims": annotate_claims(payload)}


# ---------------------------------------------------------------------------
# Sealed bundle status — the entrypoint writes /run/sealed/* after SKR succeeds.
# ---------------------------------------------------------------------------
def sealed_status() -> dict:
    manifest = SEALED_DIR / "manifest.json"
    if not manifest.is_file():
        return {"unsealed": False,
                "reason": "Sealed manifest not found. SKR may have failed, or the image "
                          "was started outside of an ACI Confidential container group."}
    info = json.loads(manifest.read_text())
    welcome_path = SEALED_DIR / "welcome.txt"
    welcome_secret = welcome_path.read_text().strip() if welcome_path.is_file() else None
    files = []
    for p in sorted(SEALED_DIR.iterdir()):
        if p.is_file() and p.name != "manifest.json":
            files.append({"name": p.name, "size": p.stat().st_size,
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    return {"unsealed": True, "welcome_secret": welcome_secret,
            "sealed_at": info.get("sealed_at"), "unsealed_at": info.get("unsealed_at"),
            "akv_endpoint": info.get("akv_endpoint"), "key_name": info.get("key_name"),
            "key_version": info.get("key_version"),
            "release_policy_sha256": info.get("release_policy_sha256"),
            "wrap_algorithm": info.get("wrap_algorithm"),
            "ciphertext_sha256": info.get("ciphertext_sha256"),
            "plaintext_sha256": info.get("plaintext_sha256"), "files": files}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return "OK", 200


@app.get("/")
def index():
    return render_template("index.html", sealed=sealed_status(),
                           maa_endpoint=MAA_ENDPOINT, app_version=APP_VERSION,
                           now=datetime.now(timezone.utc).isoformat())


@app.get("/api/sealed")
def api_sealed():
    return jsonify(sealed_status())


@app.post("/api/attest")
def api_attest():
    nonce = (request.json or {}).get("nonce") if request.is_json else None
    try:
        return jsonify({"ok": True, "attestation": perform_attestation(nonce)})
    except Exception as exc:  # surfaced to the UI panel
        return jsonify({"ok": False, "error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
