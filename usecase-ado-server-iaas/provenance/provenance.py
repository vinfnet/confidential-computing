#!/usr/bin/env python3
"""Validate build evidence and generate deterministic JSON and HTML reports."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_sha256(value: Any, field: str) -> str:
    digest = _require_text(value, field).lower()
    if not SHA256_PATTERN.fullmatch(digest):
        raise ValueError(f"{field} must be a 64-character SHA-256 digest")
    return digest


def validate_evidence(evidence: Any) -> dict[str, Any]:
    document = _require_mapping(evidence, "evidence")
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError(f"schemaVersion must be {SCHEMA_VERSION}")

    source = _require_mapping(document.get("source"), "source")
    _require_text(source.get("repository"), "source.repository")
    _require_text(source.get("commit"), "source.commit")

    build = _require_mapping(document.get("build"), "build")
    for field in ("id", "definition", "uri", "result", "startedAt", "finishedAt"):
        _require_text(build.get(field), f"build.{field}")

    subject = _require_mapping(document.get("subject"), "subject")
    _require_text(subject.get("name"), "subject.name")
    _require_text(subject.get("uri"), "subject.uri")
    subject_digest = _require_mapping(subject.get("digest"), "subject.digest")
    if subject_digest.get("algorithm") != "sha256":
        raise ValueError("subject.digest.algorithm must be sha256")
    subject_digest["value"] = _require_sha256(
        subject_digest.get("value"), "subject.digest.value"
    )

    sbom = _require_mapping(document.get("sbom"), "sbom")
    if sbom.get("format") != "SPDX" or sbom.get("version") != "2.3":
        raise ValueError("sbom must use SPDX 2.3")
    _require_text(sbom.get("uri"), "sbom.uri")
    sbom["sha256"] = _require_sha256(sbom.get("sha256"), "sbom.sha256")

    return document


def canonical_json(evidence: Any) -> str:
    document = validate_evidence(evidence)
    return json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def evidence_sha256(evidence: Any) -> str:
    return hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()


def create_evidence(
    descriptor: Any,
    sbom_path: Path,
    sbom_uri: str,
    source: dict[str, str],
    build: dict[str, str],
) -> dict[str, Any]:
    artifact = _require_mapping(descriptor, "artifact descriptor")
    name = _require_text(artifact.get("name"), "artifact descriptor.name")
    uri = _require_text(artifact.get("uri"), "artifact descriptor.uri")
    digest = _require_sha256(
        artifact.get("sha256"), "artifact descriptor.sha256"
    )
    if not sbom_path.is_file():
        raise ValueError(f"SBOM file does not exist: {sbom_path}")

    evidence = {
        "schemaVersion": SCHEMA_VERSION,
        "source": source,
        "build": build,
        "subject": {
            "name": name,
            "uri": uri,
            "digest": {"algorithm": "sha256", "value": digest},
        },
        "sbom": {
            "format": "SPDX",
            "version": "2.3",
            "uri": _require_text(sbom_uri, "sbom URI"),
            "sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(),
        },
    }
    cce_policy_digest = artifact.get("ccePolicySha256")
    if cce_policy_digest is not None:
        evidence["subject"]["ccePolicySha256"] = _require_sha256(
            cce_policy_digest, "artifact descriptor.ccePolicySha256"
        )
    return validate_evidence(evidence)


def render_html(evidence: Any, transaction_id: str, receipt_verified: bool) -> str:
    document = validate_evidence(evidence)
    source = document["source"]
    build = document["build"]
    subject = document["subject"]
    sbom = document["sbom"]

    def escaped(value: Any) -> str:
        return html.escape(str(value), quote=True)

    status = "Verified" if receipt_verified else "Not verified"
    rows = (
        ("Repository", source["repository"]),
        ("Commit", source["commit"]),
        ("Build", f'{build["definition"]} #{build["id"]}'),
        ("Result", build["result"]),
        ("Artifact", subject["uri"]),
        ("Artifact SHA-256", subject["digest"]["value"]),
        ("SBOM", sbom["uri"]),
        ("SBOM SHA-256", sbom["sha256"]),
        ("Ledger transaction", transaction_id),
        ("Receipt", status),
    )
    table_rows = "\n".join(
        f"        <tr><th>{escaped(label)}</th><td>{escaped(value)}</td></tr>"
        for label, value in rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Build provenance report</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; color: #17202a; }}
    h1 {{ font-size: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #ccd1d1; padding: .75rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
    th {{ width: 14rem; background: #f4f6f6; }}
    .verified {{ color: #176b3a; font-weight: bold; }}
  </style>
</head>
<body>
  <main>
    <h1>Build provenance report</h1>
    <p class="verified">Ledger receipt: {escaped(status)}</p>
    <table>
{table_rows}
    </table>
    <p>Evidence SHA-256: <code>{evidence_sha256(document)}</code></p>
  </main>
</body>
</html>
"""


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--descriptor", type=Path, required=True)
    create.add_argument("--sbom", type=Path, required=True)
    create.add_argument("--sbom-uri", required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--build-id", required=True)
    create.add_argument("--build-definition", required=True)
    create.add_argument("--build-uri", required=True)
    create.add_argument("--build-result", default="succeeded")
    create.add_argument("--started-at", required=True)
    create.add_argument("--finished-at", required=True)
    create.add_argument("--output", type=Path, required=True)

    canonicalize = subparsers.add_parser("canonicalize")
    canonicalize.add_argument("--input", type=Path, required=True)
    canonicalize.add_argument("--output", type=Path, required=True)

    report = subparsers.add_parser("report")
    report.add_argument("--evidence", type=Path, required=True)
    report.add_argument("--transaction-id", required=True)
    report.add_argument("--receipt-verified", action="store_true")
    report.add_argument("--output", type=Path, required=True)

    arguments = parser.parse_args()
    if arguments.command == "create":
        content = canonical_json(
            create_evidence(
                _read_json(arguments.descriptor),
                arguments.sbom,
                arguments.sbom_uri,
                {"repository": arguments.repository, "commit": arguments.commit},
                {
                    "id": arguments.build_id,
                    "definition": arguments.build_definition,
                    "uri": arguments.build_uri,
                    "result": arguments.build_result,
                    "startedAt": arguments.started_at,
                    "finishedAt": arguments.finished_at,
                },
            )
        )
    elif arguments.command == "canonicalize":
        content = canonical_json(_read_json(arguments.input))
    else:
        content = render_html(
            _read_json(arguments.evidence),
            arguments.transaction_id,
            arguments.receipt_verified,
        )

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(content, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())