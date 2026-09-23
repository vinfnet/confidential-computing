#!/usr/bin/env python3
"""Append canonical build evidence to Azure Confidential Ledger and verify its receipt."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlparse


class Poller(Protocol):
    def result(self) -> dict[str, Any]: ...


class LedgerClient(Protocol):
    def begin_create_ledger_entry(
        self, entry: dict[str, str], *, collection_id: str
    ) -> Poller: ...

    def begin_get_receipt(self, transaction_id: str) -> Poller: ...


def publish_evidence(
    client: LedgerClient,
    evidence_text: str,
    collection_id: str,
    service_certificate: str,
    receipt_verifier: Callable[..., None],
) -> dict[str, Any]:
    if not evidence_text.strip():
        raise ValueError("evidence must not be empty")
    if not collection_id.strip():
        raise ValueError("collection_id must not be empty")

    append_result = client.begin_create_ledger_entry(
        {"contents": evidence_text}, collection_id=collection_id
    ).result()
    transaction_id = append_result.get("transactionId")
    if not isinstance(transaction_id, str) or not transaction_id:
        raise RuntimeError("ledger append did not return a transactionId")

    receipt_result = client.begin_get_receipt(transaction_id).result()
    receipt = receipt_result.get("receipt")
    if not isinstance(receipt, dict):
        raise RuntimeError("ledger did not return a receipt")

    application_claims = receipt_result.get("applicationClaims")
    receipt_verifier(
        receipt,
        service_certificate,
        application_claims=application_claims,
    )
    return {
        "collectionId": collection_id,
        "transactionId": transaction_id,
        "receiptVerified": True,
        "receipt": receipt_result,
    }


def _ledger_id(endpoint: str) -> str:
    host = urlparse(endpoint).hostname
    if not host or "." not in host:
        raise ValueError("endpoint must be an HTTPS Azure Confidential Ledger URL")
    if urlparse(endpoint).scheme != "https":
        raise ValueError("endpoint must use HTTPS")
    return host.split(".", maxsplit=1)[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--managed-identity-client-id")
    arguments = parser.parse_args()

    from azure.confidentialledger import ConfidentialLedgerClient
    from azure.confidentialledger.certificate import ConfidentialLedgerCertificateClient
    from azure.confidentialledger.receipt import verify_receipt
    from azure.identity import DefaultAzureCredential

    ledger_id = _ledger_id(arguments.endpoint)
    identity_client = ConfidentialLedgerCertificateClient()
    network_identity = identity_client.get_ledger_identity(ledger_id=ledger_id)
    service_certificate = network_identity["ledgerTlsCertificate"]
    credential = DefaultAzureCredential(
        managed_identity_client_id=arguments.managed_identity_client_id
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        certificate_path = Path(temporary_directory) / f"{ledger_id}.pem"
        certificate_path.write_text(service_certificate, encoding="utf-8")
        with ConfidentialLedgerClient(
            endpoint=arguments.endpoint,
            credential=credential,
            ledger_certificate_path=certificate_path,
        ) as client:
            result = publish_evidence(
                client,
                arguments.evidence.read_text(encoding="utf-8"),
                arguments.collection_id,
                service_certificate,
                verify_receipt,
            )

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(result["transactionId"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())