import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock


MODULE_PATH = Path(__file__).parents[1] / "ledger.py"
SPEC = importlib.util.spec_from_file_location("ledger", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)


class FakePoller:
    def __init__(self, value: dict) -> None:
        self.value = value

    def result(self) -> dict:
        return self.value


class LedgerTests(unittest.TestCase):
    def test_publish_waits_for_commit_and_verifies_receipt(self) -> None:
        client = Mock()
        client.begin_create_ledger_entry.return_value = FakePoller(
            {"transactionId": "2.15"}
        )
        receipt_result = {"receipt": {"signature": "value"}}
        client.begin_get_receipt.return_value = FakePoller(receipt_result)
        verifier = Mock()

        result = LEDGER.publish_evidence(
            client, '{"schemaVersion": "1.0"}\n', "ado-demo", "certificate", verifier
        )

        client.begin_create_ledger_entry.assert_called_once_with(
            {"contents": '{"schemaVersion": "1.0"}\n'},
            collection_id="ado-demo",
        )
        client.begin_get_receipt.assert_called_once_with("2.15")
        verifier.assert_called_once_with(
            receipt_result["receipt"],
            "certificate",
            application_claims=None,
        )
        self.assertEqual("2.15", result["transactionId"])
        self.assertTrue(result["receiptVerified"])

    def test_missing_transaction_id_fails_closed(self) -> None:
        client = Mock()
        client.begin_create_ledger_entry.return_value = FakePoller({})

        with self.assertRaisesRegex(RuntimeError, "transactionId"):
            LEDGER.publish_evidence(client, "{}", "ado-demo", "certificate", Mock())

    def test_endpoint_requires_https(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            LEDGER._ledger_id("http://example.confidential-ledger.azure.com")


if __name__ == "__main__":
    unittest.main()