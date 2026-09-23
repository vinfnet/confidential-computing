import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "provenance.py"
SPEC = importlib.util.spec_from_file_location("provenance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


def valid_evidence() -> dict:
    return {
        "schemaVersion": "1.0",
        "source": {"repository": "demo", "commit": "abc123"},
        "build": {
            "id": "42",
            "definition": "hello-world",
            "uri": "https://ado.example/build/42",
            "result": "succeeded",
            "startedAt": "2026-09-23T00:00:00Z",
            "finishedAt": "2026-09-23T00:01:00Z",
        },
        "subject": {
            "name": "hello-world",
            "uri": "registry.example/hello-world@sha256:" + "a" * 64,
            "digest": {"algorithm": "sha256", "value": "a" * 64},
        },
        "sbom": {
            "format": "SPDX",
            "version": "2.3",
            "uri": "https://storage.example/sbom.spdx.json",
            "sha256": "b" * 64,
        },
    }


class ProvenanceTests(unittest.TestCase):
    def test_canonical_hash_is_independent_of_key_order(self) -> None:
        evidence = valid_evidence()
        reordered = {key: evidence[key] for key in reversed(evidence)}
        self.assertEqual(
            PROVENANCE.evidence_sha256(evidence),
            PROVENANCE.evidence_sha256(reordered),
        )

    def test_rejects_invalid_artifact_digest(self) -> None:
        evidence = copy.deepcopy(valid_evidence())
        evidence["subject"]["digest"]["value"] = "latest"
        with self.assertRaisesRegex(ValueError, "64-character SHA-256"):
            PROVENANCE.validate_evidence(evidence)

    def test_html_escapes_untrusted_values(self) -> None:
        evidence = valid_evidence()
        evidence["source"]["repository"] = "<script>alert(1)</script>"
        report = PROVENANCE.render_html(evidence, "2.15", True)
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("Ledger receipt: Verified", report)

    def test_create_evidence_hashes_sbom_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sbom = Path(directory) / "sbom.spdx.json"
            sbom.write_bytes(b'{"spdxVersion":"SPDX-2.3"}\n')
            evidence = PROVENANCE.create_evidence(
                {"name": "demo", "uri": "registry/demo@sha256:" + "a" * 64, "sha256": "a" * 64},
                sbom,
                "https://ado.example/artifacts/sbom.spdx.json",
                {"repository": "demo", "commit": "abc123"},
                valid_evidence()["build"],
            )

        self.assertEqual(
            hashlib.sha256(b'{"spdxVersion":"SPDX-2.3"}\n').hexdigest(),
            evidence["sbom"]["sha256"],
        )


if __name__ == "__main__":
    unittest.main()