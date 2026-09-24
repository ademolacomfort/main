"""Tests for bounded C2PA manifest parser."""

from __future__ import annotations

import unittest
from devx.c2pa_parser import (
    parse_c2pa_manifest,
    MAX_C2PA_PAYLOAD_BYTES,
    MAX_ASSERTIONS_COUNT,
    STATUS_VALID,
    STATUS_MALFORMED,
    STATUS_OVERSIZED,
    STATUS_UNSUPPORTED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    ERR_OVERSIZED,
    ERR_MALFORMED,
    ERR_UNSUPPORTED_VERSION,
    ERR_EXPIRED,
    ERR_REVOKED,
)


class TestC2PAParser(unittest.TestCase):
    def test_valid_manifest_with_harpocrates_metadata(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "title": "Valid Sample",
            "assertions": [
                {
                    "label": "harpocrates.metadata",
                    "data": {
                        "protocol": "harpocrates",
                        "version": 1,
                        "tier": "silent",
                        "sourceHash": "a" * 64,
                        "proofId": "b" * 64,
                        "timestamp": "2026-01-01T00:00:00Z",
                    },
                }
            ],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertTrue(res.ok)
        self.assertEqual(res.status, STATUS_VALID)
        self.assertIsNotNone(res.canonical_metadata)
        self.assertEqual(res.canonical_metadata["protocol"], "harpocrates")
        self.assertEqual(res.canonical_metadata["tier"], "silent")

    def test_malformed_json_bytes(self) -> None:
        res = parse_c2pa_manifest(b"{bad_json: true")
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_MALFORMED)
        self.assertEqual(res.error_code, ERR_MALFORMED)

    def test_oversized_payload_bytes(self) -> None:
        huge_bytes = b"x" * (MAX_C2PA_PAYLOAD_BYTES + 1)
        res = parse_c2pa_manifest(huge_bytes)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)
        self.assertEqual(res.error_code, ERR_OVERSIZED)

    def test_exceeds_assertions_bound(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "assertions": [{"label": f"a{i}"} for i in range(MAX_ASSERTIONS_COUNT + 1)],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)
        self.assertEqual(res.error_code, ERR_OVERSIZED)

    def test_deeply_nested_structure(self) -> None:
        nested: dict = {"level": 0}
        curr = nested
        for i in range(12):
            curr["child"] = {}
            curr = curr["child"]
        res = parse_c2pa_manifest(nested)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_OVERSIZED)

    def test_unsupported_version(self) -> None:
        payload = {
            "specVersion": "c2pa-v999-future",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_UNSUPPORTED)
        self.assertEqual(res.error_code, ERR_UNSUPPORTED_VERSION)

    def test_expired_claim(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "status": "expired",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_EXPIRED)
        self.assertEqual(res.error_code, ERR_EXPIRED)

    def test_revoked_claim(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "status": "revoked",
            "assertions": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertFalse(res.ok)
        self.assertEqual(res.status, STATUS_REVOKED)
        self.assertEqual(res.error_code, ERR_REVOKED)

    def test_redaction_of_sensitive_keys(self) -> None:
        payload = {
            "specVersion": "c2pa-v1",
            "secret_key": "topsecretvalue",
            "privateKey": "-----BEGIN RSA PRIVATE KEY-----",
            "assertions": [],
            "ingredients": [],
        }
        res = parse_c2pa_manifest(payload)
        self.assertTrue(res.ok)
        serialized = str(res.to_dict())
        self.assertNotIn("topsecretvalue", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)


if __name__ == "__main__":
    unittest.main()
