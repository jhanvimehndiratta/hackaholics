import json
import unittest

from engine.audit import AuditStore
from engine.detectors import analyze_text
from engine.redact import redact_text


class DetectorTests(unittest.TestCase):
    def test_detects_every_required_finding_class(self):
        text = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
            "github_pat_11AA0abcdefghijklmnopqrstuv "
            "API_KEY=sk_live_example_123456 "
            "postgres://service:hunter2@10.24.3.8/prod "
            "owner@example.com "
            "token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u"
        )

        result = analyze_text(text)
        types = {finding["type"] for finding in result["findings"]}

        self.assertEqual(result["decision"], "review_required")
        self.assertTrue(
            {
                "aws_access_key",
                "github_token",
                "api_key",
                "database_url",
                "email",
                "internal_ip",
                "suspected_secret",
            }.issubset(types)
        )
        for finding in result["findings"]:
            self.assertIn("rule", finding)
            self.assertIn("severity", finding)
            self.assertIn("safePreview", finding)
            self.assertIn("replacement", finding)
            self.assertNotIn("hunter2", finding["safePreview"])

    def test_public_ip_is_not_flagged(self):
        result = analyze_text("Resolver is 8.8.8.8")
        self.assertNotIn("internal_ip", {f["type"] for f in result["findings"]})

    def test_safe_prompt_is_allowed(self):
        result = analyze_text("How should I structure retries in a small Python service?")
        self.assertEqual(result, {"decision": "allow", "findings": []})

    def test_api_key_and_email_are_explainable(self):
        result = analyze_text(
            "Deploy with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and email me@example.com"
        )
        by_type = {finding["type"]: finding for finding in result["findings"]}
        self.assertEqual(by_type["aws_access_key"]["rule"], "aws_access_key_id")
        self.assertEqual(by_type["email"]["replacement"], "[REDACTED_EMAIL]")

    def test_benign_long_identifier_is_not_a_secret_without_context(self):
        result = analyze_text("Build artifact 550e8400e29b41d4a716446655440000 is ready")
        self.assertEqual(result["decision"], "allow")


class RedactionTests(unittest.TestCase):
    def test_redacts_selected_ranges_and_preserves_surrounding_text(self):
        text = "Contact dev@example.com from 192.168.1.42 before release."
        analysis = analyze_text(text)
        result = redact_text(text, [f["id"] for f in analysis["findings"]])
        self.assertEqual(
            result["redactedText"],
            "Contact [REDACTED_EMAIL] from [REDACTED_INTERNAL_IP] before release.",
        )

    def test_rejects_unknown_finding_id(self):
        with self.assertRaises(ValueError):
            redact_text("hello", ["finding-999"])

    def test_overlapping_matches_do_not_corrupt_redaction(self):
        text = "API_KEY=AKIAIOSFODNN7EXAMPLE"
        analysis = analyze_text(text)
        result = redact_text(text, [f["id"] for f in analysis["findings"]])
        self.assertEqual(result["redactedText"], "API_KEY=[REDACTED_API_KEY]")

    def test_redacting_all_overlapping_findings_uses_outer_replacement(self):
        text = "Connect to postgres://service:hunter2@10.24.3.8/prod now."
        analysis = analyze_text(text)
        result = redact_text(text, [f["id"] for f in analysis["findings"]])
        self.assertEqual(
            result["redactedText"],
            "Connect to [REDACTED_DATABASE_URL] now.",
        )
        self.assertEqual(
            set(result["redactedFindingIds"]),
            {finding["id"] for finding in analysis["findings"]},
        )


class AuditTests(unittest.TestCase):
    def test_audit_never_stores_raw_secret(self):
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        store = AuditStore()
        analysis = analyze_text(f"AWS_ACCESS_KEY_ID={raw_secret}")
        store.record("allow_once", analysis["findings"], sent=True)
        serialized = json.dumps(store.list())
        self.assertNotIn(raw_secret, serialized)
        self.assertIn("aws_access_key", serialized)

    def test_allow_once_has_no_persistent_bypass(self):
        prompt = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        store = AuditStore()
        first = analyze_text(prompt)
        store.record("allow_once", first["findings"], sent=True)
        second = analyze_text(prompt)
        self.assertEqual(second["decision"], "review_required")


if __name__ == "__main__":
    unittest.main()
