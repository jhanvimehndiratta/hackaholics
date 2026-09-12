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
            "internal host 192.168.1.42 "
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
            }.issubset(types)
        )
        for finding in result["findings"]:
            self.assertIn("rule", finding)
            self.assertIn("severity", finding)
            self.assertIn("safePreview", finding)
            self.assertIn("replacement", finding)
            self.assertNotIn("hunter2", finding["safePreview"])

    def test_policy_modes_and_high_entropy_detection(self):
        text = "token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u"

        balanced_result = analyze_text(text, policy="balanced")
        self.assertEqual(balanced_result["decision"], "allow")
        self.assertEqual(balanced_result["findings"], [])

        strict_result = analyze_text(text, policy="strict")
        self.assertEqual(strict_result["decision"], "review_required")
        self.assertEqual(len(strict_result["findings"]), 1)
        self.assertEqual(strict_result["findings"][0]["type"], "suspected_secret")
        self.assertEqual(strict_result["findings"][0]["rule"], "named_context_high_entropy")

    def test_rejects_unknown_policy_mode(self):
        with self.assertRaises(ValueError):
            analyze_text("hello world", policy="invalid_policy")
        with self.assertRaises(ValueError):
            redact_text("hello world", [], policy="invalid_policy")

    def test_detects_valid_rfc1918_private_ipv4_addresses(self):
        samples = ("10.24.3.8", "172.20.4.9", "192.168.1.42")

        for address in samples:
            with self.subTest(address=address):
                findings = analyze_text(f"Internal host: {address}")["findings"]
                self.assertEqual([finding["type"] for finding in findings], ["internal_ip"])

    def test_detects_rfc1918_boundary_addresses(self):
        addresses = (
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255",
        )

        for address in addresses:
            with self.subTest(address=address):
                self.assertIn(
                    "internal_ip",
                    {finding["type"] for finding in analyze_text(address)["findings"]},
                )

    def test_does_not_flag_public_or_non_rfc1918_ipv4(self):
        addresses = (
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.2.1",
            "127.0.0.1",
            "169.254.1.2",
        )

        for address in addresses:
            with self.subTest(address=address):
                self.assertNotIn(
                    "internal_ip",
                    {finding["type"] for finding in analyze_text(address)["findings"]},
                )

    def test_does_not_flag_invalid_or_incomplete_ipv4(self):
        addresses = ("192.168.999.4", "10.1.2.256", "192.168.1")

        for address in addresses:
            with self.subTest(address=address):
                self.assertNotIn(
                    "internal_ip",
                    {finding["type"] for finding in analyze_text(address)["findings"]},
                )

    def test_private_ip_preview_masks_host_portion(self):
        samples = {
            "10.24.3.8": "10.x.x.x",
            "172.20.4.9": "172.20.x.x",
            "192.168.1.42": "192.168.x.x",
        }

        for address, expected_preview in samples.items():
            with self.subTest(address=address):
                finding = analyze_text(address)["findings"][0]
                self.assertEqual(finding["safePreview"], expected_preview)

    def test_private_ip_detection_excludes_adjacent_punctuation(self):
        for suffix in (".", ",", ")", "]", ";"):
            with self.subTest(suffix=suffix):
                text = f"Host (192.168.1.42{suffix}"
                finding = analyze_text(text)["findings"][0]
                matched = text[finding["range"]["start"]:finding["range"]["end"]]
                self.assertEqual(matched, "192.168.1.42")

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

    def test_access_key_previews_show_exactly_first_three_characters(self):
        samples = {
            "aws_access_key": (
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                "AKI…",
            ),
            "github_token": (
                "github_pat_11AA0abcdefghijklmnopqrstuv",
                "git…",
            ),
            "api_key": (
                "API_KEY=sk_live_example_123456",
                "sk_…",
            ),
        }

        for finding_type, (text, expected_preview) in samples.items():
            with self.subTest(finding_type=finding_type):
                finding = next(
                    item
                    for item in analyze_text(text)["findings"]
                    if item["type"] == finding_type
                )
                self.assertEqual(finding["safePreview"], expected_preview)
                self.assertEqual(finding["replacement"], "[REDACTED_API_KEY]")

    def test_benign_long_identifier_is_not_a_secret_without_context(self):
        result = analyze_text("Build artifact 550e8400e29b41d4a716446655440000 is ready")
        self.assertEqual(result["decision"], "allow")

    def test_detects_password_values_in_common_configuration_syntaxes(self):
        samples = (
            "password=hunter2",
            "passwd: Summer2026!",
            'pwd = "correct horse battery staple"',
            "DB_PASSWORD='production-pass'",
            '{"password": "MyS3cret!"}',
            "passphrase: three quiet lunar rivers",
        )

        for text in samples:
            with self.subTest(text=text):
                findings = analyze_text(text)["findings"]
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["type"], "password")
                self.assertEqual(findings[0]["rule"], "named_password_assignment")
                self.assertEqual(findings[0]["replacement"], "[REDACTED_PASSWORD]")

    def test_password_preview_never_exposes_password_value(self):
        password = "UniqueSecret!92"
        finding = analyze_text(f"password={password}")["findings"][0]

        self.assertEqual(finding["safePreview"], f"•••••••• ({len(password)} characters)")
        self.assertNotIn(password, finding["safePreview"])

    def test_password_rule_ignores_prose_and_empty_assignments(self):
        safe_samples = (
            "Update the password policy before release.",
            "The password should be rotated every 90 days.",
            "password=",
            'password: ""',
        )

        for text in safe_samples:
            with self.subTest(text=text):
                self.assertNotIn(
                    "password",
                    {finding["type"] for finding in analyze_text(text)["findings"]},
                )


class RedactionTests(unittest.TestCase):
    def test_access_key_redaction_replaces_entire_value(self):
        samples = (
            (
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                "AWS_ACCESS_KEY_ID=[REDACTED_API_KEY]",
                "aws_access_key",
            ),
            (
                "token=github_pat_11AA0abcdefghijklmnopqrstuv",
                "token=[REDACTED_API_KEY]",
                "github_token",
            ),
            (
                "API_KEY=sk_live_example_123456",
                "API_KEY=[REDACTED_API_KEY]",
                "api_key",
            ),
        )

        for text, expected, finding_type in samples:
            with self.subTest(finding_type=finding_type):
                analysis = analyze_text(text)
                finding = next(
                    item for item in analysis["findings"] if item["type"] == finding_type
                )
                result = redact_text(text, [finding["id"]])
                self.assertEqual(result["redactedText"], expected)

    def test_redacts_password_value_without_removing_field_name(self):
        text = 'DB_PASSWORD="Summer 2026!"; deploy=true'
        analysis = analyze_text(text)
        password_id = next(
            finding["id"]
            for finding in analysis["findings"]
            if finding["type"] == "password"
        )

        result = redact_text(text, [password_id])

        self.assertEqual(
            result["redactedText"],
            "DB_PASSWORD=\"[REDACTED_PASSWORD]\"; deploy=true",
        )

    def test_private_ip_redaction_replaces_address_and_preserves_punctuation(self):
        text = "Route via 192.168.1.42, then continue."
        finding = analyze_text(text)["findings"][0]

        result = redact_text(text, [finding["id"]])

        self.assertEqual(
            result["redactedText"],
            "Route via [REDACTED_INTERNAL_IP], then continue.",
        )

    def test_database_url_suppresses_nested_private_ip_finding(self):
        text = "Connect to postgres://service:hunter2@10.24.3.8/prod now."
        findings = analyze_text(text)["findings"]

        self.assertEqual([finding["type"] for finding in findings], ["database_url"])

    def test_recognized_access_key_suppresses_generic_secret_finding(self):
        text = "token=github_pat_11AA0abcdefghijklmnopqrstuv"
        findings = analyze_text(text)["findings"]

        self.assertEqual([finding["type"] for finding in findings], ["github_token"])

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

    def test_redacting_all_findings_cannot_corrupt_ranges(self):
        text = (
            "Connect to postgres://service:hunter2@10.24.3.8/prod with "
            "API_KEY=AKIAIOSFODNN7EXAMPLE."
        )
        analysis = analyze_text(text)
        result = redact_text(text, [finding["id"] for finding in analysis["findings"]])

        self.assertEqual(
            result["redactedText"],
            "Connect to [REDACTED_DATABASE_URL] with API_KEY=[REDACTED_API_KEY].",
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
        store.record("allow_once", analysis["findings"], sent=True, policy="balanced")
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

    def test_audit_export_json_and_markdown(self):
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        store = AuditStore()
        analysis = analyze_text(f"AWS_ACCESS_KEY_ID={raw_secret}", policy="strict")
        store.record("redact_send", analysis["findings"], sent=True, policy="strict")
        store.record("block", analysis["findings"], sent=False, policy="strict")

        json_export = store.export(export_format="json")
        self.assertEqual(json_export["totalEvents"], 2)
        self.assertEqual(json_export["decisions"], {"redact_send": 1, "block": 1})
        self.assertEqual(json_export["findingCategories"], {"aws_access_key": 2})
        self.assertNotIn(raw_secret, json.dumps(json_export))

        md_export = store.export(export_format="markdown")
        self.assertIn("# Sentinel Sanitized Audit Report", md_export)
        self.assertIn("- **redact_send:** 1", md_export)
        self.assertIn("- **aws_access_key:** 2", md_export)
        self.assertIn("| strict |", md_export)
        self.assertNotIn(raw_secret, md_export)



class BrowserFixtureTests(unittest.TestCase):
    def test_python_reference_builds_synthetic_browser_fixture(self):
        from engine.tests.generate_browser_fixtures import build_fixture

        fixture = build_fixture()
        case_names = {case["name"] for case in fixture["cases"]}
        self.assertTrue({"safe", "all-findings", "strict-entropy", "overlap"} <= case_names)
        serialized = json.dumps(fixture)
        self.assertNotIn("realSecret", serialized)
        self.assertIn("<timestamp>", serialized)


if __name__ == "__main__":
    unittest.main()
