import json
import sys
from pathlib import Path

from engine.audit import AuditStore
from engine.detectors import analyze_text
from engine.redact import redact_text

CASE_SPECS = (
    {"name": "safe", "text": "How should I structure retries in a small Python service?", "policy": "balanced"},
    {"name": "all-findings", "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE github_pat_11AA0abcdefghijklmnopqrstuv API_KEY=sk_live_example_123456 postgres://service:hunter2@10.24.3.8/prod internal 192.168.1.42 owner@example.com", "policy": "balanced"},
    {"name": "strict-entropy", "text": "token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u", "policy": "strict"},
    {"name": "balanced-entropy", "text": "token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u", "policy": "balanced"},
    {"name": "password-json", "text": '{"password": "MyS3cret!"}', "policy": "balanced"},
    {"name": "private-boundaries", "text": "10.0.0.0 172.31.255.255 192.168.255.255 8.8.8.8", "policy": "balanced"},
    {"name": "overlap", "text": "API_KEY=AKIAIOSFODNN7EXAMPLE.", "policy": "balanced"},
    {"name": "database-overlap", "text": "Connect postgres://service:hunter2@10.24.3.8/prod now.", "policy": "balanced"},
)


def _normalize_timestamps(value):
    if isinstance(value, dict):
        return {key: ("<timestamp>" if key in {"timestamp", "exportDate"} else _normalize_timestamps(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_timestamps(item) for item in value]
    return value


def build_fixture():
    cases = []
    for spec in CASE_SPECS:
        analysis = analyze_text(spec["text"], policy=spec["policy"])
        ids = [finding["id"] for finding in analysis["findings"]]
        cases.append({
            **spec,
            "analysis": analysis,
            "redactions": {"all": redact_text(spec["text"], ids, policy=spec["policy"])},
        })

    store = AuditStore()
    findings = analyze_text(CASE_SPECS[1]["text"], policy="strict")["findings"]
    store.record("redact_send", findings, True, "strict")
    store.record("block", findings, False, "strict")
    audit_json = _normalize_timestamps(store.export("json"))
    audit_markdown = store.export("markdown")
    for event in store.list():
        audit_markdown = audit_markdown.replace(event["timestamp"], "<timestamp>")
    audit_markdown = audit_markdown.replace(audit_json["exportDate"], "<timestamp>") if audit_json["exportDate"] != "<timestamp>" else audit_markdown
    # Export date is independently generated; normalize its line directly.
    lines = audit_markdown.splitlines()
    lines = ["- **Export Date:** <timestamp>" if line.startswith("- **Export Date:**") else line for line in lines]
    return {"schemaVersion": 1, "cases": cases, "audit": {"json": audit_json, "markdown": "\n".join(lines)}}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_browser_fixtures.py OUTPUT.json")
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_fixture(), indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
