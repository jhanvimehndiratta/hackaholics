import math
import re
from collections import Counter


RULES = (
    {
        "type": "database_url",
        "severity": "critical",
        "rule": "password_bearing_database_url",
        "replacement": "[REDACTED_DATABASE_URL]",
        "pattern": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:/]+:[^\s@/]+@[^\s]+", re.IGNORECASE),
    },
    {
        "type": "aws_access_key",
        "severity": "high",
        "rule": "aws_access_key_id",
        "replacement": "[REDACTED_API_KEY]",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    },
    {
        "type": "github_token",
        "severity": "high",
        "rule": "github_token_prefix",
        "replacement": "[REDACTED_API_KEY]",
        "pattern": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    },
    {
        "type": "api_key",
        "severity": "high",
        "rule": "generic_api_key_assignment",
        "replacement": "[REDACTED_API_KEY]",
        "pattern": re.compile(r"(?i)(?<=API_KEY=)[\"']?[A-Za-z0-9_\-./+=]{12,}[\"']?"),
    },
    {
        "type": "email",
        "severity": "medium",
        "rule": "email_address",
        "replacement": "[REDACTED_EMAIL]",
        "pattern": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    },
    {
        "type": "internal_ip",
        "severity": "medium",
        "rule": "rfc1918_ipv4",
        "replacement": "[REDACTED_INTERNAL_IP]",
        "pattern": re.compile(r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"),
    },
)

CONTEXT_SECRET = re.compile(
    r"(?i)\b(?:token|secret|key|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{24,})[\"']?"
)


def _entropy(value):
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _preview(value):
    if "@" in value and "://" not in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}…@{domain}"
    if "://" in value:
        scheme = value.split("://", 1)[0]
        return f"{scheme}://…"
    return f"{value[:4]}…" if len(value) > 4 else "…"


def _candidate(rule, match, start=None, end=None, value=None):
    matched = value if value is not None else match.group(0)
    return {
        "type": rule["type"],
        "severity": rule["severity"],
        "rule": rule["rule"],
        "safePreview": _preview(matched),
        "replacement": rule["replacement"],
        "range": {"start": match.start() if start is None else start, "end": match.end() if end is None else end},
    }


def _contains_range(container, candidate):
    return (
        container["range"]["start"] <= candidate["range"]["start"]
        and container["range"]["end"] >= candidate["range"]["end"]
    )


def _valid_ip(candidate, text):
    value = text[candidate["range"]["start"]:candidate["range"]["end"]]
    return all(0 <= int(part) <= 255 for part in value.split("."))


def analyze_text(text):
    candidates = []
    for rule in RULES:
        for match in rule["pattern"].finditer(text):
            candidate = _candidate(rule, match)
            if rule["type"] != "internal_ip" or _valid_ip(candidate, text):
                candidates.append(candidate)

    entropy_rule = {
        "type": "suspected_secret",
        "severity": "high",
        "rule": "named_context_high_entropy",
        "replacement": "[REDACTED_SUSPECTED_SECRET]",
    }
    for match in CONTEXT_SECRET.finditer(text):
        value = match.group(1)
        if _entropy(value) >= 3.5:
            candidates.append(
                _candidate(entropy_rule, match, match.start(1), match.end(1), value)
            )

    candidates.sort(key=lambda item: (item["range"]["start"], -(item["range"]["end"] - item["range"]["start"])))
    selected = []
    for candidate in candidates:
        duplicate = next(
            (
                existing
                for existing in selected
                if existing["range"] == candidate["range"]
            ),
            None,
        )
        if duplicate:
            continue
        selected.append(candidate)

    selected.sort(key=lambda item: item["range"]["start"])
    findings = []
    for index, finding in enumerate(selected, 1):
        findings.append({"id": f"finding-{index}", **finding})

    return {
        "decision": "review_required" if findings else "allow",
        "findings": findings,
    }
