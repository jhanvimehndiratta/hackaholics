from .detectors import analyze_text


def redact_text(text, finding_ids):
    analysis = analyze_text(text)
    findings_by_id = {finding["id"]: finding for finding in analysis["findings"]}
    unknown = set(finding_ids) - set(findings_by_id)
    if unknown:
        raise ValueError(f"Unknown finding IDs: {', '.join(sorted(unknown))}")

    selected = [findings_by_id[finding_id] for finding_id in finding_ids]
    selected.sort(
        key=lambda item: (
            item["range"]["start"],
            -(item["range"]["end"] - item["range"]["start"]),
        )
    )
    outermost = []
    for finding in selected:
        contained = next(
            (
                existing
                for existing in outermost
                if existing["range"]["start"] <= finding["range"]["start"]
                and existing["range"]["end"] >= finding["range"]["end"]
            ),
            None,
        )
        if not contained:
            outermost.append(finding)

    redacted = text
    for finding in reversed(outermost):
        start = finding["range"]["start"]
        end = finding["range"]["end"]
        redacted = redacted[:start] + finding["replacement"] + redacted[end:]

    return {
        "redactedText": redacted,
        "redactedFindingIds": sorted(finding_ids, key=lambda item: int(item.split("-")[1])),
    }
