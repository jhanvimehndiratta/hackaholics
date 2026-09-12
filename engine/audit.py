from datetime import datetime, timezone
from collections import Counter


class AuditStore:
    def __init__(self):
        self._events = []

    def record(self, decision, findings, sent, policy="balanced"):
        event = {
            "id": f"event-{len(self._events) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
            "policy": policy,
            "findingCategories": sorted({finding["type"] for finding in findings}),
            "findingCount": len(findings),
            "sent": bool(sent),
        }
        self._events.insert(0, event)
        return event

    def list(self):
        return list(self._events)

    def export(self, export_format="json"):
        events = list(self._events)
        category_counts = Counter()
        decision_counts = Counter()
        for ev in events:
            decision_counts[ev["decision"]] += 1
            for cat in ev["findingCategories"]:
                category_counts[cat] += 1

        summary = {
            "exportDate": datetime.now(timezone.utc).isoformat(),
            "totalEvents": len(events),
            "decisions": dict(decision_counts),
            "findingCategories": dict(category_counts),
            "events": events,
        }

        if export_format == "markdown":
            lines = [
                "# Sentinel Sanitized Audit Report",
                "",
                f"- **Export Date:** {summary['exportDate']}",
                f"- **Total Events:** {summary['totalEvents']}",
                "",
                "## Decision Summary",
                "",
            ]
            if decision_counts:
                for dec, count in sorted(decision_counts.items()):
                    lines.append(f"- **{dec}:** {count}")
            else:
                lines.append("- No decisions recorded.")

            lines.extend(["", "## Finding Categories", ""])
            if category_counts:
                for cat, count in sorted(category_counts.items()):
                    lines.append(f"- **{cat}:** {count}")
            else:
                lines.append("- No findings detected.")

            lines.extend(["", "## Event Timeline", ""])
            if events:
                lines.append("| Timestamp | Decision | Policy | Categories | Sent |")
                lines.append("| --- | --- | --- | --- | --- |")
                for ev in events:
                    cats = ", ".join(ev["findingCategories"]) if ev["findingCategories"] else "none"
                    lines.append(
                        f"| {ev['timestamp']} | {ev['decision']} | {ev.get('policy', 'balanced')} | {cats} | {ev['sent']} |"
                    )
            else:
                lines.append("No events recorded.")

            return "\n".join(lines)

        return summary

    def clear(self):
        self._events.clear()

