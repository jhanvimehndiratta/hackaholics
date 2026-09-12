from datetime import datetime, timezone


class AuditStore:
    def __init__(self):
        self._events = []

    def record(self, decision, findings, sent):
        event = {
            "id": f"event-{len(self._events) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
            "findingCategories": sorted({finding["type"] for finding in findings}),
            "findingCount": len(findings),
            "sent": bool(sent),
        }
        self._events.insert(0, event)
        return event

    def list(self):
        return list(self._events)

    def clear(self):
        self._events.clear()
