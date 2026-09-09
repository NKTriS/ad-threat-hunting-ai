from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(slots=True)
class NormalizedEvent:
    event_uid: str
    timestamp: datetime
    host: str
    agent_id: str
    source_ip: str | None
    username: str | None
    event_id: str
    channel: str
    provider: str
    rule_id: str
    rule_level: int
    rule_description: str
    mitre_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    command_line: str | None = None
    process_name: str | None = None
    service_name: str | None = None
    ticket_encryption_type: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass(slots=True)
class Incident:
    incident_id: str
    technique: str
    mitre_id: str
    severity: str
    confidence: float
    start_time: datetime
    end_time: datetime
    entities: dict[str, list[str]]
    evidence: list[NormalizedEvent]
    correlation_reason: str
    source: str = "wazuh"

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "technique": self.technique,
            "mitre_id": self.mitre_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "entities": self.entities,
            "evidence": [event.to_dict() for event in self.evidence],
            "correlation_reason": self.correlation_reason,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        evidence = [
            NormalizedEvent(
                **{
                    **item,
                    "timestamp": parse_timestamp(item.get("timestamp")),
                }
            )
            for item in data.get("evidence", [])
        ]
        return cls(
            incident_id=str(data["incident_id"]),
            technique=str(data["technique"]),
            mitre_id=str(data["mitre_id"]),
            severity=str(data["severity"]),
            confidence=float(data["confidence"]),
            start_time=parse_timestamp(data.get("start_time")),
            end_time=parse_timestamp(data.get("end_time")),
            entities=dict(data.get("entities", {})),
            evidence=evidence,
            correlation_reason=str(data.get("correlation_reason", "")),
            source=str(data.get("source", "wazuh")),
        )
