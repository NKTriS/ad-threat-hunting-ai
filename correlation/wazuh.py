from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .models import NormalizedEvent, parse_timestamp


def _nested(data: dict[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        current: Any = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, "", [], {}):
            return current
    return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _event_uid(alert: dict[str, Any]) -> str:
    existing = alert.get("id")
    if existing:
        return str(existing)
    stable = json.dumps(alert, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha1(stable).hexdigest()[:20]


def normalize_wazuh_alert(alert: dict[str, Any]) -> NormalizedEvent:
    event_data = _nested(alert, "data.win.eventdata", default={})
    if not isinstance(event_data, dict):
        event_data = {}

    username = _nested(
        alert,
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.user",
        "data.srcuser",
    )
    source_ip = _nested(
        alert,
        "data.win.eventdata.ipAddress",
        "data.win.eventdata.sourceIp",
        "data.win.eventdata.sourceAddress",
        "data.srcip",
    )

    return NormalizedEvent(
        event_uid=_event_uid(alert),
        timestamp=parse_timestamp(
            _nested(alert, "timestamp", "data.win.system.systemTime")
        ),
        host=str(
            _nested(alert, "data.win.system.computer", "agent.name", default="unknown")
        ),
        agent_id=str(_nested(alert, "agent.id", default="unknown")),
        source_ip=str(source_ip) if source_ip else None,
        username=str(username) if username else None,
        event_id=str(
            _nested(
                alert,
                "data.win.system.eventID",
                "data.win.system.eventId",
                "data.id",
                default="unknown",
            )
        ),
        channel=str(_nested(alert, "data.win.system.channel", default="unknown")),
        provider=str(
            _nested(alert, "data.win.system.providerName", default="unknown")
        ),
        rule_id=str(_nested(alert, "rule.id", default="unknown")),
        rule_level=int(_nested(alert, "rule.level", default=0)),
        rule_description=str(_nested(alert, "rule.description", default="")),
        mitre_ids=_as_list(_nested(alert, "rule.mitre.id")),
        mitre_tactics=_as_list(_nested(alert, "rule.mitre.tactic")),
        mitre_techniques=_as_list(_nested(alert, "rule.mitre.technique")),
        command_line=_nested(
            alert,
            "data.win.eventdata.commandLine",
            "data.win.eventdata.parentCommandLine",
        ),
        process_name=_nested(
            alert,
            "data.win.eventdata.image",
            "data.win.eventdata.newProcessName",
            "data.win.eventdata.processName",
        ),
        service_name=_nested(
            alert,
            "data.win.eventdata.serviceName",
            "data.win.eventdata.targetServerName",
        ),
        ticket_encryption_type=_nested(
            alert,
            "data.win.eventdata.ticketEncryptionType",
            "data.win.eventdata.ticketEncryption",
            "data.win.eventdata.encryptionType",
        ),
        details={str(key): value for key, value in event_data.items()},
    )


def load_wazuh_alerts(path: str | Path) -> list[NormalizedEvent]:
    alerts: list[NormalizedEvent] = []
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"Expected a JSON object on line {line_number}")
            alerts.append(normalize_wazuh_alert(payload))
    return alerts


def dump_incidents(incidents: Iterable[Any], path: str | Path) -> None:
    output = [incident.to_dict() for incident in incidents]
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8"
    )
