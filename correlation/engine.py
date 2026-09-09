from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from .models import Incident, NormalizedEvent


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    window_seconds: int = 300
    password_spray_min_events: int = 5
    password_spray_min_users: int = 5


def _bucket(timestamp: datetime, window_seconds: int) -> int:
    return int(timestamp.timestamp()) // window_seconds


def _incident_id(mitre_id: str, events: list[NormalizedEvent]) -> str:
    identity = mitre_id + "|" + "|".join(sorted(event.event_uid for event in events))
    return "INC-" + hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10].upper()


def _entities(events: list[NormalizedEvent]) -> dict[str, list[str]]:
    return {
        "hosts": sorted({event.host for event in events if event.host}),
        "users": sorted({event.username for event in events if event.username}),
        "source_ips": sorted(
            {event.source_ip for event in events if event.source_ip}
        ),
    }


def _make_incident(
    technique: str,
    mitre_id: str,
    severity: str,
    confidence: float,
    events: list[NormalizedEvent],
    reason: str,
) -> Incident:
    ordered = sorted(events, key=lambda event: event.timestamp)
    return Incident(
        incident_id=_incident_id(mitre_id, ordered),
        technique=technique,
        mitre_id=mitre_id,
        severity=severity,
        confidence=confidence,
        start_time=ordered[0].timestamp,
        end_time=ordered[-1].timestamp,
        entities=_entities(ordered),
        evidence=ordered,
        correlation_reason=reason,
    )


def _has_mitre(event: NormalizedEvent, mitre_id: str) -> bool:
    return mitre_id.casefold() in {item.casefold() for item in event.mitre_ids}


def _looks_like_discovery(event: NormalizedEvent) -> bool:
    if _has_mitre(event, "T1087.002"):
        return True
    command = (event.command_line or "").casefold()
    indicators = (
        "net user /domain",
        "net group /domain",
        "get-aduser",
        "get-adgroup",
        "dsquery user",
        "whoami /groups",
    )
    return any(indicator in command for indicator in indicators)


def _password_spray_windows(
    events: list[NormalizedEvent], config: CorrelationConfig
) -> list[list[NormalizedEvent]]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    matches: list[list[NormalizedEvent]] = []
    start = 0
    while start < len(ordered):
        end = start
        while (
            end + 1 < len(ordered)
            and (ordered[end + 1].timestamp - ordered[start].timestamp).total_seconds()
            <= config.window_seconds
        ):
            end += 1
        candidate = ordered[start : end + 1]
        users = {event.username for event in candidate if event.username}
        if (
            len(candidate) >= config.password_spray_min_events
            and len(users) >= config.password_spray_min_users
        ):
            matches.append(candidate)
            start = end + 1
        else:
            start += 1
    return matches


def correlate_events(
    events: list[NormalizedEvent], config: CorrelationConfig | None = None
) -> list[Incident]:
    config = config or CorrelationConfig()
    incidents: list[Incident] = []

    spray_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
    roast_groups: dict[tuple[str, str, int], list[NormalizedEvent]] = defaultdict(list)
    discovery_groups: dict[tuple[str, str, int], list[NormalizedEvent]] = defaultdict(list)

    for event in events:
        bucket = _bucket(event.timestamp, config.window_seconds)
        if (
            event.source_ip
            and (event.event_id == "4625" or _has_mitre(event, "T1110.003"))
        ):
            spray_groups[event.source_ip].append(event)

        encryption = (event.ticket_encryption_type or "").casefold()
        description = event.rule_description.casefold()
        if (
            _has_mitre(event, "T1558.003")
            or "kerberoast" in description
            or (event.event_id == "4769" and encryption in {"0x17", "23"})
        ):
            roast_groups[(event.host, event.username or "unknown", bucket)].append(event)

        if _looks_like_discovery(event):
            discovery_groups[(event.host, event.username or "unknown", bucket)].append(
                event
            )

    for source_ip, source_events in spray_groups.items():
        for group in _password_spray_windows(source_events, config):
            users = {event.username for event in group if event.username}
            incidents.append(
                _make_incident(
                    "Password Spraying",
                    "T1110.003",
                    "high",
                    0.90,
                    group,
                    f"{len(group)} failed logons targeted {len(users)} users from "
                    f"source {source_ip} within {config.window_seconds} seconds.",
                )
            )

    for group in roast_groups.values():
        incidents.append(
            _make_incident(
                "Kerberoasting",
                "T1558.003",
                "high",
                0.85,
                group,
                "Kerberos service ticket activity matched a Wazuh MITRE rule or "
                "used RC4 ticket encryption (0x17/etype 23).",
            )
        )

    for group in discovery_groups.values():
        incidents.append(
            _make_incident(
                "Domain Account Discovery",
                "T1087.002",
                "medium",
                0.80,
                group,
                "Process command line or Wazuh MITRE metadata indicates domain "
                "account/group discovery.",
            )
        )

    incidents.sort(key=lambda incident: incident.start_time)
    return incidents
