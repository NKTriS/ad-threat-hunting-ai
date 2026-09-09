"""Wazuh event normalization and incident correlation."""

from .engine import CorrelationConfig, correlate_events
from .models import Incident, NormalizedEvent
from .wazuh import load_wazuh_alerts, normalize_wazuh_alert

__all__ = [
    "CorrelationConfig",
    "Incident",
    "NormalizedEvent",
    "correlate_events",
    "load_wazuh_alerts",
    "normalize_wazuh_alert",
]
