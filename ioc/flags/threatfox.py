"""Threat flag extraction from ThreatFox results."""
from __future__ import annotations

from .base import _flag, _safe_int


def _flags_threatfox(tf: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(tf, dict) or not tf:
        return flags

    rows = tf.get("data", []) if isinstance(tf.get("data"), list) else []
    if not rows:
        return flags

    primary = rows[0] if isinstance(rows[0], dict) else {}
    tt = str(primary.get("threat_type") or "").lower()
    family = str(primary.get("malware") or primary.get("malware_family") or "").strip()
    confidence = _safe_int(primary.get("confidence_level"))

    if "c2" in tt or "command" in tt:
        flags.append(_flag(
            "TF_C2_IOC",
            f"ThreatFox: C2 IOC{' — ' + family if family else ''}",
            "Active C2 infrastructure",
            "CRITICAL",
            ["TA0011", "T1071"],
            f"Threat type: {tt}, Family: {family or 'unknown'}, Confidence: {confidence}%",
            "ThreatFox",
        ))
    if "payload" in tt or "download" in tt:
        flags.append(_flag(
            "TF_PAYLOAD_IOC",
            f"ThreatFox: Payload delivery IOC{' — ' + family if family else ''}",
            "Malware payload distribution",
            "HIGH",
            ["TA0002", "T1105"],
            f"Threat type: {tt}, Family: {family or 'unknown'}, Confidence: {confidence}%",
            "ThreatFox",
        ))
    if "phish" in tt:
        flags.append(_flag(
            "TF_PHISHING_IOC",
            f"ThreatFox: Phishing IOC",
            "Phishing campaign indicator",
            "HIGH",
            ["TA0001", "T1566"],
            f"Confidence: {confidence}%",
            "ThreatFox",
        ))
    if family and "c2" not in tt and "payload" not in tt and "phish" not in tt:
        flags.append(_flag(
            "TF_MALWARE_FAMILY",
            f"ThreatFox: malware family identified — {family}",
            f"Known malware family: {family}",
            "HIGH" if confidence >= 75 else "MEDIUM",
            ["TA0002"],
            f"Family: {family}, Confidence: {confidence}%",
            "ThreatFox",
        ))
    if confidence >= 90:
        flags.append(_flag(
            "TF_HIGH_CONFIDENCE",
            f"ThreatFox high confidence match: {confidence}%",
            "High-confidence threat IOC",
            "HIGH",
            [],
            f"Confidence: {confidence}%",
            "ThreatFox",
        ))

    return flags
