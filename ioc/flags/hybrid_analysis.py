"""Threat flag extraction from Hybrid Analysis results."""
from __future__ import annotations

from .base import _flag, _safe_int


def _flags_hybrid_analysis(ha: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(ha, dict) or not ha:
        return flags

    verdict = str(ha.get("verdict") or "").lower()
    score = _safe_int(ha.get("threat_score"))
    family = str(ha.get("malware_family") or "").strip()
    behavior = ha.get("behavior", {}) if isinstance(ha.get("behavior"), dict) else {}
    net_ioc = ha.get("network_ioc", {}) if isinstance(ha.get("network_ioc"), dict) else {}
    mitre_attack = ha.get("mitre_attack", []) if isinstance(ha.get("mitre_attack"), list) else []

    if verdict == "malicious":
        flags.append(_flag(
            "HA_MALICIOUS_VERDICT",
            f"Hybrid Analysis verdict: MALICIOUS{' (' + family + ')' if family else ''}",
            "Confirmed malicious sample",
            "CRITICAL",
            ["TA0002", "T1204"],
            f"Score: {score}, Family: {family or 'unknown'}",
            "Hybrid Analysis",
        ))
    elif verdict == "suspicious":
        flags.append(_flag(
            "HA_SUSPICIOUS_VERDICT",
            f"Hybrid Analysis verdict: SUSPICIOUS",
            "Suspicious behavior in sandbox",
            "HIGH",
            ["TA0002"],
            f"Score: {score}",
            "Hybrid Analysis",
        ))

    if score >= 80 and verdict != "malicious":
        flags.append(_flag(
            "HA_HIGH_THREAT_SCORE",
            f"Hybrid Analysis threat score: {score}/100",
            "High threat score in sandbox",
            "HIGH",
            ["TA0002"],
            f"Score: {score}",
            "Hybrid Analysis",
        ))

    if family:
        flags.append(_flag(
            "HA_KNOWN_FAMILY",
            f"Malware family identified: {family}",
            f"Named malware: {family}",
            "CRITICAL",
            ["TA0002"],
            f"Family: {family}",
            "Hybrid Analysis",
        ))

    if net_ioc.get("domains") or net_ioc.get("ips"):
        n_d = len(net_ioc.get("domains") or [])
        n_i = len(net_ioc.get("ips") or [])
        flags.append(_flag(
            "HA_NETWORK_COMMS",
            f"Network IOC observed: {n_d} domain(s), {n_i} IP(s)",
            "C2 or data exfiltration network activity",
            "HIGH",
            ["TA0011", "T1071"],
            f"Domains: {(net_ioc.get('domains') or [])[:3]}, IPs: {(net_ioc.get('ips') or [])[:3]}",
            "Hybrid Analysis",
        ))

    if isinstance(behavior, dict) and behavior.get("persistence"):
        flags.append(_flag(
            "HA_PERSISTENCE_BEHAVIOR",
            "Persistence mechanism observed in sandbox",
            "Sample establishes persistence",
            "HIGH",
            ["TA0003", "T1543"],
            "Persistence behavior reported by Hybrid Analysis",
            "Hybrid Analysis",
        ))

    for technique in mitre_attack[:5]:
        t = str(technique).strip()
        if t.startswith("T1486"):
            flags.append(_flag("HA_RANSOMWARE_TECHNIQUE", "MITRE T1486: Data Encrypted for Impact", "Ransomware behavior", "CRITICAL", ["TA0040", "T1486"], f"MITRE: {t}", "Hybrid Analysis"))
        elif t.startswith("T1055"):
            flags.append(_flag("HA_PROCESS_INJECTION", "MITRE T1055: Process Injection", "Evasion / privilege escalation", "HIGH", ["TA0005", "T1055"], f"MITRE: {t}", "Hybrid Analysis"))
        elif t.startswith("T1059"):
            flags.append(_flag("HA_SCRIPT_EXECUTION", "MITRE T1059: Command and Scripting Interpreter", "Script-based execution", "HIGH", ["TA0002", "T1059"], f"MITRE: {t}", "Hybrid Analysis"))

    return flags
