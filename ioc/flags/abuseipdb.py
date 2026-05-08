"""Threat flag extraction from AbuseIPDB results."""
from __future__ import annotations

from .base import _flag, _safe_int


def _flags_abuseipdb(ab: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(ab, dict) or not ab:
        return flags

    score = _safe_int(ab.get("abuseConfidenceScore"))
    reports = _safe_int(ab.get("totalReports"))

    if score >= 90:
        flags.append(_flag(
            "ABUSE_CRITICAL_CONFIDENCE",
            f"AbuseIPDB confidence: {score}% — highly abusive IP",
            "Known malicious IP address",
            "CRITICAL",
            ["TA0011", "T1071"],
            f"Confidence: {score}%, Reports: {reports}",
            "AbuseIPDB",
        ))
    elif score >= 70:
        flags.append(_flag(
            "ABUSE_HIGH_CONFIDENCE",
            f"AbuseIPDB confidence: {score}%",
            "Frequently reported malicious IP",
            "HIGH",
            ["TA0011", "T1071"],
            f"Confidence: {score}%, Reports: {reports}",
            "AbuseIPDB",
        ))
    elif score >= 25:
        flags.append(_flag(
            "ABUSE_MEDIUM_CONFIDENCE",
            f"AbuseIPDB confidence: {score}%",
            "Moderately reported suspicious IP",
            "MEDIUM",
            [],
            f"Confidence: {score}%, Reports: {reports}",
            "AbuseIPDB",
        ))

    if reports >= 50:
        flags.append(_flag(
            "ABUSE_MANY_REPORTS",
            f"{reports} abuse reports on record",
            "Persistently abusive IP",
            "HIGH",
            [],
            f"Total reports: {reports}",
            "AbuseIPDB",
        ))

    # Category-based flags
    cat_report = ab.get("reportCategories") or {}
    if not isinstance(cat_report, dict):
        cat_report = {}
    cat_map = {
        4:  ("ABUSE_CAT_DDOS",      "DDoS attack source",           "DDoS / DoS",           ["TA0040", "T1498"],  "HIGH"),
        7:  ("ABUSE_CAT_PHISHING",  "Phishing source IP",           "Phishing",             ["TA0001", "T1566"],  "HIGH"),
        14: ("ABUSE_CAT_PORTSCAN",  "Port scan activity reported",  "Reconnaissance scan",  ["TA0043", "T1046"],  "MEDIUM"),
        15: ("ABUSE_CAT_HACKING",   "Hacking activity reported",    "Active exploitation",  ["TA0001", "T1190"],  "HIGH"),
        16: ("ABUSE_CAT_SQLI",      "SQL injection reported",       "Web application attack",["T1190"],           "HIGH"),
        18: ("ABUSE_CAT_BRUTEFORCE","Brute-force attack source",    "Credential attack",    ["TA0006", "T1110"],  "HIGH"),
        21: ("ABUSE_CAT_WEBATTACK", "Web application attack source","Web attack",           ["T1190"],            "HIGH"),
        22: ("ABUSE_CAT_SSH",       "SSH attack source",            "Credential / SSH attack",["TA0006","T1110.004"],"MEDIUM"),
    }
    for code_str, count in cat_report.items():
        try:
            code = int(code_str)
        except Exception:
            continue
        if code in cat_map and _safe_int(count) >= 1:
            fid, label, threat, mitre_list, sev = cat_map[code]
            flags.append(_flag(fid, label, threat, sev, mitre_list,
                               f"Category {code} reported {count}×", "AbuseIPDB"))

    return flags
