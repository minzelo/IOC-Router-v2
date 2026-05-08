"""Verdict aggregation helpers."""
from __future__ import annotations

from typing import Dict, List, Tuple

from ioc.parser import IOC


def summarize_results(
    items: List[IOC],
    vt_results: Dict[str, dict],
    urlscan_results: Dict[str, dict],
    abuse_results: Dict[str, dict],
    threatfox_results: Dict[str, dict],
    malwarebazaar_results: Dict[str, dict],
) -> Tuple[dict, List[dict]]:
    summary = {
        "total": len(items),
        "malicious": 0,
        "suspicious": 0,
        "unknown": 0,
        "benign": 0,
    }
    rows: List[dict] = []

    for ioc in items:
        vt = vt_results.get(ioc.value) or {}
        us = urlscan_results.get(ioc.value) or {}
        ab = abuse_results.get(ioc.value) or {}
        tf = threatfox_results.get(ioc.value) or {}
        mb = malwarebazaar_results.get(ioc.value) or {}
        stats = vt.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        abuse_score = ab.get("abuseConfidenceScore", 0) if ab else 0
        urlscan_verdicts = us.get("verdicts", {}) if us else {}
        urlscan_mal = urlscan_verdicts.get("malicious", False)
        urlscan_phish = urlscan_verdicts.get("phishing", False)

        strong_sources = 0
        weak_sources = 0
        if malicious >= 3:
            strong_sources += 1
        elif malicious > 0:
            weak_sources += 1
        if suspicious > 0:
            weak_sources += 1
        if abuse_score >= 80:
            strong_sources += 1
        elif abuse_score >= 50:
            weak_sources += 1
        if urlscan_mal or urlscan_phish:
            weak_sources += 1
        if mb:
            weak_sources += 1
        if tf:
            weak_sources += 1

        if malicious > 0:
            verdict = "Malicious"
            summary["malicious"] += 1
            confidence = "High" if strong_sources >= 1 and (strong_sources + weak_sources) >= 2 else "Med"
            reason = f"VT: {malicious} engines flagged"
        elif suspicious > 0:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med"
            reason = f"VT: {suspicious} engines suspicious"
        elif abuse_score >= 80:
            verdict = "Malicious"
            summary["malicious"] += 1
            confidence = "High" if strong_sources >= 2 or (strong_sources >= 1 and weak_sources >= 1) else "Med"
            reason = f"AbuseIPDB score {abuse_score}"
        elif abuse_score >= 50 or urlscan_mal or urlscan_phish:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            if abuse_score >= 50:
                reason = f"AbuseIPDB score {abuse_score}"
            else:
                reason = "urlscan verdict suspicious"
        elif mb:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            reason = "MalwareBazaar hit"
        elif tf:
            verdict = "Suspicious"
            summary["suspicious"] += 1
            confidence = "Med" if (strong_sources + weak_sources) >= 2 else "Low"
            reason = "ThreatFox hit"
        elif harmless > 0 or undetected > 0:
            verdict = "Unknown"
            summary["unknown"] += 1
            confidence = "Low"
            reason = "VT: no detections"
        else:
            verdict = "Unknown"
            summary["unknown"] += 1
            confidence = "Low"
            reason = "No data"

        sources = []
        if vt:
            sources.append("VT")
        if us:
            sources.append("urlscan")
        if ab:
            sources.append("AbuseIPDB")
        if tf:
            sources.append("ThreatFox")
        if mb:
            sources.append("MalwareBazaar")

        rows.append(
            {
                "Artifact": ioc.value,
                "Type": ioc.type,
                "Verdict": verdict,
                "Confidence": confidence,
                "Primary Evidence": reason,
                "Next Action": "Review",
                "Sources": ", ".join(sources) if sources else "",
            }
        )

    summary["benign"] = 0
    return summary, rows
