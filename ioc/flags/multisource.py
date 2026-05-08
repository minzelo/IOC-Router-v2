"""Multi-source correlation threat flags."""
from __future__ import annotations

from .base import _flag, _safe_int


def _flags_multisource(
    vt: dict, us: dict, ab: dict, tf: dict, mb: dict, ha: dict,
) -> list[dict]:
    flags: list[dict] = []

    # Count how many providers flag as malicious
    mal_count = 0
    mal_sources = []

    vt_mal = _safe_int((vt.get("stats", {}) or {}).get("malicious"))
    if vt_mal >= 3:
        mal_count += 1
        mal_sources.append(f"VT ({vt_mal} engines)")

    us_verdict = (us.get("verdicts", {}) or {}).get("overall", {}) or {}
    if us_verdict.get("malicious"):
        mal_count += 1
        mal_sources.append("URLScan")

    ab_score = _safe_int((ab or {}).get("abuseConfidenceScore"))
    if ab_score >= 70:
        mal_count += 1
        mal_sources.append(f"AbuseIPDB ({ab_score}%)")

    tf_rows = (tf.get("data") or []) if isinstance(tf, dict) else []
    if tf_rows:
        mal_count += 1
        mal_sources.append("ThreatFox")

    if (mb.get("data") or []) if isinstance(mb, dict) else []:
        mal_count += 1
        mal_sources.append("MalwareBazaar")

    ha_verdict = str((ha or {}).get("verdict") or "").lower()
    if ha_verdict == "malicious":
        mal_count += 1
        mal_sources.append("HybridAnalysis")

    if mal_count >= 4:
        flags.append(_flag(
            "MULTI_HIGH_CONFIDENCE_MALICIOUS",
            f"Confirmed malicious across {mal_count} independent sources",
            "High-confidence malicious indicator",
            "CRITICAL",
            ["TA0001", "TA0002", "TA0011"],
            f"Sources: {', '.join(mal_sources)}",
            "Multi-source",
        ))
    elif mal_count >= 2:
        flags.append(_flag(
            "MULTI_CORROBORATED_MALICIOUS",
            f"Flagged malicious by {mal_count} sources",
            "Corroborated malicious indicator",
            "HIGH",
            [],
            f"Sources: {', '.join(mal_sources)}",
            "Multi-source",
        ))

    return flags
