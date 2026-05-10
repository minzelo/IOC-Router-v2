"""Threat flag extraction from MxToolBox results."""
from __future__ import annotations

from .base import _flag, _safe_int


def _flags_mxtoolbox(mx: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(mx, dict) or not mx or mx.get("error"):
        return flags

    verdict = str(mx.get("verdict") or "").upper()
    lookups = mx.get("lookups") or {}
    if not isinstance(lookups, dict):
        return flags

    total_failed = _safe_int(mx.get("total_failed"))
    total_warnings = _safe_int(mx.get("total_warnings"))

    # ── Blacklist checks ──────────────────────────────────────────────────────
    bl = lookups.get("blacklist") or {}
    if isinstance(bl, dict) and not bl.get("error"):
        bl_failed = bl.get("raw_failed_count", 0)
        bl_warn   = bl.get("raw_warning_count", 0)
        bl_items  = bl.get("failed") or []
        detail    = "; ".join(str(i) for i in bl_items[:5]) if bl_items else ""

        if bl_failed >= 3:
            flags.append(_flag(
                "MX_BLACKLIST_CRITICAL",
                f"Listed on {bl_failed} blacklists",
                "Blacklisted IP/domain",
                "CRITICAL",
                ["TA0011", "T1071"],
                detail or f"{bl_failed} blacklist entries",
                "MxToolBox",
            ))
        elif bl_failed >= 1:
            flags.append(_flag(
                "MX_BLACKLIST_HIT",
                f"Listed on {bl_failed} blacklist(s)",
                "Known bad reputation",
                "HIGH",
                ["TA0011", "T1071"],
                detail or f"{bl_failed} blacklist entry",
                "MxToolBox",
            ))
        elif bl_warn >= 1:
            flags.append(_flag(
                "MX_BLACKLIST_WARN",
                f"Blacklist warning on {bl_warn} source(s)",
                "Borderline reputation",
                "MEDIUM",
                ["TA0011"],
                f"{bl_warn} blacklist warning(s)",
                "MxToolBox",
            ))

    # ── Email security: SPF ───────────────────────────────────────────────────
    spf = lookups.get("spf") or {}
    if isinstance(spf, dict) and not spf.get("error"):
        spf_fail = spf.get("raw_failed_count", 0)
        spf_warn = spf.get("raw_warning_count", 0)
        spf_detail = "; ".join(str(i) for i in (spf.get("failed") or [])[:3])

        if spf_fail >= 1:
            flags.append(_flag(
                "MX_SPF_FAIL",
                "SPF record missing or invalid",
                "Email spoofing / phishing risk",
                "HIGH",
                ["TA0001", "T1566"],
                spf_detail or "SPF check failed",
                "MxToolBox",
            ))
        elif spf_warn >= 1:
            flags.append(_flag(
                "MX_SPF_WARN",
                "SPF record has warnings",
                "Potential email spoofing exposure",
                "MEDIUM",
                ["TA0001", "T1566"],
                f"{spf_warn} SPF warning(s)",
                "MxToolBox",
            ))

    # ── Email security: DMARC ─────────────────────────────────────────────────
    dmarc = lookups.get("dmarc") or {}
    if isinstance(dmarc, dict) and not dmarc.get("error"):
        dmarc_fail = dmarc.get("raw_failed_count", 0)
        dmarc_warn = dmarc.get("raw_warning_count", 0)
        dmarc_detail = "; ".join(str(i) for i in (dmarc.get("failed") or [])[:3])

        if dmarc_fail >= 1:
            flags.append(_flag(
                "MX_DMARC_FAIL",
                "DMARC policy missing or not enforced",
                "Email spoofing / phishing risk",
                "HIGH",
                ["TA0001", "T1566"],
                dmarc_detail or "DMARC check failed",
                "MxToolBox",
            ))
        elif dmarc_warn >= 1:
            flags.append(_flag(
                "MX_DMARC_WARN",
                "DMARC policy has warnings",
                "Partial email spoofing protection",
                "MEDIUM",
                ["TA0001"],
                f"{dmarc_warn} DMARC warning(s)",
                "MxToolBox",
            ))

    # ── MX record ─────────────────────────────────────────────────────────────
    mxr = lookups.get("mx") or {}
    if isinstance(mxr, dict) and not mxr.get("error"):
        mx_fail = mxr.get("raw_failed_count", 0)
        if mx_fail >= 1:
            flags.append(_flag(
                "MX_RECORD_FAIL",
                "MX record missing or invalid",
                "Mail delivery / domain legitimacy issue",
                "MEDIUM",
                [],
                "; ".join(str(i) for i in (mxr.get("failed") or [])[:3]) or "MX check failed",
                "MxToolBox",
            ))

    # ── DNS ───────────────────────────────────────────────────────────────────
    dns = lookups.get("dns") or {}
    if isinstance(dns, dict) and not dns.get("error"):
        dns_fail = dns.get("raw_failed_count", 0)
        if dns_fail >= 1:
            flags.append(_flag(
                "MX_DNS_FAIL",
                "DNS resolution issue detected",
                "Infrastructure / DNS anomaly",
                "MEDIUM",
                ["TA0043"],
                "; ".join(str(i) for i in (dns.get("failed") or [])[:3]) or "DNS check failed",
                "MxToolBox",
            ))

    # ── HTTP ──────────────────────────────────────────────────────────────────
    http = lookups.get("http") or {}
    if isinstance(http, dict) and not http.get("error"):
        http_fail = http.get("raw_failed_count", 0)
        http_warn = http.get("raw_warning_count", 0)
        if http_fail >= 1:
            flags.append(_flag(
                "MX_HTTP_FAIL",
                "HTTP check failed (possible misconfiguration or takedown)",
                "Web service anomaly",
                "LOW",
                [],
                "; ".join(str(i) for i in (http.get("failed") or [])[:3]) or "HTTP check failed",
                "MxToolBox",
            ))
        elif http_warn >= 1:
            flags.append(_flag(
                "MX_HTTP_WARN",
                "HTTP check returned warnings",
                "Web service misconfiguration",
                "LOW",
                [],
                f"{http_warn} HTTP warning(s)",
                "MxToolBox",
            ))

    # ── PTR (reverse DNS) ─────────────────────────────────────────────────────
    ptr = lookups.get("ptr") or {}
    if isinstance(ptr, dict) and not ptr.get("error"):
        ptr_fail = ptr.get("raw_failed_count", 0)
        if ptr_fail >= 1:
            flags.append(_flag(
                "MX_PTR_FAIL",
                "No PTR (reverse DNS) record — no legitimate rDNS",
                "Reputation / spam indicator",
                "LOW",
                [],
                "PTR lookup failed",
                "MxToolBox",
            ))

    # ── Overall verdict fallback if no specific flag yet ──────────────────────
    if not flags and verdict == "FAIL":
        flags.append(_flag(
            "MX_VERDICT_FAIL",
            f"MxToolBox overall verdict: FAIL ({total_failed} failed, {total_warnings} warnings)",
            "DNS/Mail infrastructure issue",
            "MEDIUM",
            [],
            f"Failed checks: {total_failed}",
            "MxToolBox",
        ))
    elif not flags and verdict == "WARN":
        flags.append(_flag(
            "MX_VERDICT_WARN",
            f"MxToolBox overall verdict: WARN ({total_warnings} warnings)",
            "DNS/Mail configuration warning",
            "LOW",
            [],
            f"Warning checks: {total_warnings}",
            "MxToolBox",
        ))

    return flags
