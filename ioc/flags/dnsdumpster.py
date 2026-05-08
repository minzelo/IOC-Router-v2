"""Threat flag extraction from DNSDumpster results."""
from __future__ import annotations

from .base import _flag


def _flags_dnsdumpster(dnsd: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(dnsd, dict) or not dnsd:
        return flags

    subdomains = dnsd.get("subdomains") or []
    records = dnsd.get("records") or {}

    if isinstance(subdomains, list) and len(subdomains) >= 20:
        flags.append(_flag(
            "DNS_LARGE_SUBDOMAIN_COUNT",
            f"{len(subdomains)} subdomains discovered",
            "Large attack surface via subdomains",
            "LOW",
            ["TA0043"],
            f"{len(subdomains)} subdomains",
            "DNSDumpster",
        ))

    if isinstance(records, dict):
        mx = records.get("MX") or records.get("mx") or []
        ns = records.get("NS") or records.get("ns") or []
        txt = records.get("TXT") or records.get("txt") or []
        txt_vals = " ".join(str(t) for t in (txt if isinstance(txt, list) else []))

        if not mx and not ns:
            flags.append(_flag(
                "DNS_NO_STANDARD_RECORDS",
                "No MX/NS records found — unusual DNS profile",
                "Atypical DNS configuration — possible newly set up infra",
                "LOW",
                ["T1583"],
                "No MX/NS records",
                "DNSDumpster",
            ))

        if "v=spf1 -all" in txt_vals or "v=spf1 ~all" in txt_vals.lower():
            pass  # Normal SPF — no flag
        if "spf" not in txt_vals.lower() and mx:
            flags.append(_flag(
                "DNS_NO_SPF",
                "No SPF record — domain could be used for spoofing",
                "Email spoofing risk",
                "LOW",
                ["T1566.001"],
                "No SPF TXT record found",
                "DNSDumpster",
            ))

    return flags
