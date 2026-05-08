"""CISA KEV recent CVE panel with NVD CVSS scoring for the landing page."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#ef4444", "#2d0a0a"),
    "HIGH":     ("#f97316", "#2d1500"),
    "MEDIUM":   ("#eab308", "#2a2000"),
    "LOW":      ("#4ade80", "#0a2010"),
    "NONE":     ("#6b7280", "#1a1d23"),
    "N/A":      ("#6b7280", "#1a1d23"),
}


def _severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a severity label."""
    if score is None:
        return "N/A"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


@st.cache_data(ttl=86400, show_spinner=False)
def fetch_nvd_cvss(cve_id: str) -> dict:
    """Fetch CVSS v3.1 (or v3.0 fallback) score for a single CVE from NVD API v2.

    Args:
        cve_id: CVE identifier string e.g. "CVE-2021-44228".

    Returns:
        Dict with keys: score (float|None), severity (str), vector (str).
    """
    _empty = {"score": None, "severity": "N/A", "vector": ""}
    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={"cveId": cve_id},
            headers={"Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return _empty

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return _empty

    metrics = vulns[0].get("cve", {}).get("metrics", {})

    # Prefer CVSSv3.1 → CVSSv3.0 → CVSSv4.0 → CVSSv2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = (
                cvss_data.get("baseSeverity")
                or _severity_from_score(score)
            ).upper()
            vector = cvss_data.get("vectorString", "")
            return {"score": score, "severity": severity, "vector": vector}

    return _empty


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_cisa_kev_recent(days: int = 1) -> dict:
    """Fetch CVEs from CISA KEV catalog added within the last N days.

    Args:
        days: Number of days to look back from today.

    Returns:
        Dict with keys: title, catalogVersion, vulnerabilities (list), error (bool).
    """
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error("Failed to fetch CISA KEV: %s", exc)
        return {"title": "", "catalogVersion": "", "vulnerabilities": [], "error": True}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()
    recent = [
        {
            "cveID": v.get("cveID", ""),
            "vendorProject": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerabilityName": v.get("vulnerabilityName", ""),
            "dateAdded": v.get("dateAdded", ""),
        }
        for v in data.get("vulnerabilities", [])
        if _parse_date(v.get("dateAdded", "")) >= cutoff
    ]

    return {
        "title": data.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalogVersion": data.get("catalogVersion", ""),
        "vulnerabilities": recent,
        "error": False,
    }


def _parse_date(date_str: str):
    """Parse YYYY-MM-DD string to date, returning epoch date on failure."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return datetime(1970, 1, 1).date()


def _severity_badge_html(score: float | None, severity: str) -> str:
    """Build an inline HTML severity badge."""
    fg, bg = _SEVERITY_STYLE.get(severity, _SEVERITY_STYLE["N/A"])
    score_label = f"{score:.1f}" if score is not None else "N/A"
    return (
        f'<span style="display:inline-flex;align-items:center;gap:5px;'
        f'background:{bg};border:1px solid {fg}33;border-radius:5px;'
        f'padding:2px 7px;font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;">'
        f'<span style="color:{fg};font-weight:700;">{severity}</span>'
        f'<span style="color:{fg};opacity:0.85;">{score_label}</span>'
        f'</span>'
    )


def render_cve_panel() -> None:
    """Render the New CVE panel showing recent CISA KEV entries with CVSS scoring."""
    kev_data = fetch_cisa_kev_recent(days=1)
    vulns = kev_data.get("vulnerabilities", [])
    catalog_version = kev_data.get("catalogVersion", "")
    error = kev_data.get("error", False)

    version_label = f"v{catalog_version} · " if catalog_version else ""

    st.markdown(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-bottom:10px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.88rem;'
        f'font-weight:700;color:#f5f7fb;letter-spacing:0.01em;">New CVE</span>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.65rem;'
        f'color:#6b7280;">{version_label}CISA KEV · last 24h</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if error:
        st.warning("Unable to reach CISA KEV feed. Check your connection.")
        return

    if not vulns:
        st.markdown(
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;'
            'color:#6b7280;text-align:center;padding:32px 0;border:1px solid rgba(255,255,255,0.06);'
            'border-radius:10px;background:rgba(255,255,255,0.02);">'
            'No new CVEs added to CISA KEV<br>in the last 24 hours.'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    items_html = ""
    for v in vulns:
        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        name = v.get("vulnerabilityName", "")
        date_added = v.get("dateAdded", "")
        vendor_product = f"{vendor} · {product}" if vendor and product else vendor or product

        cvss = fetch_nvd_cvss(cve_id)
        score = cvss["score"]
        severity = cvss["severity"]
        badge = _severity_badge_html(score, severity)

        items_html += (
            f'<div style="border:1px solid rgba(255,255,255,0.08);border-radius:8px;'
            f'padding:10px 12px;margin-bottom:8px;background:rgba(255,255,255,0.02);">'
            # Row 1: CVE ID + date
            f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">'
            f'<a href="https://www.cve.org/CVERecord?id={cve_id}" target="_blank" '
            f'style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
            f'color:#60a5fa;font-weight:600;text-decoration:none;" '
            f'onmouseover="this.style.textDecoration=\'underline\'" '
            f'onmouseout="this.style.textDecoration=\'none\'">{cve_id}</a>'
            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
            f'color:#6b7280;white-space:nowrap;">{date_added}</span>'
            f'</div>'
            # Row 2: name
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
            f'color:#e2e6f0;margin-top:4px;line-height:1.4;">{name}</div>'
            # Row 3: vendor·product + severity badge
            f'<div style="display:flex;justify-content:space-between;align-items:center;'
            f'margin-top:6px;gap:6px;">'
            f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
            f'color:#9ca3af;">{vendor_product}</span>'
            f'{badge}'
            f'</div>'
            f'</div>'
        )

    st.markdown(
        f'<div style="max-height:calc(100vh - 260px);overflow-y:auto;padding-right:2px;">'
        f'{items_html}'
        f'</div>',
        unsafe_allow_html=True,
    )
