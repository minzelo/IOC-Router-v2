"""Recent CVE panel using NVD API v2 with lazy loading (10 per page)."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_PAGE_SIZE = 10
_CACHE_TTL = 3600  # 1 hour — matches st.cache_data TTL

_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#ef4444", "#2d0a0a"),
    "HIGH":     ("#f97316", "#2d1500"),
    "MEDIUM":   ("#eab308", "#2a2000"),
    "LOW":      ("#4ade80", "#0a2010"),
    "NONE":     ("#6b7280", "#1a1d23"),
    "N/A":      ("#6b7280", "#1a1d23"),
}

_FILTER_OPTIONS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEVERITY_FILTERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _extract_cvss(metrics: dict) -> tuple[float | None, str]:
    """Extract best available CVSS score and severity from an NVD metrics dict.

    Args:
        metrics: The metrics dict from an NVD CVE item.

    Returns:
        Tuple of (score, severity_label).
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = (
                cvss_data.get("baseSeverity") or _severity_from_score(score)
            ).upper()
            return score, severity
    return None, "N/A"


def _extract_vendor_product(configurations: list) -> tuple[str, str]:
    """Extract vendor and product name from NVD CPE configurations.

    Args:
        configurations: The configurations list from an NVD CVE item.

    Returns:
        Tuple of (vendor, product), empty strings if not found.
    """
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5 and parts[3] not in ("*", "-", ""):
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title() if parts[4] not in ("*", "-") else ""
                    return vendor, product
    return "", ""


def _parse_nvd_item(item: dict, kev_ids: set[str]) -> dict:
    """Parse a single NVD vulnerability item into a display-ready dict.

    Args:
        item: A single entry from NVD vulnerabilities list.
        kev_ids: Set of CVE IDs in the CISA KEV catalog.

    Returns:
        Dict with display fields for a CVE card.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )
    if len(desc) > 120:
        desc = desc[:117] + "..."

    score, severity = _extract_cvss(cve.get("metrics", {}))
    vendor, product = _extract_vendor_product(cve.get("configurations", []))

    return {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "description": desc,
        "datePublished": cve.get("published", "")[:10],
        "score": score,
        "severity": severity,
        "isKev": cve_id in kev_ids,
    }


# ── API fetchers ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=_CACHE_TTL, show_spinner=False)
def _fetch_kev_ids() -> set[str]:
    """Fetch the set of CVE IDs in the CISA KEV catalog.

    Returns:
        Set of CVE ID strings currently in the CISA KEV catalog.
    """
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        return {v.get("cveID", "") for v in resp.json().get("vulnerabilities", [])}
    except requests.RequestException as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return set()


@st.cache_data(ttl=_CACHE_TTL, show_spinner=False)
def _fetch_nvd_page(pub_start: str, pub_end: str, start_index: int) -> dict:
    """Fetch one page of CVEs from NVD API v2.

    Args:
        pub_start: ISO-8601 start datetime string (UTC).
        pub_end: ISO-8601 end datetime string (UTC).
        start_index: Zero-based offset for NVD pagination.

    Returns:
        Dict with keys: items (raw NVD list), total (int), error (bool).
    """
    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": _PAGE_SIZE,
                "startIndex": start_index,
            },
            headers={"Accept": "application/json"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "items": data.get("vulnerabilities", []),
            "total": data.get("totalResults", 0),
            "error": False,
        }
    except requests.RequestException as exc:
        logger.error("NVD page fetch failed (startIndex=%d): %s", start_index, exc)
        return {"items": [], "total": 0, "error": True}


# ── Session state helpers ─────────────────────────────────────────────────────

def _time_window() -> tuple[str, str]:
    """Return (pub_start, pub_end) ISO strings for the last 24 hours."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    now = datetime.now(timezone.utc)
    return (now - timedelta(hours=24)).strftime(fmt), now.strftime(fmt)


def _state_is_fresh() -> bool:
    """Return True if cached session state is within the cache TTL."""
    fetched_at = st.session_state.get("cve_fetched_at", 0)
    return (time.time() - fetched_at) < _CACHE_TTL


def _init_state() -> None:
    """Initialize (or reset) the CVE panel session state and fetch first page."""
    pub_start, pub_end = _time_window()
    kev_ids = _fetch_kev_ids()
    page = _fetch_nvd_page(pub_start, pub_end, start_index=0)

    st.session_state["cve_items"] = [_parse_nvd_item(i, kev_ids) for i in page["items"]]
    st.session_state["cve_next_index"] = len(page["items"])
    st.session_state["cve_total_nvd"] = page["total"]
    st.session_state["cve_pub_start"] = pub_start
    st.session_state["cve_pub_end"] = pub_end
    st.session_state["cve_error"] = page["error"]
    st.session_state["cve_fetched_at"] = time.time()


def _load_next_page() -> None:
    """Fetch and append the next page of CVEs to session state."""
    pub_start = st.session_state["cve_pub_start"]
    pub_end = st.session_state["cve_pub_end"]
    start_index = st.session_state["cve_next_index"]

    kev_ids = _fetch_kev_ids()
    page = _fetch_nvd_page(pub_start, pub_end, start_index=start_index)

    if not page["error"]:
        new_items = [_parse_nvd_item(i, kev_ids) for i in page["items"]]
        st.session_state["cve_items"].extend(new_items)
        st.session_state["cve_next_index"] += len(page["items"])
        st.session_state["cve_total_nvd"] = page["total"]


# ── HTML builders ─────────────────────────────────────────────────────────────

def _severity_badge_html(score: float | None, severity: str) -> str:
    """Build an inline HTML severity badge.

    Args:
        score: CVSS base score or None.
        severity: Severity label string.

    Returns:
        HTML string for the badge.
    """
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


def _kev_badge_html() -> str:
    """Build a small KEV indicator badge.

    Returns:
        HTML string for the KEV badge.
    """
    return (
        '<span style="display:inline-flex;align-items:center;'
        'background:#1e3a5f;border:1px solid #3b82f633;border-radius:4px;'
        'padding:1px 5px;font-family:\'JetBrains Mono\',monospace;font-size:0.58rem;'
        'color:#60a5fa;font-weight:600;letter-spacing:0.03em;">KEV</span>'
    )


def _card_html(v: dict) -> str:
    """Build HTML for a single CVE card.

    Args:
        v: Parsed CVE dict from _parse_nvd_item.

    Returns:
        HTML string for the card.
    """
    cve_id = v["cveID"]
    vendor = v["vendorProject"]
    product = v["product"]
    vendor_product = f"{vendor} · {product}" if vendor and product else vendor or product or "—"

    badge = _severity_badge_html(v["score"], v["severity"])
    kev_tag = f" {_kev_badge_html()}" if v["isKev"] else ""

    return (
        f'<div style="border:1px solid rgba(255,255,255,0.08);border-radius:8px;'
        f'padding:10px 12px;margin-bottom:8px;background:rgba(255,255,255,0.02);">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">'
        f'<div style="display:flex;align-items:center;gap:6px;">'
        f'<a href="https://www.cve.org/CVERecord?id={cve_id}" target="_blank" '
        f'style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
        f'color:#60a5fa;font-weight:600;text-decoration:none;" '
        f'onmouseover="this.style.textDecoration=\'underline\'" '
        f'onmouseout="this.style.textDecoration=\'none\'">{cve_id}</a>'
        f'{kev_tag}'
        f'</div>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
        f'color:#6b7280;white-space:nowrap;">{v["datePublished"]}</span>'
        f'</div>'
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;'
        f'color:#e2e6f0;margin-top:4px;line-height:1.4;">{v["description"]}</div>'
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-top:6px;gap:6px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
        f'color:#9ca3af;">{vendor_product}</span>'
        f'{badge}'
        f'</div>'
        f'</div>'
    )


# ── Filter logic ──────────────────────────────────────────────────────────────

def _on_severity_change() -> None:
    """Enforce mutual exclusivity between ALL and individual severity filters.

    Rules:
    - If the user just selected ALL → keep only ALL.
    - If any individual severity is selected → remove ALL.
    - If nothing is selected → revert to ALL.
    """
    selected: list[str] = list(st.session_state.get("cve_severity_pills") or [])
    prev: list[str] = list(st.session_state.get("cve_severity_pills_prev") or ["ALL"])

    newly_added = [s for s in selected if s not in prev]

    if "ALL" in newly_added:
        new_selection = ["ALL"]
    elif any(s in _SEVERITY_FILTERS for s in selected):
        new_selection = [s for s in selected if s != "ALL"]
    else:
        new_selection = ["ALL"]

    st.session_state["cve_severity_pills"] = new_selection
    st.session_state["cve_severity_pills_prev"] = new_selection


# ── Main render ───────────────────────────────────────────────────────────────

def render_cve_panel() -> None:
    """Render the New CVE panel with lazy loading and severity filtering."""
    if "cve_items" not in st.session_state or not _state_is_fresh():
        with st.spinner("Loading CVEs…"):
            _init_state()

    error: bool = st.session_state.get("cve_error", False)
    items: list[dict] = st.session_state.get("cve_items", [])
    total_nvd: int = st.session_state.get("cve_total_nvd", 0)
    next_index: int = st.session_state.get("cve_next_index", 0)

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'margin-bottom:10px;">'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.88rem;'
        f'font-weight:700;color:#f5f7fb;letter-spacing:0.01em;">New CVE</span>'
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.65rem;'
        f'color:#6b7280;">{total_nvd} total · NVD · last 24h</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if error:
        st.warning("Unable to reach NVD API. Check your connection.")
        return

    if not items and total_nvd == 0:
        st.markdown(
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;'
            'color:#6b7280;text-align:center;padding:32px 0;border:1px solid rgba(255,255,255,0.06);'
            'border-radius:10px;background:rgba(255,255,255,0.02);">'
            'No new CVEs published<br>in the last 24 hours.'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Severity filter ───────────────────────────────────────────────────────
    if "cve_severity_pills" not in st.session_state:
        st.session_state["cve_severity_pills"] = ["ALL"]
        st.session_state["cve_severity_pills_prev"] = ["ALL"]

    selected_filters: list[str] = st.pills(
        label="Severity filter",
        options=_FILTER_OPTIONS,
        selection_mode="multi",
        label_visibility="collapsed",
        key="cve_severity_pills",
        on_change=_on_severity_change,
    )

    active: set[str] = set(selected_filters) if selected_filters else {"ALL"}
    filtered = items if "ALL" in active else [v for v in items if v["severity"] in active]

    # ── CVE cards (fixed-height scrollable) ──────────────────────────────────
    if filtered:
        st.markdown(
            '<div style="height:320px;overflow-y:auto;padding-right:4px;">'
            + "".join(_card_html(v) for v in filtered)
            + "</div>",
            unsafe_allow_html=True,
        )
    else:
        unloaded = total_nvd - next_index
        hint = (
            f" Try loading more — {unloaded} unloaded result{'s' if unloaded != 1 else ''} remaining."
            if unloaded > 0 else ""
        )
        st.markdown(
            f'<div style="height:320px;display:flex;align-items:center;justify-content:center;'
            f'font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;color:#6b7280;'
            f'text-align:center;">'
            f'No CVEs match the selected filter.{hint}'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── View more ─────────────────────────────────────────────────────────────
    st.markdown('<div style="margin-top:10px;"></div>', unsafe_allow_html=True)
    has_more = next_index < total_nvd
    if has_more:
        remaining = total_nvd - next_index
        col_btn, col_info = st.columns([2, 3])
        with col_btn:
            if st.button("View more", key="cve_view_more", use_container_width=True):
                with st.spinner("Loading…"):
                    _load_next_page()
                st.rerun()
        with col_info:
            st.markdown(
                f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.63rem;'
                f'color:#6b7280;padding-top:6px;">'
                f'{remaining} more result{"s" if remaining != 1 else ""} on NVD'
                f'</div>',
                unsafe_allow_html=True,
            )
