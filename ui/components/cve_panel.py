"""Recent CVE panel using NVD API v2 with lazy loading (10 per page)."""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

_WIB = timezone(timedelta(hours=7))  # UTC+7 Jakarta / WIB

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

_FILTER_OPTIONS = ["Common", "ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEVERITY_FILTERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# Keywords checked case-insensitively across vendor + product + description.
_COMMON_APP_KEYWORDS: list[str] = [
    "cisco", "fortinet", "palo alto", "paloalto", "vmware", "dell",
    "huawei", "microsoft", "chrome", "firefox", "zoom", "slack",
    "whatsapp desktop", "telegram desktop", "notion", "google drive",
    "microsoft authenticator", "bitwarden", "lastpass",
]
# Short/ambiguous tokens — matched against vendor+product only to avoid false positives.
_COMMON_APP_VENDOR_ONLY: list[str] = ["hp", "edge"]

# Matches "vulnerability/overflow/injection/… in <ProductName>" in description text.
# Requires a capital-letter start so generic words ("the", "a") are not captured.
_PRODUCT_IN_DESC_RE = re.compile(
    r"(?:vulnerability|overflow|injection|flaw|issue|bug|error|weakness)\s+in\s+"
    r"([A-Z][A-Za-z0-9][A-Za-z0-9_\-\.]*(?:\s+[A-Z][A-Za-z0-9][A-Za-z0-9_\-\.]*)?)",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_common_app(v: dict) -> bool:
    """Return True if the CVE involves a well-known application from the common app list.

    Args:
        v: Parsed CVE dict from _parse_nvd_item.

    Returns:
        True if any common-app keyword is found in the CVE fields.
    """
    vendor = v.get("vendorProject", "").lower()
    product = v.get("product", "").lower()
    desc = v.get("description", "").lower()
    full_text = f"{vendor} {product} {desc}"
    vendor_product = f"{vendor} {product}"

    if any(kw in full_text for kw in _COMMON_APP_KEYWORDS):
        return True
    return any(kw in vendor_product for kw in _COMMON_APP_VENDOR_ONLY)


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

    Prefers Primary (NVD) scores; falls back to Secondary (CNA) scores when
    NVD has not yet published its own analysis.

    Args:
        metrics: The metrics dict from an NVD CVE item.

    Returns:
        Tuple of (score, severity_label).
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type", "").lower() == "primary"), None)
        entry = primary or entries[0]
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = (cvss_data.get("baseSeverity") or _severity_from_score(score)).upper()
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


def _parse_nvd_item(item: dict, kev_data: dict[str, dict]) -> dict:
    """Parse a single NVD vulnerability item into a display-ready dict.

    Vendor/product resolution order:
      1. NVD CPE configurations (populated after NVD analysis)
      2. CISA KEV catalog entry (available immediately for KEV CVEs)
      3. sourceIdentifier domain (e.g. "security@apache.org" → "Apache")
      4. Description text regex — "vulnerability in <Product>" pattern

    Args:
        item: A single entry from NVD vulnerabilities list.
        kev_data: Dict mapping CVE ID to {vendorProject, product} from CISA KEV.

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

    kev_entry = kev_data.get(cve_id, {})

    if not vendor and not product and kev_entry:
        vendor = kev_entry.get("vendorProject", "")
        product = kev_entry.get("product", "")

    if not vendor and not product:
        source = cve.get("sourceIdentifier", "")
        if "@" in source:
            domain = source.split("@", 1)[1]
            org = domain.split(".")[0]
            if org not in ("nist", "mitre", "cve"):
                vendor = org.replace("-", " ").title()

    if not vendor and not product:
        full_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        m = _PRODUCT_IN_DESC_RE.search(full_desc)
        if m:
            vendor = m.group(1)

    pub_raw = cve.get("published", "")
    try:
        # NVD published timestamps are UTC; convert to WIB (UTC+7) for display
        pub_utc = datetime.strptime(pub_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        pub_wib = pub_utc.astimezone(_WIB)
        date_published = pub_wib.strftime("%Y-%m-%d")
        time_published = pub_wib.strftime("%H:%M")
    except (ValueError, TypeError):
        date_published = pub_raw[:10]
        time_published = pub_raw[11:16] if len(pub_raw) >= 16 else ""

    return {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "description": desc,
        "datePublished": date_published,
        "timePublished": time_published,
        "publishedRaw": pub_raw,
        "score": score,
        "severity": severity,
        "isKev": bool(kev_entry),
    }


# ── API fetchers ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=_CACHE_TTL, show_spinner=False)
def _fetch_kev_data() -> dict[str, dict]:
    """Fetch CISA KEV catalog, keyed by CVE ID with vendor/product metadata.

    Returns:
        Dict mapping CVE ID to a dict with vendorProject and product strings.
    """
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        return {
            v.get("cveID", ""): {
                "vendorProject": v.get("vendorProject", ""),
                "product": v.get("product", ""),
            }
            for v in resp.json().get("vulnerabilities", [])
        }
    except requests.RequestException as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return {}


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
    """Return (pub_start, pub_end) ISO strings (UTC) for NVD, anchored to WIB calendar days.

    The window starts at midnight WIB of the previous calendar day and ends now.
    We convert to UTC for the NVD API request because NVD expects UTC timestamps.
    Anchoring to WIB midnight (= UTC-7h of local midnight) ensures the full previous
    day's CVE batch is included when viewed from Jakarta time.
    """
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    now_wib = datetime.now(_WIB)
    yesterday_midnight_wib = (now_wib - timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    # Convert both ends to UTC for the NVD API
    pub_start_utc = yesterday_midnight_wib.astimezone(timezone.utc)
    pub_end_utc = now_wib.astimezone(timezone.utc)
    return pub_start_utc.strftime(fmt), pub_end_utc.strftime(fmt)


def _state_is_fresh() -> bool:
    """Return True if cached session state is within the cache TTL."""
    fetched_at = st.session_state.get("cve_fetched_at", 0)
    return (time.time() - fetched_at) < _CACHE_TTL


def _init_state() -> None:
    """Initialize (or reset) the CVE panel session state and fetch first page."""
    pub_start, pub_end = _time_window()
    kev_data = _fetch_kev_data()
    page = _fetch_nvd_page(pub_start, pub_end, start_index=0)

    st.session_state["cve_items"] = [_parse_nvd_item(i, kev_data) for i in page["items"]]
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

    kev_data = _fetch_kev_data()
    page = _fetch_nvd_page(pub_start, pub_end, start_index=start_index)

    if not page["error"]:
        new_items = [_parse_nvd_item(i, kev_data) for i in page["items"]]
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


def _card_html(v: dict, common_app: bool = False) -> str:
    """Build HTML for a single CVE card.

    Args:
        v: Parsed CVE dict from _parse_nvd_item.
        common_app: If True, render with a red highlight border/background.

    Returns:
        HTML string for the card.
    """
    cve_id = v["cveID"]
    vendor = v["vendorProject"]
    product = v["product"]
    vendor_product = f"{vendor} · {product}" if vendor and product else vendor or product or "—"

    badge = _severity_badge_html(v["score"], v["severity"])
    kev_tag = f" {_kev_badge_html()}" if v["isKev"] else ""

    time_str = v.get("timePublished", "")
    date_label = f'{v["datePublished"]} {time_str} WIB' if time_str else v["datePublished"]

    if common_app:
        border = "rgba(239,68,68,0.45)"
        bg = "rgba(239,68,68,0.07)"
    else:
        border = "rgba(255,255,255,0.08)"
        bg = "rgba(255,255,255,0.02)"

    return (
        f'<div style="border:1px solid {border};border-radius:8px;'
        f'padding:10px 12px;margin-bottom:8px;background:{bg};">'
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
        f'color:#6b7280;white-space:nowrap;" title="Waktu ditambahkan ke NVD (WIB)">{date_label}</span>'
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

    "Common" is treated as an independent boolean toggle — it is preserved
    across severity selection changes and never cleared by the ALL/severity logic.

    Rules:
    - If the user just selected ALL → keep ALL (+ Common if active).
    - If any individual severity is selected → remove ALL (+ keep Common).
    - If no severity remains selected → revert to ALL (+ keep Common).
    """
    selected: list[str] = list(st.session_state.get("cve_severity_pills") or [])
    prev: list[str] = list(st.session_state.get("cve_severity_pills_prev") or ["ALL"])

    newly_added = [s for s in selected if s not in prev]
    has_common_app = "Common" in selected
    severity_sel = [s for s in selected if s != "Common"]

    if "ALL" in newly_added:
        new_severity = ["ALL"]
    elif any(s in _SEVERITY_FILTERS for s in severity_sel):
        new_severity = [s for s in severity_sel if s != "ALL"]
    else:
        new_severity = ["ALL"]

    new_selection = (["Common"] if has_common_app else []) + new_severity
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
        f'color:#6b7280;">{total_nvd} total · NVD · since yesterday</span>'
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
            'No new CVEs published<br>since yesterday.'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Search bar ────────────────────────────────────────────────────────────
    st.markdown(
        """<style>
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button {
            background-color: #e02020 !important;
            border-color: #e02020 !important;
            border-radius: 8px !important;
            color: #fff !important;
            font-size: 1.05rem !important;
            line-height: 1 !important;
            padding: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            height: 38px !important;
            min-height: 38px !important;
            letter-spacing: 0 !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button:hover {
            background-color: #b91c1c !important;
            border-color: #b91c1c !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) button p {
            font-size: 1.05rem !important;
            line-height: 1 !important;
            margin: 0 !important;
        }
        div[data-testid="stPills"] button {
            font-size: 0.6rem !important;
            padding: 2px 8px !important;
            min-height: 0 !important;
            height: auto !important;
            line-height: 1.4 !important;
        }
        div[data-testid="column"]:has(button[key="cve_search_btn"]) {
            padding-top: 0 !important;
        }
        div[data-testid="stTextInput"] {
            margin-bottom: -12px !important;
        }
        div[data-testid="stPills"] {
            margin-top: 4px !important;
        }
        </style>""",
        unsafe_allow_html=True,
    )
    col_search, col_btn = st.columns([5, 1])
    with col_search:
        search_input = st.text_input(
            label="CVE search",
            placeholder="Search by CVE ID, product, or attack type…",
            label_visibility="collapsed",
            key="cve_search_input",
        )
    with col_btn:
        search_clicked = st.button("▶", key="cve_search_btn", use_container_width=True)

    if search_clicked:
        st.session_state["cve_search_query"] = search_input.strip().lower()

    if "cve_search_query" not in st.session_state:
        st.session_state["cve_search_query"] = ""

    search_query: str = st.session_state["cve_search_query"]

    # ── Severity + Common filter ──────────────────────────────────────────────
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
    common_app_only: bool = "Common" in active
    active_severity = active - {"Common"}
    if not active_severity:
        active_severity = {"ALL"}

    filtered = items if "ALL" in active_severity else [v for v in items if v["severity"] in active_severity]

    if common_app_only:
        filtered = [v for v in filtered if _is_common_app(v)]

    if search_query:
        filtered = [
            v for v in filtered
            if search_query in v["cveID"].lower()
            or search_query in v.get("vendorProject", "").lower()
            or search_query in v.get("product", "").lower()
            or search_query in v.get("description", "").lower()
        ]

    # ── CVE cards (fixed-height scrollable) ──────────────────────────────────
    if filtered:
        st.markdown(
            '<div style="height:320px;overflow-y:auto;padding-right:4px;">'
            + "".join(_card_html(v, _is_common_app(v)) for v in filtered)
            + "</div>",
            unsafe_allow_html=True,
        )
    else:
        unloaded = total_nvd - next_index
        if search_query:
            hint = " Try broadening your search or loading more results."
        elif unloaded > 0:
            hint = f" Try loading more — {unloaded} unloaded result{'s' if unloaded != 1 else ''} remaining."
        else:
            hint = ""
        st.markdown(
            f'<div style="height:320px;display:flex;align-items:center;justify-content:center;'
            f'font-family:\'JetBrains Mono\',monospace;font-size:0.75rem;color:#6b7280;'
            f'text-align:center;">'
            f'No CVEs match the current search or filter.{hint}'
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
