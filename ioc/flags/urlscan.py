"""Threat flag extraction from URLScan results."""
from __future__ import annotations

from .base import _flag, _days_since, _safe_int


def _flags_urlscan(us: dict) -> list[dict]:
    flags: list[dict] = []
    if not isinstance(us, dict) or not us:
        return flags

    verdicts = us.get("verdicts", {}) or {}
    overall = verdicts.get("overall", {}) or {}
    engines_v = verdicts.get("engines", {}) or {}
    result = us.get("result", {}) or {}
    page = us.get("page", {}) or {}

    # --- Verdict ---
    if overall.get("malicious"):
        flags.append(_flag(
            "URLSCAN_MALICIOUS_VERDICT",
            "URLScan overall verdict: MALICIOUS",
            "Confirmed malicious web content",
            "CRITICAL",
            ["TA0001", "T1566.002"],
            f"Score: {overall.get('score', '?')}",
            "URLScan",
        ))
    if engines_v.get("malicious"):
        eng_score = engines_v.get("score", 0)
        flags.append(_flag(
            "URLSCAN_ENGINE_MALICIOUS",
            f"URLScan threat engines: MALICIOUS (score {eng_score})",
            "Third-party engine consensus: malicious",
            "CRITICAL" if _safe_int(eng_score) >= 80 else "HIGH",
            ["TA0001", "T1566"],
            f"Engine score: {eng_score}",
            "URLScan",
        ))

    # --- Threat tags & brands ---
    v_tags = overall.get("tags") or []
    if "phishing" in [str(t).lower() for t in v_tags]:
        flags.append(_flag(
            "URLSCAN_PHISHING_TAG",
            "URLScan tagged as phishing",
            "Phishing site",
            "CRITICAL",
            ["TA0001", "T1566.002"],
            f"Tags: {v_tags}",
            "URLScan",
        ))
    if "malware" in [str(t).lower() for t in v_tags]:
        flags.append(_flag(
            "URLSCAN_MALWARE_TAG",
            "URLScan tagged as malware",
            "Malware hosting / distribution",
            "CRITICAL",
            ["TA0002", "T1204"],
            f"Tags: {v_tags}",
            "URLScan",
        ))

    v_brands = overall.get("brands") or []
    if v_brands:
        flags.append(_flag(
            "URLSCAN_BRAND_IMPERSONATION",
            f"Brand impersonation detected: {', '.join(str(b) for b in v_brands[:3])}",
            "Brand spoofing / phishing lure",
            "HIGH",
            ["T1566.002", "T1036"],
            f"Brands targeted: {v_brands}",
            "URLScan",
        ))

    # --- Processed result flags ---
    processed = us.get("result", {})
    if isinstance(processed, dict):
        data_obj = processed.get("data", {}) if isinstance(processed.get("data"), dict) else {}
        requests_list = data_obj.get("requests") or processed.get("http") or []

        # Redirect chain
        if isinstance(requests_list, list) and len(requests_list) > 0:
            seen: set[str] = set()
            chain: list[str] = []
            for tx in requests_list:
                if not isinstance(tx, dict):
                    continue
                req = tx.get("request", {}) if isinstance(tx.get("request"), dict) else {}
                res = tx.get("response", {}) if isinstance(tx.get("response"), dict) else {}
                u = req.get("url")
                if isinstance(u, str) and u and u not in seen:
                    seen.add(u)
                    chain.append(u)
                loc = res.get("location") or res.get("redirect") or res.get("redirectURL")
                if isinstance(loc, str) and loc and loc not in seen:
                    seen.add(loc)
                    chain.append(loc)
            n_redir = max(len(chain) - 1, 0)
            if n_redir >= 5:
                flags.append(_flag(
                    "URLSCAN_LONG_REDIRECT_CHAIN",
                    f"Long redirect chain: {n_redir} hops",
                    "Multi-hop redirect evasion",
                    "HIGH",
                    ["T1027", "T1036"],
                    f"{n_redir} hops",
                    "URLScan",
                ))
            elif n_redir >= 2:
                flags.append(_flag(
                    "URLSCAN_REDIRECT_CHAIN",
                    f"Redirect chain: {n_redir} hops",
                    "Redirect chain — potential evasion",
                    "MEDIUM",
                    ["T1027"],
                    f"{n_redir} hops",
                    "URLScan",
                ))

        # Suspicious POST / credential harvest
        suspicious_post_hints = ("/login", "/auth", "/verify", "/submit", "/signin", "/password")
        form_posts = []
        downloads = []
        encoded_hits = []
        import re as _re
        for tx in (requests_list if isinstance(requests_list, list) else []):
            if not isinstance(tx, dict):
                continue
            req = tx.get("request", {}) if isinstance(tx.get("request"), dict) else {}
            res = tx.get("response", {}) if isinstance(tx.get("response"), dict) else {}
            req_url = req.get("url") or ""
            method = (req.get("method") or "").upper()
            if method == "POST" and any(h in req_url.lower() for h in suspicious_post_hints):
                if req_url not in form_posts:
                    form_posts.append(req_url)
            ctype = (res.get("contentType") or res.get("mimeType") or "").lower()
            disp = (res.get("contentDisposition") or "").lower()
            if any(k in ctype for k in ("x-msdownload", "octet-stream", "x-dosexec")):
                if req_url not in downloads:
                    downloads.append(req_url)
            elif "attachment" in disp and req_url:
                if req_url not in downloads:
                    downloads.append(req_url)
            serialized = str(tx)
            if not encoded_hits:
                if _re.search(r"(?:[A-Za-z0-9+/]{80,}={0,2})", serialized):
                    encoded_hits.append("base64 blob")
                elif any(k in serialized.lower() for k in ("eval(", "atob(", "unescape(")):
                    encoded_hits.append("obfuscated JS")

        if form_posts:
            flags.append(_flag(
                "URLSCAN_CREDENTIAL_HARVEST_FORM",
                f"Credential-harvest form POST detected ({len(form_posts)} target(s))",
                "Credential phishing form",
                "CRITICAL",
                ["T1566.002", "T1056.003"],
                f"POST targets: {form_posts[:2]}",
                "URLScan",
            ))
        if downloads:
            flags.append(_flag(
                "URLSCAN_MALWARE_DOWNLOAD",
                f"Executable/binary served for download ({len(downloads)} file(s))",
                "Malware delivery via web",
                "CRITICAL",
                ["TA0002", "T1105", "T1566.002"],
                f"Download URLs: {downloads[:2]}",
                "URLScan",
            ))
        if encoded_hits:
            flags.append(_flag(
                "URLSCAN_OBFUSCATED_PAYLOAD",
                f"Obfuscated/encoded payload in HTTP transactions: {encoded_hits[0]}",
                "JavaScript obfuscation / drive-by exploit",
                "HIGH",
                ["T1027", "T1059.007"],
                f"Pattern: {encoded_hits[0]}",
                "URLScan",
            ))

        # TLS cert anomalies
        tls = processed.get("tls") or processed.get("certificate") or {}
        if isinstance(tls, list) and tls:
            tls = tls[0]
        if isinstance(tls, dict):
            valid_from = tls.get("validFrom") or tls.get("valid_from")
            if valid_from:
                age = _days_since(valid_from)
                if age is not None and age <= 14:
                    flags.append(_flag(
                        "URLSCAN_CERT_RECENTLY_ISSUED",
                        f"TLS certificate issued {age} days ago",
                        "Newly created infrastructure — common in phishing",
                        "MEDIUM",
                        ["T1583.003"],
                        f"Certificate age: {age} days",
                        "URLScan",
                    ))

    return flags
