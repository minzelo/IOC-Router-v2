"""AI output panel — threat analysis, AI description, share text generation."""
from __future__ import annotations

import base64
import re
from datetime import datetime
from urllib.parse import quote_plus, urlsplit, urlunsplit

import streamlit as st
import streamlit.components.v1 as components

from ioc.flags import extract_ioc_flags, flags_to_ai_context, flags_summary_for_evidence
from ioc.threat_analysis import analyzeThreat
from providers.gemini import gemini_generate, gemini_list_models
from providers.groq import groq_generate
from core.geo import fetch_geo_ip_api, fetch_nominatim


def _clear_ai_outputs() -> None:
    """Clear all AI-generated session state outputs."""
    for _k in ("ai_short", "ai_desc", "ai_threat_analysis", "ai_ioc_links"):
        if _k in st.session_state:
            del st.session_state[_k]


def render_ai_panel(run_results: dict, settings) -> None:
    """Render the AI output panel (left split) for threat analysis and AI description.

    Args:
        run_results: The full run_results dict from session state.
        settings: The Settings object with API keys and model config.
    """
    items = run_results["items"]
    vt_results = run_results["vt"]
    urlscan_results = run_results["urlscan"]
    abuse_results = run_results["abuse"]
    tf_results = run_results["tf"]
    mb_results = run_results["mb"]
    shodan_results = run_results["shodan"]
    dnsd_results = run_results.get("dnsd", {})
    ha_results = run_results.get("ha", {})

    st.subheader("AI-Output")
    if not settings.gemini_key:
        st.info("Gemini API key not set. Set the env var: GEMINI_KEY")
    ai_provider = st.selectbox("AI Provider", ["Gemini", "Groq"], key="ai_provider")
    scope = st.selectbox("Scope", ["All IOCs", "Selected IOC(s)"], index=0)
    tone = st.selectbox("Tone", ["SOC L1 concise", "More formal"])
    use_only_evidence = st.checkbox("Use only evidence shown (no guessing)", value=True)
    sanitize = st.checkbox("Sanitize sensitive data", value=True)
    if ai_provider == "Gemini":
        if st.button("Fetch Gemini Models"):
            models, err = gemini_list_models(settings)
            st.session_state["gemini_models"] = models
            st.session_state["gemini_models_err"] = err
        if st.session_state.get("gemini_models_err"):
            st.code(st.session_state["gemini_models_err"])
        models = st.session_state.get("gemini_models", [])
        if models:
            default_model = settings.gemini_model or "gemini-2.5-flash"
            default_index = models.index(default_model) if default_model in models else 0
            st.selectbox("Gemini Model (from list)", models, index=default_index, key="gemini_model_select")
            settings.gemini_model = st.session_state.get("gemini_model_select") or settings.gemini_model
        settings.gemini_api_version = "v1"
    selections = [ioc.value for ioc in items]
    selected = st.multiselect("Select IOC(s)", selections) if scope == "Selected IOC(s)" else selections

    def _clip(value: object, limit: int = 600) -> str:
        text = str(value)
        if len(text) <= limit:
            return text
        return text[:limit] + "...(truncated)"

    def _vt_url_id(url: str) -> str:
        raw_bytes = str(url or "").encode("utf-8")
        return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

    def _ha_text_payload(val: str) -> object:
        ha = ha_results.get(val, {})
        if not ha:
            return "No data"
        message = str(ha.get("message") or "").strip()
        if message in {
            "Not supported by Hybrid Analysis API",
            "Hybrid Analysis does not analyze email indicators.",
            "No results found",
        }:
            return "No data"
        return ha

    def _provider_has_data(provider_name: str, ioc) -> bool:
        value = ioc.value
        if provider_name == "virustotal":
            vt = vt_results.get(value, {}) or {}
            return bool(vt and (vt.get("attributes") or vt.get("stats") or vt.get("id")))
        if provider_name == "urlscan":
            us = urlscan_results.get(value, {}) or {}
            return bool(us and (us.get("uuid") or us.get("result") or us.get("page") or us.get("task")))
        if provider_name == "abuseipdb":
            ab = abuse_results.get(value, {}) or {}
            return bool(ab and not ab.get("error"))
        if provider_name == "threatfox":
            tf = tf_results.get(value, {}) or {}
            return bool(tf.get("query_status") == "ok" and tf.get("data"))
        if provider_name == "malwarebazaar":
            mb = mb_results.get(value, {}) or {}
            return bool(mb.get("query_status") == "ok" and mb.get("data"))
        if provider_name == "shodan":
            sh = shodan_results.get(value, {}) or {}
            return bool(sh and not sh.get("error") and (sh.get("summary") or sh.get("ports") or sh.get("queriedIp")))
        if provider_name == "dnsdumpster":
            dd = dnsd_results.get(value, {}) or {}
            return bool(dd and not dd.get("error") and (dd.get("soc_summary") or dd.get("dns_records") or dd.get("host_records")))
        if provider_name == "hybrid_analysis":
            ha = ha_results.get(value, {}) or {}
            if not ha:
                return False
            message = str(ha.get("message") or "").strip()
            if message in {
                "Not supported by Hybrid Analysis API",
                "Hybrid Analysis does not analyze email indicators.",
                "No results found",
            }:
                return False
            return bool(
                ha.get("verdict")
                or ha.get("threat_score")
                or ha.get("malware_family")
                or (ha.get("network_ioc") or {}).get("domains")
                or (ha.get("network_ioc") or {}).get("ips")
                or any((ha.get("behavior") or {}).values())
            )
        return False

    def _build_ioc_links(selected_values: list[str]) -> str:
        link_lines: list[str] = []
        for ioc in items:
            if ioc.value not in selected_values:
                continue

            links: list[str] = []
            value = ioc.value
            ioc_type = ioc.type

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("virustotal", ioc):
                if ioc_type == "url":
                    links.append(f"VirusTotal: https://www.virustotal.com/gui/url/{_vt_url_id(value)}")
                elif ioc_type == "ip":
                    links.append(f"VirusTotal: https://www.virustotal.com/gui/ip-address/{value}")
                elif ioc_type == "domain":
                    links.append(f"VirusTotal: https://www.virustotal.com/gui/domain/{value}")
                elif ioc_type == "hash":
                    links.append(f"VirusTotal: https://www.virustotal.com/gui/file/{value}")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("urlscan", ioc):
                if ioc_type == "ip":
                    links.append(f"urlscan: https://urlscan.io/ip/{value}")
                elif ioc_type == "domain":
                    links.append(f"urlscan: https://urlscan.io/domain/{value}")
                elif ioc_type == "url":
                    links.append(f"urlscan: https://urlscan.io/search/#q={quote_plus(value)}")
                elif ioc_type == "hash":
                    links.append(f"urlscan: https://urlscan.io/search/#q=hash:{quote_plus(value)}")

            if ioc_type == "ip" and _provider_has_data("abuseipdb", ioc):
                links.append(f"AbuseIPDB: https://www.abuseipdb.com/check/{value}")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("threatfox", ioc):
                links.append(f"ThreatFox: https://threatfox.abuse.ch/browse.php?search={quote_plus(value)}")

            if ioc_type == "hash" and _provider_has_data("malwarebazaar", ioc):
                links.append(f"MalwareBazaar: https://bazaar.abuse.ch/sample/{value}/")

            if ioc_type in {"ip", "domain"} and _provider_has_data("shodan", ioc):
                if ioc_type == "ip":
                    links.append(f"Shodan: https://www.shodan.io/host/{value}")
                else:
                    links.append(f"Shodan: https://www.shodan.io/domain/{value}")

            if ioc_type in {"domain", "url"} and _provider_has_data("dnsdumpster", ioc):
                _dd_target = dnsd_results.get(value, {}).get("queriedDomain") or value
                links.append(f"DNSDumpster: https://dnsdumpster.com/results/{_dd_target}/")

            if ioc_type in {"ip", "domain", "url", "hash"} and _provider_has_data("hybrid_analysis", ioc):
                if ioc_type == "hash":
                    links.append(f"Hybrid Analysis: https://hybrid-analysis.com/sample/{value}")
                else:
                    links.append(f"Hybrid Analysis: https://hybrid-analysis.com/search?query={quote_plus(value)}")

            if links:
                link_lines.append(f"Source: {value} ({ioc_type})")
                link_lines.extend(f"- {line}" for line in links)

        return "\n".join(link_lines)

    def _build_prompt(selected_values: list[str], section: str) -> str:
        lines = []
        lines.append(f"You are a SOC assistant. Generate ONLY the {section} section.")
        if section == "SHORT":
            lines.append("Output 2-4 sentences.")
        else:
            lines.append("Output a concise ticket description in 4-6 sentences.")
            lines.append("Write exactly one paragraph.")
            lines.append("Do not truncate output. Always finish with complete sentences.")
            lines.append("Include a concluding assessment sentence based on all evidence.")
            lines.append("Do not mention remediation or recommended actions.")
        lines.append("Return plain text only, no bullets.")
        lines.append("Use only the evidence provided. If evidence is insufficient, say 'inconclusive' and recommend next checks.")
        lines.append(f"Tone: {tone}.")
        if sanitize:
            lines.append("Sanitize sensitive data where possible.")
        # Shared process/action context — always included when values are present
        _ctx_device_action = "" if (st.session_state.get("device_action") or "") in ("", "None") else (st.session_state.get("device_action") or "")
        _ctx_parent = st.session_state.get("parent_process") or ""
        _ctx_child = st.session_state.get("child_process") or ""
        _has_process_ctx = bool(_ctx_device_action or _ctx_parent or _ctx_child)
        if _has_process_ctx:
            lines.append("Additional endpoint context (use if present, do not invent):")
            if _ctx_device_action:
                lines.append(f"  Device Action: {_ctx_device_action} — incorporate this to indicate whether the activity was blocked/prevented or allowed.")
            if _ctx_parent:
                lines.append(f"  Parent Process: {_ctx_parent} — the process that spawned the suspicious activity.")
            if _ctx_child:
                lines.append(f"  Child Process: {_ctx_child} — the process spawned as a result of the activity.")

        if section == "DESCRIPTION":
            host_ip_value = st.session_state.get("host_ip") or st.session_state.get("source_ip") or "N/A"
            raw_log_value = (st.session_state.get("raw_log") or "").strip()
            lines.append("Use the available context fields below as part of the description narrative.")
            lines.append("Map them as follows: what/how=Alert Name, who=Host and Host IP (internal IP), when=Time Detected, where=Artifacts/IOCs.")
            lines.append("Treat Host IP as the affected internal IP. If an IOC is an IP, treat it as an external IP that may represent either the source or destination of the connection.")
            lines.append("Use Raw Log only as supporting context for the description. Do not invent fields that are not explicitly present.")
            lines.append("If a context field is present, incorporate it naturally into the paragraph.")
            lines.append(f"Context what/how: {st.session_state.get('alert_name') or 'N/A'}")
            lines.append(f"Context who host: {st.session_state.get('host') or 'N/A'}")
            lines.append(f"Context who host_ip (internal): {host_ip_value}")
            lines.append(f"Context when: {st.session_state.get('time_detected') or 'N/A'}")
            where_values = [f"{ioc.value} ({ioc.type})" for ioc in items if ioc.value in selected_values]
            lines.append(f"Context where artifacts: {', '.join(where_values) if where_values else 'N/A'}")
            lines.append(f"Context raw_log: {raw_log_value if raw_log_value else 'N/A'}")
        lines.append("Evidence bundle:")
        for ioc in items:
            if ioc.value not in selected_values:
                continue
            lines.append(f"- IOC: {ioc.value} ({ioc.type})")
            lines.append(f"  VT: {_clip(vt_results.get(ioc.value, {}))}")
            lines.append(f"  urlscan: {_clip(urlscan_results.get(ioc.value, {}))}")
            lines.append(f"  AbuseIPDB: {_clip(abuse_results.get(ioc.value, {}))}")
            lines.append(f"  ThreatFox: {_clip(tf_results.get(ioc.value, {}))}")
            lines.append(f"  MalwareBazaar: {_clip(mb_results.get(ioc.value, {}))}")
            lines.append(f"  Shodan: {_clip(shodan_results.get(ioc.value, {}))}")
            lines.append(f"  DNSDumpster: {_clip(dnsd_results.get(ioc.value, {}))}")
            lines.append(f"  Hybrid Analysis: {_clip(_ha_text_payload(ioc.value))}")
            # Inject structured threat flags as additional context
            _ioc_flags = extract_ioc_flags(
                ioc.value, ioc.type,
                vt_results.get(ioc.value, {}) or {},
                urlscan_results.get(ioc.value, {}) or {},
                abuse_results.get(ioc.value, {}) or {},
                tf_results.get(ioc.value, {}) or {},
                mb_results.get(ioc.value, {}) or {},
                shodan_results.get(ioc.value, {}) or {},
                dnsd_results.get(ioc.value, {}) or {},
                ha_results.get(ioc.value, {}) or {},
            )
            if _ioc_flags:
                lines.append(f"  Threat Flags:\n{flags_to_ai_context(_ioc_flags)}")
        return "\n".join(lines)

    def _obfuscate_domains_and_urls(text: str) -> str:
        raw = str(text or "")

        def _obfuscate_host(host: str) -> str:
            return host.replace(".", "[.]")

        # Obfuscate host part in full URLs first.
        url_pattern = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)

        def _url_repl(match: re.Match) -> str:
            token = match.group(0)
            trailing = ""
            while token and token[-1] in ".,;:!?)]}\"'":
                trailing = token[-1] + trailing
                token = token[:-1]
            try:
                parsed = urlsplit(token)
                if not parsed.netloc:
                    return match.group(0)
                obf_netloc = _obfuscate_host(parsed.netloc)
                rebuilt = urlunsplit((parsed.scheme, obf_netloc, parsed.path, parsed.query, parsed.fragment))
                return rebuilt + trailing
            except Exception:
                return match.group(0)

        out = url_pattern.sub(_url_repl, raw)

        # Obfuscate bare domains.
        domain_pattern = re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
            re.IGNORECASE,
        )
        return domain_pattern.sub(lambda m: _obfuscate_host(m.group(0)), out)

    def _build_analysis_summary(selected_values: list[str]) -> dict:
        picked = set(selected_values or [])
        evidence = {
            "attack_prevented": False,
            "scanning_or_recon": False,
            "phishing_or_social_eng": False,
            "exploit_attempt": False,
            "malware_executed": False,
            "c2_connection": False,
            "privilege_escalation": False,
            "lateral_movement": False,
            "persistence_mechanism": False,
            "data_exfiltration": False,
            "service_disruption_or_encryption": False,
        }
        notes: list[str] = []
        tactics = set()

        def _add_note(text: str) -> None:
            if text and text not in notes and len(notes) < 12:
                notes.append(text)

        for ioc in items:
            if picked and ioc.value not in picked:
                continue
            _vt  = vt_results.get(ioc.value, {}) or {}
            us   = urlscan_results.get(ioc.value, {}) or {}
            ab   = abuse_results.get(ioc.value, {}) or {}
            tf   = tf_results.get(ioc.value, {}) or {}
            mb   = mb_results.get(ioc.value, {}) or {}
            sh   = shodan_results.get(ioc.value, {}) or {}
            dnsd = dnsd_results.get(ioc.value, {}) or {}
            ha   = ha_results.get(ioc.value, {}) or {}

            # --- Derive evidence from flags ---
            ioc_flags = extract_ioc_flags(
                ioc.value, ioc.type, _vt, us, ab, tf, mb, sh, dnsd, ha
            )
            flag_summary = flags_summary_for_evidence(ioc_flags)
            for k, v in flag_summary["evidence"].items():
                if v:
                    evidence[k] = True
            for t in flag_summary["mitre_tactics"]:
                tactics.add(t)
            for n in flag_summary["notes"]:
                _add_note(n)

            # --- Keep original signals for backward compat ---
            verdicts = us.get("verdicts", {}) if isinstance(us.get("verdicts"), dict) else {}
            if verdicts.get("phishing"):
                evidence["phishing_or_social_eng"] = True
                tactics.add("TA0001")
            if verdicts.get("malicious"):
                evidence["attack_prevented"] = True

            tf_rows = tf.get("data", []) if isinstance(tf.get("data"), list) else []
            for row in tf_rows:
                if not isinstance(row, dict):
                    continue
                tt = str(row.get("threat_type") or "").lower()
                if "exploit" in tt:
                    evidence["exploit_attempt"] = True
                    tactics.add("TA0001")

            ha_behavior = ha.get("behavior", {}) if isinstance(ha.get("behavior"), dict) else {}
            ha_mitre = ha.get("mitre_attack", []) if isinstance(ha.get("mitre_attack"), list) else []
            if ha_behavior.get("persistence"):
                evidence["persistence_mechanism"] = True
                tactics.add("TA0003")
            for technique in ha_mitre:
                if isinstance(technique, str) and technique.strip():
                    tactics.add(technique.strip())

        if evidence["phishing_or_social_eng"] or evidence["exploit_attempt"] or evidence["scanning_or_recon"]:
            evidence["attack_prevented"] = evidence["attack_prevented"] or not (evidence["malware_executed"] or evidence["c2_connection"])

        return {
            "evidence": evidence,
            "mitre_tactics": sorted(tactics),
            "risk_notes": notes[:8],
            "asset_criticality": "critical" if st.session_state.get("critical_asset") else "standard",
            "device_action": "" if (st.session_state.get("device_action", "") or "") in ("", "None") else st.session_state.get("device_action", ""),
        }

    def _to_bold_unicode(text: str) -> str:
        out = []
        for ch in str(text):
            if "A" <= ch <= "Z":
                out.append(chr(ord(ch) - ord("A") + 0x1D400))
            elif "a" <= ch <= "z":
                out.append(chr(ord(ch) - ord("a") + 0x1D41A))
            elif "0" <= ch <= "9":
                out.append(chr(ord(ch) - ord("0") + 0x1D7CE))
            else:
                out.append(ch)
        return "".join(out)

    def _derive_threat_category(ev: dict) -> str:
        if ev.get("data_exfiltration") or ev.get("service_disruption_or_encryption"):
            return "Impact/Exfiltration"
        if ev.get("persistence_mechanism"):
            return "Persistence Mechanism"
        if ev.get("lateral_movement"):
            return "Lateral Movement Technique"
        if ev.get("privilege_escalation"):
            return "Privilege Escalation Technique"
        if ev.get("malware_executed") or ev.get("c2_connection"):
            return "Execution and C2"
        if ev.get("phishing_or_social_eng"):
            return "Phishing/Social Engineering"
        if ev.get("exploit_attempt"):
            return "Exploitation Attempt"
        if ev.get("scanning_or_recon"):
            return "Reconnaissance/Scanning"
        return "Exposure/Misconfiguration"

    def _derive_attack_status(ev: dict) -> str:
        has_active = any(
            [
                ev.get("malware_executed"),
                ev.get("c2_connection"),
                ev.get("privilege_escalation"),
                ev.get("lateral_movement"),
                ev.get("persistence_mechanism"),
                ev.get("data_exfiltration"),
                ev.get("service_disruption_or_encryption"),
            ]
        )
        has_attempt = any([ev.get("scanning_or_recon"), ev.get("phishing_or_social_eng"), ev.get("exploit_attempt")])
        if has_active:
            return "Active"
        if ev.get("attack_prevented") and has_attempt:
            return "Prevented/Blocked"
        if has_attempt:
            return "Attempted"
        return "No active attack evidence"

    def _build_reason_fallbacks(summary: dict, state: str, level: str) -> list[str]:
        ev = summary.get("evidence", {}) if isinstance(summary, dict) else {}
        if not isinstance(ev, dict):
            ev = {}
        category = _derive_threat_category(ev)
        status = _derive_attack_status(ev)
        criticality = str(summary.get("asset_criticality", "standard")).lower()

        state_reason_map = {
            "Impact": "attack progression has reached business impact",
            "Persistence": "attack progression indicates a sustained foothold",
            "Lateral Movement": "attack progression indicates movement between hosts",
            "Privilege Escalation": "attack progression indicates privilege elevation",
            "Compromise": "attack progression has moved beyond attempt to full compromise",
            "Intrusion Attempt": "attack progression is still at the attempt stage",
            "Exposure": "no active attack progression observed",
        }
        r1 = f"Threat State {state} selected because {state_reason_map.get(state, 'observed evidence progression')}."
        r2 = f"Threat Category {category} derived from techniques observed in the evidence."
        r3 = f"Attack Status {status} with asset criticality {criticality} yields Threat Level {level}."
        return [r1, r2, r3]

    def _format_threat_text_for_box(raw_text: str, summary: dict) -> str:
        lines = [ln.strip() for ln in str(raw_text or "").splitlines() if ln.strip()]
        state = ""
        level = ""
        risk_label = ""
        reasons: list[str] = []

        for ln in lines:
            low = ln.lower()
            if low.startswith("- threat state:") or low.startswith("threat state:"):
                state = ln.split(":", 1)[1].strip() if ":" in ln else state
            elif low.startswith("- threat level:") or low.startswith("threat level:"):
                level = ln.split(":", 1)[1].strip() if ":" in ln else level
            elif low.startswith("- risk label:") or low.startswith("risk label:"):
                risk_label = ln.split(":", 1)[1].strip() if ":" in ln else risk_label
            elif low.startswith("* ") or low.startswith("- ") or low.startswith("• "):
                candidate = ln.lstrip("-*• ").strip()
                if candidate and not candidate.lower().startswith("threat ") and not candidate.lower().startswith("risk label") and not candidate.lower().startswith("reasons"):
                    reasons.append(candidate)

        if not state:
            # Fallback if AI missed structured line.
            for s in ["Impact", "Persistence", "Lateral Movement", "Privilege Escalation", "Compromise", "Intrusion Attempt", "Exposure"]:
                if s.lower() in str(raw_text).lower():
                    state = s
                    break
        if not level:
            for lv in ["Very High", "High", "Medium", "Low"]:
                if lv.lower() in str(raw_text).lower():
                    level = lv
                    break
        reasons = _build_reason_fallbacks(summary, state or "-", level or "-")
        if not risk_label:
            risk_label = "-"

        emoji_map = {
            "Low": "🟢",
            "Medium": "🟡",
            "High": "🟠",
            "Very High": "🔴",
        }
        emoji = emoji_map.get(level, "")
        state_disp = _to_bold_unicode(state or "-")
        level_disp = _to_bold_unicode(level or "-")

        out = [
            f"- Threat State: {state_disp}",
            f"- Threat Level: {emoji} {level_disp}".rstrip(),
            f"- Risk Label: {risk_label}",
            "- Reasons:",
        ]
        for r in reasons[:3]:
            out.append(f"  * {r}")
        return "\n".join(out)

    current_ai_signature = (
        ai_provider,
        settings.gemini_model if ai_provider == "Gemini" else "llama-3.1-8b-instant",
    )
    last_ai_signature = st.session_state.get("ai_signature_last")
    if last_ai_signature and last_ai_signature != current_ai_signature:
        _clear_ai_outputs()
    st.session_state["ai_signature_last"] = current_ai_signature

    if st.button("Generate AI Output", type="primary") or st.session_state.get("auto_generate_ai"):
        if not selected:
            st.warning("Select at least 1 IOC.")
        elif ai_provider == "Gemini" and not settings.gemini_key:
            st.warning("GEMINI_KEY belum di-set.")
        elif ai_provider == "Groq" and not settings.groq_key:
            st.warning("GROQ_KEY belum di-set.")
        else:
            st.session_state["auto_generate_ai"] = False
            short_prompt = _build_prompt(selected, "SHORT")
            desc_prompt = _build_prompt(selected, "DESCRIPTION")
            if use_only_evidence:
                short_prompt = "STRICT: Do not invent data. " + short_prompt
                desc_prompt = "STRICT: Do not invent data. " + desc_prompt
            if ai_provider == "Gemini":
                short_out, short_err = gemini_generate(short_prompt, settings, use_backup=False)
                desc_out, desc_err = gemini_generate(desc_prompt, settings, use_backup=False)
            else:
                short_out, short_err = groq_generate(short_prompt, settings)
                desc_out, desc_err = groq_generate(desc_prompt, settings)
            if not short_out:
                st.error("AI Short Result gagal dibuat.")
                if short_err:
                    st.code(short_err)
            if not desc_out:
                st.error("AI Description gagal dibuat.")
                if desc_err:
                    st.code(desc_err)
            if short_out:
                short_clean = short_out.strip()
                if short_clean.upper().startswith("SHORT:"):
                    short_clean = short_clean.split(":", 1)[1].strip()
                st.session_state["ai_short"] = short_clean
            if desc_out:
                desc_clean = desc_out.strip()
                if desc_clean.upper().startswith("DESCRIPTION:"):
                    desc_clean = desc_clean.split(":", 1)[1].strip()
                desc_clean = re.sub(r"\s+", " ", desc_clean).strip()
                desc_clean = _obfuscate_domains_and_urls(desc_clean)
                st.session_state["ai_desc"] = f"#Description: {desc_clean}" if desc_clean else "#Description:"
                st.session_state["ai_ioc_links"] = _build_ioc_links(selected)

    def _build_share_text(selected_values: list[str]) -> str:
        lines: list[str] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("=== IOC Router — Analysis Report ===")
        lines.append(f"Generated : {now}")
        lines.append("")

        # ── Summary ──────────────────────────────────────────────────────
        run_summary = st.session_state["run_results"].get("summary", {})
        lines.append("--- SUMMARY ---")
        lines.append(
            f"Total: {run_summary.get('total', 0)}  |  "
            f"Malicious: {run_summary.get('malicious', 0)}  |  "
            f"Suspicious: {run_summary.get('suspicious', 0)}  |  "
            f"Unknown: {run_summary.get('unknown', 0)}"
        )
        lines.append("")

        # ── IOC Results ──────────────────────────────────────────────────
        lines.append("--- IOC RESULTS ---")
        run_rows = st.session_state["run_results"].get("rows", [])
        for idx, row in enumerate(run_rows, 1):
            artifact = row.get("Artifact", "")
            if artifact not in selected_values:
                continue
            lines.append(f"{idx}. {artifact} [{row.get('Type', '')}]")
            lines.append(f"   Verdict   : {row.get('Verdict', '')} ({row.get('Confidence', '')} confidence)")
            lines.append(f"   Evidence  : {row.get('Primary Evidence', '')}")
            lines.append(f"   Sources   : {row.get('Sources', '')}")
        lines.append("")

        # ── Threat Analysis ───────────────────────────────────────────────
        _ta_sum    = _build_analysis_summary(selected_values)
        _ta_result = analyzeThreat(_ta_sum)
        _ta_state  = _ta_result.get("threat_state", "Exposure")
        _ta_level  = _ta_result.get("threat_level", "Low")
        _ta_label  = _ta_result.get("risk_level_label", "")
        _ta_mitre  = _ta_result.get("mitre_alignment", [])
        _ta_reasons = _ta_result.get("reasons", [])
        _emoji_map = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Very High": "🔴"}
        lines.append("--- THREAT ANALYSIS ---")
        _da = st.session_state.get("device_action", "")
        if _da:
            lines.append(f"Device Action : {_da}")
        lines.append(f"Threat State : {_ta_state}")
        lines.append(f"Threat Level : {_emoji_map.get(_ta_level, '')} {_ta_level}".rstrip())
        lines.append(f"Risk Label   : {_ta_label or '—'}")
        if _ta_reasons:
            lines.append("Reasons:")
            for _r in _ta_reasons:
                lines.append(f"  * {_r}")
        _tactic_ids = [t for t in _ta_mitre if t.startswith("TA")]
        if _tactic_ids:
            lines.append(f"MITRE ATT&CK : {', '.join(_tactic_ids)}")
        lines.append("")

        # ── Infrastructure ───────────────────────────────────────────────
        _infra_blocks: list[str] = []
        for ioc in items:
            if ioc.value not in selected_values:
                continue
            if ioc.type not in ("ip", "domain"):
                continue

            _vt_a = (vt_results.get(ioc.value) or {}).get("attributes") or {}
            _ab   = abuse_results.get(ioc.value) or {}
            _sh   = shodan_results.get(ioc.value) or {}

            # Resolve target IP for geo lookup
            _geo_target: str | None = None
            if ioc.type == "ip":
                _geo_target = ioc.value
            else:
                _sh_ips = _sh.get("queriedIps") or []
                _geo_target = _sh_ips[0] if _sh_ips else _sh.get("queriedIp")

            # ip-api.com (cached — no extra network call if already fetched)
            _geo: dict = fetch_geo_ip_api(_geo_target) if _geo_target else {}

            # Nominatim reverse geocode (cached)
            _lat = _geo.get("lat")
            _lon = _geo.get("lon")
            _nom: dict = fetch_nominatim(_lat, _lon) if _lat is not None and _lon is not None else {}
            _nom_addr: dict = _nom.get("address") or {}

            # ── ASN (VT preferred)
            _asn_num   = _vt_a.get("asn")
            _asn_owner = _vt_a.get("as_owner")
            _asn_geo   = _geo.get("as")  # e.g. "AS150984 PT Fitrah Marina Sukses"
            if _asn_num and _asn_owner:
                _asn_str = f"AS{_asn_num} — {_asn_owner}"
            elif _asn_num:
                _asn_str = f"AS{_asn_num}"
            elif _asn_geo:
                _asn_str = _asn_geo
            else:
                _asn_str = None

            # ── Location: build richest possible string
            # City from ip-api or Nominatim
            _city = (
                _geo.get("city")
                or _nom_addr.get("city")
                or _nom_addr.get("town")
                or _nom_addr.get("village")
            )
            # Region/state
            _region = (
                _geo.get("regionName")
                or _nom_addr.get("state")
            )
            # Country
            _country = (
                _geo.get("country")
                or _nom_addr.get("country")
                or _vt_a.get("country")
            )
            _cc = (
                _geo.get("countryCode")
                or _ab.get("countryCode")
                or _vt_a.get("country")
            )
            # Postal code
            _postal = _geo.get("zip") or _nom_addr.get("postcode")
            # Continent (VT)
            _continent = _vt_a.get("continent")
            # RIR (VT)
            _rir = _vt_a.get("regional_internet_registry")
            # Coordinates
            _coords = f"{_lat}, {_lon}" if _lat is not None and _lon is not None else None

            # Compose location string: "City, Region, Country (CC)"
            _loc_parts = [p for p in [_city, _region, _country] if p]
            _loc_str = ", ".join(dict.fromkeys(_loc_parts)) or None
            if _loc_str and _cc and f"({_cc})" not in _loc_str:
                _loc_str = f"{_loc_str} ({_cc})"

            # ── ISP / Org
            _isp = _ab.get("isp") or _geo.get("isp")
            _org = _geo.get("org")
            _usage = _ab.get("usageType")

            block_lines = [f"  [{ioc.value}]"]
            if _asn_str:
                block_lines.append(f"    ASN         : {_asn_str}")
            if _rir:
                block_lines.append(f"    RIR         : {_rir}")
            if _loc_str:
                block_lines.append(f"    Location    : {_loc_str}")
            if _postal:
                block_lines.append(f"    Postal Code : {_postal}")
            if _continent:
                block_lines.append(f"    Continent   : {_continent}")
            if _coords:
                block_lines.append(f"    Coordinates : {_coords}")
            if _isp:
                block_lines.append(f"    ISP         : {_isp}")
            if _org and _org != _isp:
                block_lines.append(f"    Org         : {_org}")
            if _usage:
                block_lines.append(f"    Usage Type  : {_usage}")

            if len(block_lines) > 1:
                _infra_blocks.append("\n".join(block_lines))

        if _infra_blocks:
            lines.append("--- INFRASTRUCTURE ---")
            for blk in _infra_blocks:
                lines.append(blk)
            lines.append("")

        # ── AI Description ────────────────────────────────────────────────
        _desc = st.session_state.get("ai_desc", "").strip()
        if _desc:
            _desc_clean = re.sub(r"^#?Description:\s*", "", _desc, flags=re.IGNORECASE).strip()
            lines.append("--- DESCRIPTION ---")
            lines.append(_desc_clean)
            lines.append("")

        # ── Sources ───────────────────────────────────────────────────────
        _links_text = _build_ioc_links(selected_values)
        if _links_text:
            lines.append("--- SOURCES ---")
            for _ln in _links_text.splitlines():
                lines.append(_ln)
            lines.append("")

        lines.append("=== End of Report ===")
        return "\n".join(lines)

    short_text = st.session_state.get("ai_short", "")
    desc_text = st.session_state.get("ai_desc", "")

    def _text_with_copy(label: str, text: str, height: int, key: str) -> None:
        st.text_area(label, value=text or "", height=height, key=key)
        data = base64.b64encode((text or "").encode("utf-8")).decode("ascii")
        html = f"""
        <style>
          .copy-wrap {{ display: flex; align-items: center; gap: 8px; margin-top: 6px; }}
          .copy-btn {{
            padding: 6px 10px;
            border: 1px solid #ccc;
            border-radius: 6px;
            background: #f7f7f7;
            cursor: pointer;
            font-size: 0.9rem;
          }}
          .copy-msg {{ color: #0a7b30; font-size: 0.85rem; }}
        </style>
        <div class="copy-wrap">
          <button class="copy-btn" id="{key}_btn">Copy</button>
          <span class="copy-msg" id="{key}_msg"></span>
        </div>
        <script>
          const btn = document.getElementById("{key}_btn");
          const msg = document.getElementById("{key}_msg");
          const data = "{data}";
          if (btn) {{
            btn.addEventListener("click", () => {{
              const text = atob(data);
              navigator.clipboard.writeText(text).then(() => {{
                msg.textContent = "copied!";
              }});
            }});
          }}
        </script>
        """
        components.html(html, height=60)

    if desc_text or selected:
        # ── Threat Analysis expander (always shown when IOCs selected) ──────
        _ta_summary = _build_analysis_summary(selected or [])
        _ta_result  = analyzeThreat(_ta_summary)
        _ta_state   = _ta_result.get("threat_state", "Exposure")
        _ta_level   = _ta_result.get("threat_level", "Low")
        _ta_label   = _ta_result.get("risk_level_label", "")
        _ta_mitre   = _ta_result.get("mitre_alignment", [])
        _ta_reasons = _ta_result.get("reasons", [])

        _level_color = {"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e67e22", "Very High": "#e74c3c"}.get(_ta_level, "#aaa")
        _level_badge = f'<span style="background:{_level_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.82rem;font-weight:600">{_ta_level}</span>'
        _state_color = {"Exposure":"#3498db","Intrusion Attempt":"#f39c12","Compromise":"#e67e22","Privilege Escalation":"#e74c3c","Lateral Movement":"#c0392b","Persistence":"#8e44ad","Impact":"#7b241c"}.get(_ta_state,"#555")
        _state_badge = f'<span style="background:{_state_color};color:#fff;padding:2px 10px;border-radius:12px;font-size:0.82rem;font-weight:600">{_ta_state}</span>'

        with st.expander("**Threat Analysis**", expanded=True):
            # ── Row 1: State + Level + Label ─────────────────────────────
            _h1, _h2, _h3 = st.columns([2, 2, 3])
            with _h1:
                st.markdown("**Threat State**")
                st.markdown(_state_badge, unsafe_allow_html=True)
            with _h2:
                st.markdown("**Threat Level**")
                st.markdown(_level_badge, unsafe_allow_html=True)
            with _h3:
                st.markdown("**Risk Label**")
                st.markdown(f'<span style="color:#aaa;font-size:0.9rem">{_ta_label or "—"}</span>', unsafe_allow_html=True)

            # ── Row 2: Reasons ────────────────────────────────────────────
            if _ta_reasons:
                st.divider()
                st.markdown("**Reasons**")
                for _r in _ta_reasons:
                    st.markdown(f"- {_r}")

            # ── Row 3: MITRE ATT&CK tactics ──────────────────────────────
            _mitre_names = {
                "TA0001":"Initial Access","TA0002":"Execution","TA0003":"Persistence",
                "TA0004":"Privilege Escalation","TA0005":"Defense Evasion","TA0006":"Credential Access",
                "TA0007":"Discovery","TA0008":"Lateral Movement","TA0009":"Collection",
                "TA0010":"Exfiltration","TA0011":"Command & Control","TA0040":"Impact",
                "TA0042":"Resource Development","TA0043":"Reconnaissance",
            }
            _tactic_ids = [t for t in _ta_mitre if t.startswith("TA")]
            if _tactic_ids:
                st.divider()
                st.markdown("**MITRE ATT&CK Tactics**")
                _badge_html = " ".join(
                    f'<span style="background:#2c3e50;color:#ecf0f1;padding:3px 9px;border-radius:10px;font-size:0.78rem;margin:2px;display:inline-block">'
                    f'{t} · {_mitre_names.get(t, t)}</span>'
                    for t in _tactic_ids
                )
                st.markdown(_badge_html, unsafe_allow_html=True)

            # ── Row 4: IOC Flags ──────────────────────────────────────────
            _all_flags: list[dict] = []
            for _ioc in items:
                if selected and _ioc.value not in selected:
                    continue
                _all_flags.extend(extract_ioc_flags(
                    _ioc.value, _ioc.type,
                    vt_results.get(_ioc.value, {}) or {},
                    urlscan_results.get(_ioc.value, {}) or {},
                    abuse_results.get(_ioc.value, {}) or {},
                    tf_results.get(_ioc.value, {}) or {},
                    mb_results.get(_ioc.value, {}) or {},
                    shodan_results.get(_ioc.value, {}) or {},
                    dnsd_results.get(_ioc.value, {}) or {},
                    ha_results.get(_ioc.value, {}) or {},
                ))
            # Deduplicate
            _seen_fids: set[str] = set()
            _deduped_flags: list[dict] = []
            for _f in _all_flags:
                if _f["id"] not in _seen_fids:
                    _seen_fids.add(_f["id"])
                    _deduped_flags.append(_f)

            if _deduped_flags:
                st.divider()
                st.markdown("**Threat Indicators**")
                _sev_cfg = {
                    "CRITICAL": ("#c0392b", "🔴"),
                    "HIGH":     ("#e67e22", "🟠"),
                    "MEDIUM":   ("#f39c12", "🟡"),
                    "LOW":      ("#27ae60", "🟢"),
                    "INFO":     ("#7f8c8d", "ℹ️"),
                }
                for _sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    _grp = [_f for _f in _deduped_flags if _f["severity"] == _sev]
                    if not _grp:
                        continue
                    _sc, _se = _sev_cfg[_sev]
                    with st.expander(f"{_se} {_sev} — {len(_grp)} indicator(s)"):
                        for _f in _grp:
                            _mitre_str = " · ".join(_f["mitre"]) if _f["mitre"] else "—"
                            _src_badge = f'<span style="background:#34495e;color:#ecf0f1;padding:1px 7px;border-radius:8px;font-size:0.73rem">{_f["source"]}</span>'
                            st.markdown(
                                f'**{_f["label"]}** {_src_badge}<br>'
                                f'<span style="color:#aaa;font-size:0.82rem">Type: {_f["threat_type"]} &nbsp;|&nbsp; MITRE: {_mitre_str}</span>'
                                + (f'<br><span style="color:#888;font-size:0.78rem">{_f["detail"]}</span>' if _f.get("detail") else ""),
                                unsafe_allow_html=True,
                            )
                            st.markdown("---")

            # ── Row 5: Key Evidence per IOC ───────────────────────────────
            _ke_rows: list[tuple[str, str, str]] = []  # (ioc, label, value)
            for _ioc in items:
                if selected and _ioc.value not in selected:
                    continue
                _vt_i  = vt_results.get(_ioc.value, {}) or {}
                _us_i  = urlscan_results.get(_ioc.value, {}) or {}
                _tf_i  = tf_results.get(_ioc.value, {}) or {}
                _mb_i  = mb_results.get(_ioc.value, {}) or {}
                _sh_i  = shodan_results.get(_ioc.value, {}) or {}
                _ha_i  = ha_results.get(_ioc.value, {}) or {}
                _at_i  = (_vt_i.get("attributes") or {})

                # Malware family
                _family = (
                    str(_ha_i.get("malware_family") or "").strip()
                    or str(((_tf_i.get("data") or [{}])[0]).get("malware") or "").strip()
                    or str(_mb_i.get("data", [{}])[0].get("signature") if isinstance(_mb_i.get("data"), list) and _mb_i.get("data") else "").strip()
                )
                if _family:
                    _ke_rows.append((_ioc.value, "Malware Family", _family))

                # VT first seen
                _fs = _at_i.get("first_seen_itw_date") or _at_i.get("first_submission_date")
                if _fs:
                    try:
                        _fs_str = datetime.utcfromtimestamp(int(_fs)).strftime("%Y-%m-%d")
                    except Exception:
                        _fs_str = str(_fs)[:10]
                    _ke_rows.append((_ioc.value, "First Seen", _fs_str))

                # Domain age
                _cd = _at_i.get("creation_date")
                if _cd:
                    try:
                        _age = (datetime.utcnow() - datetime.utcfromtimestamp(int(_cd))).days
                        _ke_rows.append((_ioc.value, "Domain Age", f"{_age} days"))
                    except Exception:
                        pass

                # URLScan redirect count
                _us_result = _us_i.get("result", {}) or {}
                _us_data = _us_result.get("data", {}) if isinstance(_us_result.get("data"), dict) else {}
                _us_reqs = _us_data.get("requests") or _us_result.get("http") or []
                if isinstance(_us_reqs, list) and _us_reqs:
                    _seen_r: set = set()
                    _chain_r: list = []
                    for _tx in _us_reqs:
                        if not isinstance(_tx, dict): continue
                        _u = (_tx.get("request") or {}).get("url")
                        if isinstance(_u, str) and _u not in _seen_r:
                            _seen_r.add(_u); _chain_r.append(_u)
                    _nr = max(len(_chain_r) - 1, 0)
                    if _nr > 0:
                        _ke_rows.append((_ioc.value, "Redirect Hops", str(_nr)))

                # Shodan CVEs
                _sh_sum = _sh_i.get("summary", {}) if isinstance(_sh_i.get("summary"), dict) else {}
                _sh_roll = (_sh_sum.get("shodan", {}) or {}).get("rollup", {})
                _sh_cves = _sh_roll.get("cves") or _sh_i.get("vulns") or []
                if isinstance(_sh_cves, list) and _sh_cves:
                    _ke_rows.append((_ioc.value, "CVEs (Shodan)", str(len(_sh_cves))))

                # Shodan open ports
                _sh_ports = _sh_roll.get("unique_ports") or _sh_i.get("ports") or []
                if isinstance(_sh_ports, list) and _sh_ports:
                    _ke_rows.append((_ioc.value, "Open Ports", str(len(_sh_ports))))

                # URLScan brand impersonation
                _us_brands = ((_us_i.get("verdicts", {}) or {}).get("overall", {}) or {}).get("brands") or []
                if _us_brands:
                    _ke_rows.append((_ioc.value, "Brand Impersonation", ", ".join(str(b) for b in _us_brands[:3])))

                # AbuseIPDB score
                _ab_i = abuse_results.get(_ioc.value, {}) or {}
                _ab_score = _ab_i.get("abuseConfidenceScore")
                if _ab_score is not None and int(_ab_score) >= 25:
                    _ke_rows.append((_ioc.value, "Abuse Confidence", f"{_ab_score}%"))

            if _ke_rows:
                st.divider()
                st.markdown("**Key Evidence**")
                # Group by IOC
                _ke_by_ioc: dict[str, list] = {}
                for _iv, _lbl, _val in _ke_rows:
                    _ke_by_ioc.setdefault(_iv, []).append((_lbl, _val))
                for _iv, _pairs in _ke_by_ioc.items():
                    if len(selected) > 1:
                        st.caption(f"`{_iv}`")
                    _ncols = min(len(_pairs), 4)
                    for _ci in range(0, len(_pairs), _ncols):
                        _chunk = _pairs[_ci:_ci + _ncols]
                        _cols = st.columns(len(_chunk))
                        for _col, (_lbl, _val) in zip(_cols, _chunk):
                            _col.metric(_lbl, _val)

            # ── Row 6: Source Links ───────────────────────────────────────
            _ioc_links_text = st.session_state.get("ai_ioc_links") or _build_ioc_links(selected or [])
            if _ioc_links_text:
                st.divider()
                st.markdown("**Source Links**")
                for _ll in _ioc_links_text.strip().splitlines():
                    _ll = _ll.strip()
                    if not _ll or _ll.startswith("Source:"):
                        continue
                    if _ll.startswith("- "):
                        _parts = _ll[2:].split(": ", 1)
                        if len(_parts) == 2:
                            _lname, _lurl = _parts
                            st.markdown(f"• [{_lname}]({_lurl}) — `{_lurl}`")
                        else:
                            st.markdown(f"• {_ll[2:]}")

        # ── Description below (full width, with copy) ───────────────────
        shown_desc = desc_text if desc_text else ""
        st.markdown("**IOC Description**")
        st.caption(f"~{len(shown_desc.split())} words" if shown_desc else "No description generated yet")
        st.text_area("", value=shown_desc, height=180, key="ai_description", label_visibility="collapsed")
        if shown_desc:
            _desc_b64 = base64.b64encode(shown_desc.encode("utf-8")).decode("ascii")
            _desc_html = f"""
            <style>
              .copy-wrap{{display:flex;align-items:center;gap:8px;margin-top:4px}}
              .copy-btn{{padding:5px 10px;border:1px solid #ccc;border-radius:6px;background:#f7f7f7;cursor:pointer;font-size:0.88rem}}
              .copy-msg{{color:#0a7b30;font-size:0.82rem}}
            </style>
            <div class="copy-wrap">
              <button class="copy-btn" id="desc_copy_btn">Copy</button>
              <span class="copy-msg" id="desc_copy_msg"></span>
            </div>
            <script>
              (function(){{
                var btn=document.getElementById("desc_copy_btn");
                var msg=document.getElementById("desc_copy_msg");
                if(btn){{btn.addEventListener("click",function(){{
                  navigator.clipboard.writeText(atob("{_desc_b64}")).then(function(){{msg.textContent="copied!"}});
                }})}}
              }})();
            </script>
            """
            components.html(_desc_html, height=50)

        # ── Pre-compute share text into session_state for output format ──
        st.session_state["share_text"] = _build_share_text([ioc.value for ioc in items])
