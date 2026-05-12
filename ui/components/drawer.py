"""API key drawer — slide-out sidebar panel."""
from __future__ import annotations

import streamlit as st


def render_api_drawer() -> None:
    """Render the slide-out API-key configuration panel inside Streamlit's sidebar."""
    with st.sidebar:
        st.markdown(
            "<h3 style='margin:0.6rem 0 0.2rem;font-size:1rem;font-weight:700;"
            "color:#f5f7fb;letter-spacing:0.01em;text-align:center;'>⚙️ Insert API Keys</h3>"
            "<p style='margin:0 0 0.5rem;font-size:0.7rem;color:#6e7681;text-align:center;"
            "font-style:italic;'>Press Enter to input API key</p>"
            "<hr style='border-color:#21262d;margin:0 0 1rem;'/>",
            unsafe_allow_html=True,
        )

        st.markdown(
            "<p style='font-size:0.72rem;font-weight:600;color:#8b95a8;"
            "text-transform:uppercase;letter-spacing:0.09em;margin:0 0 0.35rem;'>🤖 AI</p>",
            unsafe_allow_html=True,
        )
        st.text_input("Gemini", type="password", placeholder="AIza…",
                      key="sk_gemini", label_visibility="visible")
        st.text_input("Grok", type="password", placeholder="gsk_…",
                      key="sk_grok", label_visibility="visible")

        st.divider()

        st.markdown(
            "<p style='font-size:0.72rem;font-weight:600;color:#8b95a8;"
            "text-transform:uppercase;letter-spacing:0.09em;margin:0 0 0.35rem;'>🔍 Threat Intel</p>",
            unsafe_allow_html=True,
        )
        st.text_input("VirusTotal", type="password", placeholder="VT API key",
                      key="sk_vt", label_visibility="visible")
        st.text_input("urlscan", type="password", placeholder="urlscan API key",
                      key="sk_urlscan", label_visibility="visible")
        st.text_input("AbuseIPDB", type="password", placeholder="AbuseIPDB API key",
                      key="sk_abuse", label_visibility="visible")
        st.text_input("ThreatFox", type="password", placeholder="ThreatFox API key",
                      key="sk_threatfox", label_visibility="visible")
        st.text_input("MalwareBazaar", type="password", placeholder="MB API key",
                      key="sk_mb", label_visibility="visible")
        st.text_input("Shodan", type="password", placeholder="Shodan API key",
                      key="sk_shodan", label_visibility="visible")
        st.text_input("DNSDumpster", type="password", placeholder="DNSDumpster API key",
                      key="sk_dnsd", label_visibility="visible")
        st.text_input("Hybrid Analysis", type="password", placeholder="HA API key",
                      key="sk_ha", label_visibility="visible")
        st.text_input("MxToolBox", type="password", placeholder="MxToolBox API key",
                      key="sk_mxtoolbox", label_visibility="visible")
        st.text_input("Whoxy", type="password", placeholder="Whoxy API key",
                      key="sk_whoxy", label_visibility="visible")
        st.text_input("Ransomware Live", type="password", placeholder="RL API key",
                      key="sk_ransomware_live", label_visibility="visible")

        st.divider()

        if st.button("🗑 Clear all", use_container_width=True, key="__drawer_clear__"):
            for _k in ["sk_gemini", "sk_grok", "sk_vt", "sk_urlscan", "sk_abuse",
                       "sk_threatfox", "sk_mb", "sk_shodan", "sk_dnsd", "sk_ha", "sk_mxtoolbox", "sk_whoxy",
                       "sk_ransomware_live"]:
                if _k in st.session_state:
                    del st.session_state[_k]
            st.rerun()

        st.caption("Keys override .env · Not saved to disk")
