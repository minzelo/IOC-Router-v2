"""Leaflet/OSM interactive map HTML builder."""
from __future__ import annotations

import json


def build_osm_map_html(
    lat: float,
    lon: float,
    geo: dict,
    nom: dict,
    ab: dict,
    vt_attrs: dict,
    ip_label: str,
) -> str:
    """Build a Leaflet/OSM interactive map HTML string with an enriched popup."""

    def _esc(s: object) -> str:
        if s is None:
            return ""
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

    popup_lines: list[str] = [f"<b>🌐 IP:</b> {_esc(ip_label)}"]

    # ── ip-api geo ─────────────────────────────────────────────────────────
    city = geo.get("city")
    region_name = geo.get("regionName")
    region_code = geo.get("region")
    country = geo.get("country")
    cc = geo.get("countryCode")
    postal = geo.get("zip")
    org = geo.get("org")
    isp_geo = geo.get("isp")
    loc_parts = [p for p in [city, region_name,
                              f"{country} ({cc})" if country and cc else country or cc] if p]
    if loc_parts:
        popup_lines.append(f"<b>📍 Geo:</b> {_esc(', '.join(loc_parts))}")
    popup_lines.append(f"<b>Coords:</b> {lat}, {lon}")
    if postal:
        popup_lines.append(f"<b>Postal:</b> {_esc(postal)}")
    if org or isp_geo:
        popup_lines.append(
            f"<b>Org/ISP:</b> {_esc(org)}" + (f" / ISP: {_esc(isp_geo)}" if isp_geo else "")
        )

    # ── Nominatim reverse geocode ───────────────────────────────────────────
    addr = nom.get("address", {}) or {}
    nom_parts = [p for p in [
        addr.get("road"), addr.get("suburb"),
        addr.get("city") or addr.get("town") or addr.get("village"),
        addr.get("state"), addr.get("postcode"), addr.get("country"),
    ] if p]
    if nom_parts:
        popup_lines.append(f"<b>🏘️ Nominatim:</b> {_esc(', '.join(nom_parts))}")

    # ── AbuseIPDB ───────────────────────────────────────────────────────────
    ab_cc = ab.get("countryCode")
    ab_usage = ab.get("usageType")
    ab_isp = ab.get("isp")
    ab_parts = [p for p in [ab_cc, ab_usage, f"ISP: {ab_isp}" if ab_isp else None] if p]
    if ab_parts:
        popup_lines.append(f"<b>🔎 AbuseIPDB:</b> {_esc(' | '.join(ab_parts))}")

    # ── VirusTotal ──────────────────────────────────────────────────────────
    vt_country = vt_attrs.get("country")
    vt_continent = vt_attrs.get("continent")
    vt_asn = vt_attrs.get("asn")
    vt_as_owner = vt_attrs.get("as_owner")
    vt_rir = vt_attrs.get("regional_internet_registry")
    vt_geo_str = ", ".join(p for p in [vt_country, vt_continent] if p)
    vt_asn_str = (
        f"ASN: {vt_asn} ({vt_as_owner})" if vt_asn and vt_as_owner
        else (f"ASN: {vt_asn}" if vt_asn else "")
    )
    vt_parts = [p for p in [vt_geo_str, vt_asn_str, f"RIR: {vt_rir}" if vt_rir else None] if p]
    if vt_parts:
        popup_lines.append(f"<b>📡 VirusTotal:</b> {_esc(' | '.join(vt_parts))}")

    popup_html = "<br>".join(popup_lines)
    popup_js = json.dumps(popup_html)   # safe JS string

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    html,body{{margin:0;padding:0;background:#13151a;height:100%;}}
    #map{{width:100%;height:398px;}}
    .leaflet-popup-content-wrapper{{
      background:#13151a!important;color:#e8eaf0!important;
      border:1px solid #e03b3b!important;border-radius:4px!important;
      box-shadow:0 2px 12px rgba(224,59,59,.2)!important;
    }}
    .leaflet-popup-content{{
      font-family:'JetBrains Mono','Courier New',monospace!important;
      font-size:11.5px!important;line-height:1.65!important;color:#e8eaf0!important;
    }}
    .leaflet-popup-tip{{background:#13151a!important;}}
    .leaflet-popup-close-button{{color:#e03b3b!important;font-size:16px!important;}}
    b{{color:#e03b3b;}}
    .leaflet-control-attribution{{background:rgba(13,14,17,.75)!important;color:#888!important;font-size:10px!important;}}
    .leaflet-control-attribution a{{color:#e03b3b!important;}}
  </style>
</head>
<body>
  <div id="map"></div>
  <script>
    var map = L.map('map',{{zoomControl:true}}).setView([{lat},{lon}],10);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{
      attribution:'&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom:18
    }}).addTo(map);
    var marker = L.circleMarker([{lat},{lon}],{{
      radius:10,color:'#e03b3b',fillColor:'#e03b3b',fillOpacity:.55,weight:2
    }}).addTo(map);
    marker.bindPopup({popup_js}).openPopup();
  </script>
</body>
</html>"""
