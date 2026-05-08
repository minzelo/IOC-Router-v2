# IOC Router

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Threat Intelligence](https://img.shields.io/badge/Threat_Intelligence-multi--source-red)
![AI Powered](https://img.shields.io/badge/AI_Powered-Gemini_%2B_Groq-blue)
[![Live Demo](https://img.shields.io/badge/Live_Demo-minzelo--ioc--analyzer-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://minzelo-ioc-analyzer.streamlit.app)

IOC Router is a multi-source threat intelligence platform built for SOC analysts. Paste one or more suspicious indicators — IPs, domains, URLs, file hashes, emails, or bare WHOIS keywords — and get an enriched verdict aggregated from up to 10 threat intel providers, complete with severity-rated flags, MITRE ATT&CK mappings, geolocation, and an AI-generated incident ticket.

Access from: https://ioc-router-v2.streamlit.app

---

## Features

| # | Feature | Description |
|:-:|---------|-------------|
| 1 | **Multi-source Enrichment** | Queries up to 10 providers simultaneously — VirusTotal, URLScan, AbuseIPDB, Shodan, ThreatFox, MalwareBazaar, DNSDumpster, Hybrid Analysis, MxToolBox, Whoxy |
| 2 | **IOC Type Auto-detection** | Automatically identifies IPv4/IPv6, domain, URL, file hash (MD5/SHA1/SHA256), email, and WHOIS keywords |
| 3 | **Threat Flag Extraction** | Extracts 100+ granular threat flags with severity levels (CRITICAL → INFO) and MITRE ATT&CK IDs |
| 4 | **Verdict Aggregation** | Produces a final verdict (Malicious / Suspicious / Unknown / Benign) with confidence scoring based on provider consensus |
| 5 | **Threat State & Level** | Determines threat lifecycle state (Exposure → Impact) and assigns a threat level (Low → Very High), adjusted for asset criticality |
| 6 | **Geolocation & Mapping** | Resolves IPs to country, city, ISP, and ASN — displayed on an interactive map |
| 7 | **AI Ticket Generation** | Auto-generates a human-readable incident description using Google Gemini or Groq, based on flags, raw logs, and context metadata |
| 8 | **Multiple Output Formats** | Export results as structured Notes, Table, JSON, or a shareable encoded text |

---

## Supported IOC Types

| Type | Examples |
|------|---------|
| IPv4 / IPv6 | `192.168.1.1`, `2001:db8::1` |
| Domain | `malicious-site.com` |
| URL | `http://phishing.example.com/login` |
| File Hash | MD5, SHA1, SHA256 |
| Email | `attacker@domain.com` |
| WHOIS Keyword | `evilcorp` — triggers Whoxy reverse WHOIS by keyword |

---

## Threat Intelligence Providers

| Provider | Supported IOCs | Key Data |
|----------|---------------|----------|
| [**VirusTotal**](docs/virustotal.md) | IP, Domain, URL, Hash | 70+ AV engine results, YARA/SIGMA hits, sandbox behavior, reputation |
| [**URLScan.io**](docs/urlscan.md) | URL, Domain | Screenshot, redirect chain, credential form detection, obfuscation |
| [**AbuseIPDB**](docs/abuseipdb.md) | IP, Domain, URL | Abuse confidence score, report categories (DDoS, SSH brute force, phishing, etc.) |
| [**Shodan**](docs/shodan.md) | IP | Open ports, CVEs, service tags (tor, vpn, honeypot, etc.) |
| [**ThreatFox**](docs/threatfox.md) | IP, Domain, URL, Hash | Malware family, C2 infrastructure, confidence level |
| [**MalwareBazaar**](docs/malwarebazaar.md) | Hash | File signature, type, YARA rules, known sample metadata |
| [**DNSDumpster**](docs/dnsdumpster.md) | Domain, URL | Subdomains, A/MX/NS records, SPF configuration |
| [**Hybrid Analysis**](docs/hybrid_analysis.md) | IP, Domain, URL, Hash | Sandbox verdict, threat score, malware family, network IOCs, MITRE behavior |
| [**MxToolBox**](docs/mxtoolbox.md) | IP, Domain, URL, Email | Blacklist checks, PTR/MX/DNS/SPF/DMARC lookups, HTTP reachability, mail security posture |
| [**Whoxy**](docs/whoxy.md) | Domain, URL, WHOIS Keyword | WHOIS registration data, registrant email/company, reverse WHOIS by registrant or keyword |

---

## Analysis Pipeline

```
Input IOCs
    ↓
[Parser]          — type detection, normalization, deduplication
    ↓
[Provider Router] — each IOC is sent only to relevant providers
    ↓
[Flag Extraction] — 100+ threat flags extracted, severity-rated, MITRE-mapped
    ↓
[Verdict Engine]  — multi-source aggregation → Malicious / Suspicious / Unknown / Benign
    ↓
[Threat Analysis] — threat state + level, asset criticality adjustment
    ↓
[Geolocation]     — IP → geo coordinates → interactive map
    ↓
[AI Generation]   — Gemini / Groq generates an incident ticket narrative
    ↓
Output (Notes / Table / JSON / Shareable Text)
```

---

## Output Formats

| Format | Description |
|--------|-------------|
| **Ticket Notes** | Structured human-readable text per IOC — suitable for copy-paste into SIEM tickets |
| **Table** | Tabular view with artifact, type, verdict, confidence, evidence, and sources |
| **JSON** | Raw structured output for downstream processing or logging |
| **Shareable Text** | Base64-encoded summary, copy-to-clipboard ready |

---

## Project Structure

```
ioc-router/
├── app.py                        # Streamlit entry point
├── config.py                     # API key config & environment loading
├── requirements.txt
│
├── core/                         # Orchestration & shared utilities
│   ├── orchestrator.py           # Async provider dispatch & result aggregation
│   ├── cache.py                  # In-memory result caching
│   └── geo.py                    # IP geolocation resolution
│
├── ioc/                          # IOC processing pipeline
│   ├── parser.py                 # Type detection, normalization, deduplication
│   ├── verdict.py                # Multi-source verdict aggregation engine
│   ├── threat_analysis.py        # Threat state, threat level, asset criticality
│   └── flags/                    # Per-provider threat flag extractors
│       ├── virustotal.py
│       ├── urlscan.py
│       ├── abuseipdb.py
│       ├── shodan.py
│       ├── threatfox.py
│       ├── malwarebazaar.py
│       ├── hybrid_analysis.py
│       ├── dnsdumpster.py
│       ├── multisource.py        # Cross-provider correlation flags
│       └── base.py               # Shared flag builder helpers
│
├── providers/                    # Provider API clients
│   ├── virustotal.py
│   ├── urlscan.py
│   ├── abuseipdb.py
│   ├── shodan.py
│   ├── threatfox.py
│   ├── malwarebazaar.py
│   ├── hybrid_analysis.py
│   ├── dnsdumpster.py
│   ├── mxtoolbox.py              # MxToolBox DNS/blacklist/mail lookups
│   ├── whoxy.py                  # Whoxy WHOIS + reverse WHOIS
│   ├── gemini.py                 # Google Gemini AI client
│   └── groq.py                   # Groq AI client
│
├── ui/                           # Streamlit UI components
│   ├── styles.py                 # Global CSS & theme
│   └── components/
│       ├── drawer.py             # API key drawer sidebar
│       ├── ioc_card.py           # Per-IOC result card
│       ├── ai_panel.py           # AI ticket generation panel
│       ├── cve_panel.py          # CVE details panel
│       ├── map.py                # Interactive OSM map builder
│       └── output_renderer.py    # Notes / Table / JSON / Shareable output
│
├── docs/                         # Provider integration documentation
│   ├── virustotal.md
│   ├── urlscan.md
│   ├── abuseipdb.md
│   ├── shodan.md
│   ├── threatfox.md
│   ├── malwarebazaar.md
│   ├── hybrid_analysis.md
│   ├── dnsdumpster.md
│   ├── mxtoolbox.md
│   ├── whoxy.md
│   ├── gemini.md
│   └── grok.md
│
└── tests/
    ├── test_abuseipdb_processing.py
    ├── test_dnsdumpster_processing.py
    ├── test_hybrid_analysis_provider.py
    ├── test_malwarebazaar_provider.py
    ├── test_shodan_internetdb.py
    ├── test_threat_analysis.py
    └── test_urlscan_processing.py
```

---

## Requirements

- Python 3.10 or higher
- pip
- API keys for the providers you want to use (at minimum `VT_KEY` is recommended)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ioc-router.git
cd ioc-router
```

### 2. Configure API keys

Create a `.env` file in the project root:

```env
VT_KEY=your_virustotal_key
URLSCAN_KEY=your_urlscan_key
ABUSEIPDB_KEY=your_abuseipdb_key
SHODAN_KEY=your_shodan_key
THREATFOX_KEY=your_threatfox_key
MALWAREBAZAAR_KEY=your_malwarebazaar_key
DNSDUMPSTER_KEY=your_dnsdumpster_key
HYBRID_ANALYSIS_KEY=your_hybrid_analysis_key
MXTOOLBOX_KEY=your_mxtoolbox_key
WHOXY_KEY=your_whoxy_key
GEMINI_KEY=your_gemini_key
GEMINI_KEY_BACKUP=your_gemini_backup_key          # optional
GEMINI_MODEL=gemini-2.5-flash                     # optional, this is the default
GEMINI_API_VERSION=v1                             # optional, this is the default
GROQ_KEY=your_groq_key
```

> API keys can also be entered directly in the app UI via the key drawer — they are stored in session only and never written to disk.

### 3. Run the app

```bash
streamlit run app.py
```

The app will be available at:

```
http://localhost:8501
```
