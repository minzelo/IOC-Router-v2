# URLScan.io

URLScan.io scans URLs in a sandboxed browser, capturing screenshots, redirect chains, DOM content, TLS certificate data, and all network connections made during the page load. IOC Router uses it for URL and domain phishing/obfuscation analysis.

---

## How It Works (Technical)

### Endpoints Used

[`providers/urlscan.py`](../providers/urlscan.py) uses three endpoints:

| Action | Method | Endpoint |
|--------|--------|----------|
| Search existing scans | `GET` | `/api/v1/search/?q={query}` |
| Submit new scan | `POST` | `/api/v1/scan/` |
| Retrieve result | `GET` | `/api/v1/result/{uuid}/` |

### Authentication

API key passed via the `API-Key` HTTP header:

```
API-Key: <URLSCAN_KEY>
```

### Search Strategy

Before submitting a new scan, the provider searches the URLScan database for existing results ([`providers/urlscan.py`](../providers/urlscan.py)):

- For URLs: tries `page.url:"{url}"` then `task.url:"{url}"`
- For domains: tries `domain:"{domain}"`, `page.domain:"{domain}"`, `task.domain:"{domain}"`

If a recent result exists it is used directly, skipping an unnecessary scan submission.

### Scan Submission & Polling

When no existing result is found, a new scan is submitted via `POST /api/v1/scan/`. The provider then polls `GET /api/v1/result/{uuid}/` up to **3 times** with a **2-second** delay between polls until the result is ready.

### Response Fields Analysed

| Field | What It Detects |
|-------|----------------|
| `verdicts.overall.malicious` | URLScan's own malicious verdict |
| `verdicts.overall.phishing` | Phishing verdict from the scanner |
| `page.url` / `page.domain` | Final resolved URL after redirects |
| `lists.domains` | All external domains contacted |
| `http.requests[]` | Full HTTP transaction log |
| `tls.certificates[]` | Certificate issuer, validity, SANs |
| DOM snapshot | Inline scripts, password fields, base64 blobs |

### Flag Extraction

[`ioc/flags/urlscan.py`](../ioc/flags/urlscan.py) derives flags from the raw scan result:

| Flag | Trigger |
|------|---------|
| Credential harvest + form exfil | Password field + POST to external domain |
| Obfuscation + file download | Base64 blobs in DOM + download link detected |
| Aggressive redirect chain | 3+ redirect hops |
| Certificate anomaly | Self-signed cert, recently issued (<30 days), or domain mismatch |
| Tracker overload | 5+ third-party tracker domains |

### Verdict Classification

| Verdict | Conditions |
|---------|-----------|
| MALICIOUS | Credential harvest + exfil **OR** obfuscation + file download **OR** redirect + cert mismatch + recent cert |
| SUSPICIOUS | 2 or more suspicious indicators present |
| CLEAN | Scan data returned, no malicious indicators |
| UNKNOWN | No scan data found |

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `urlscan_lookup_batch()` in [`providers/urlscan.py`](../providers/urlscan.py)

---

## Getting an API Key

1. Register at [https://urlscan.io/user/signup](https://urlscan.io/user/signup).
2. After logging in, go to **Settings → API Keys** (or [https://urlscan.io/user/profile](https://urlscan.io/user/profile)).
3. Click **Create new API key**, give it a name, and copy the generated key.
4. Add it to `.env`:
   ```env
   URLSCAN_KEY=your_api_key_here
   ```

**Free tier limits:** 100 public scans/day, 1 000 search API calls/day. Private scans and higher quotas require a paid plan.
