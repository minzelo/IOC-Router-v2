# AbuseIPDB

AbuseIPDB is a community-driven database of IP addresses reported for malicious activity. It assigns an abuse confidence score (0–100) and categorises the type of abuse. IOC Router uses it for IP reputation checks, resolving domain and URL inputs to their underlying IPs first.

---

## How It Works (Technical)

### Endpoint Used

[`providers/abuseipdb.py`](../providers/abuseipdb.py) calls a single endpoint:

```
GET https://api.abuseipdb.com/api/v2/check
```

### Authentication

API key sent via the `Key` HTTP header:

```
Key: <ABUSEIPDB_KEY>
```

### Request Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `ipAddress` | Target IP | The IP to check |
| `maxAgeInDays` | `90` | Look back 90 days for reports |
| `verbose` | `true` | Include individual report entries |

Domains and URLs are first resolved to an IP address before the API call is made.

### Response Fields Used

| Field | Description |
|-------|-------------|
| `abuseConfidenceScore` | 0–100 score; higher = more likely malicious |
| `totalReports` | Total abuse reports ever filed |
| `lastReportedAt` | ISO 8601 UTC timestamp of most recent report |
| `categories[]` | Numeric codes for abuse types (see table below) |
| `reports[]` | Individual report entries with timestamps and comments |
| `countryCode` | Two-letter country code of the IP |
| `usageType` | Usage classification (Data Center, ISP, etc.) |
| `isp` | ISP name |
| `domain` | Reverse-lookup domain |

### Abuse Category Codes

| Code | Category |
|------|---------|
| 3 | Fraud Orders |
| 4 | DDoS Attack |
| 9 | Open Proxy |
| 10 | Web Spam |
| 11 | Email Spam |
| 14 | Port Scan |
| 15 | Hacking |
| 16 | SQL Injection |
| 17 | Spoofing |
| 18 | Brute-Force |
| 19 | Bad Web Bot |
| 20 | Exploited Host |
| 21 | Web App Attack |
| 22 | SSH |
| 23 | IoT Targeted |

### Risk Classification Logic

Defined in [`providers/abuseipdb.py`](../providers/abuseipdb.py):

| Condition | Risk |
|-----------|------|
| Score > 75 | HIGH |
| Score 50–75 | MEDIUM |
| Score < 50 | LOW |

Additional recency flag: marked **Active** if reported within the last 7 days.

### Verdict Mapping

| Score | Verdict |
|-------|---------|
| ≥ 80 | MALICIOUS (also overrides multi-source verdict in [`ioc/verdict.py`](../ioc/verdict.py)) |
| 50–79 | SUSPICIOUS |
| < 50 | LIKELY_BENIGN |

### Flag Extraction

[`ioc/flags/abuseipdb.py`](../ioc/flags/abuseipdb.py) converts the score and category list into structured threat flags with MITRE ATT&CK mappings, e.g. SSH brute-force → T1110, DDoS → T1498.

### Timeout & Batching

- Timeout: **15 seconds** per request
- Entry point: `abuseipdb_lookup_batch()` in [`providers/abuseipdb.py`](../providers/abuseipdb.py)

---

## Getting an API Key

1. Register at [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register).
2. Log in and go to **Account → API** (or [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)).
3. Click **Create Key**, give it a label, and copy the key.
4. Add it to `.env`:
   ```env
   ABUSEIPDB_KEY=your_api_key_here
   ```

**Free tier limits:** 1 000 check requests/day. Higher tiers unlock more daily checks and bulk lookup endpoints.
