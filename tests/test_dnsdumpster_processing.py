import unittest

from providers.dnsdumpster import _build_soc_summary


class TestDnsdumpsterProcessing(unittest.TestCase):
    def test_soc_summary_extracts_hosts_and_flags(self):
        data = {
            "dns_records": [
                {"host": "vpn.example.com", "type": "A", "ip": "1.2.3.4", "asn": "AS123", "owner": "Example Telecom", "netblock": "1.2.3.0/24"},
                {"host": "dev.example.com", "type": "CNAME", "value": "dev-app.herokudns.com"},
                {"host": "example.com", "type": "NS", "value": "ns1.cloudflare.com"},
                {"host": "example.com", "type": "TXT", "value": "v=spf1 include:_spf.google.com ~all"},
            ],
            "mx_records": [
                {"host": "example.com", "type": "MX", "value": "mail.example.com"},
            ],
            "host_records": [
                {"host": "vpn.example.com", "banner": "OpenSSH 7.4"},
            ],
        }

        out = _build_soc_summary("example.com", data)
        hosts = out.get("discovered_hosts_subdomains", [])
        self.assertTrue(any(h.get("host") == "vpn.example.com" for h in hosts))
        self.assertTrue(any("Sensitive host pattern" in r for r in out.get("red_flags", [])))
        self.assertTrue(any("third-party/takeover check" in r for r in out.get("red_flags", [])))
        self.assertTrue(out.get("mail_dns_infra", {}).get("mx"))

    def test_soc_summary_handles_empty(self):
        out = _build_soc_summary("example.com", {})
        self.assertEqual(out.get("discovered_hosts_subdomains"), [])
        self.assertEqual(out.get("network_enrichment"), [])
        self.assertEqual(out.get("red_flags"), [])


if __name__ == "__main__":
    unittest.main()
