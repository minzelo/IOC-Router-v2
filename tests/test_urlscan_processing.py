from datetime import datetime, timedelta, timezone
import unittest

from providers.urlscan import process_urlscan_response


class TestUrlscanProcessing(unittest.TestCase):
    def test_malicious_case(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "uuid": "scan-mal-1",
            "task": {"url": "https://secure-login-check.com/login", "time": now.isoformat()},
            "page": {"url": "https://secure-login-check.com/login", "title": "Microsoft Login Verification"},
            "screenshot": "https://urlscan.io/screenshots/scan-mal-1.png",
            "result": {
                "dom": "<script>eval(atob('QWxhZGRpbjpvcGVuIHNlc2FtZQ=='));</script><input type='password'/>",
                "lists": {
                    "domains": ["secure-login-check.com", "x9ab2kq4-data-drop.net"],
                    "ips": ["45.77.1.10"],
                },
                "tls": {
                    "issuer": "CN=TempCert",
                    "subject_cn": "evil-host.net",
                    "san": ["evil-host.net"],
                    "valid_from": (now - timedelta(days=1)).isoformat(),
                    "valid_to": (now + timedelta(days=20)).isoformat(),
                },
                "data": {
                    "requests": [
                        {"request": {"url": "https://secure-login-check.com/login", "method": "GET"}, "response": {"location": "https://secure-login-check.com/verify"}},
                        {"request": {"url": "https://secure-login-check.com/verify", "method": "POST"}, "response": {"status": 200}},
                    ]
                },
            },
            "verdicts": {"malicious": True},
        }

        out = process_urlscan_response(payload, now_utc=now)

        self.assertEqual(out["verdict"]["classification"], "MALICIOUS")
        self.assertGreaterEqual(out["verdict"]["confidence"], 80)

    def test_suspicious_case(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "uuid": "scan-susp-1",
            "task": {"url": "https://portal-example.com"},
            "page": {"url": "https://portal-example.com", "title": "Portal Sign In"},
            "result": {
                "dom": "<html><input type='password'/></html>",
                "lists": {"domains": ["portal-example.com"], "ips": ["8.8.8.8"]},
                "tls": {
                    "issuer": "Let's Encrypt",
                    "subject_cn": "different-domain.net",
                    "san": ["different-domain.net"],
                    "valid_from": (now - timedelta(days=2)).isoformat(),
                    "valid_to": (now + timedelta(days=60)).isoformat(),
                },
                "data": {
                    "requests": [
                        {"request": {"url": "https://portal-example.com", "method": "GET"}, "response": {"location": "https://portal-example.com/login"}},
                        {"request": {"url": "https://portal-example.com/login", "method": "GET"}, "response": {"status": 200}},
                    ]
                },
            },
        }

        out = process_urlscan_response(payload, now_utc=now)

        self.assertEqual(out["verdict"]["classification"], "SUSPICIOUS")
        self.assertGreaterEqual(out["verdict"]["confidence"], 55)
        self.assertLessEqual(out["verdict"]["confidence"], 79)

    def test_clean_case(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "uuid": "scan-clean-1",
            "task": {"url": "https://example.com"},
            "page": {"url": "https://example.com", "title": "Example Domain"},
            "result": {
                "dom": "<html><body>Normal content</body></html>",
                "lists": {"domains": ["example.com"], "ips": ["93.184.216.34"]},
                "tls": {
                    "issuer": "DigiCert Inc",
                    "subject_cn": "example.com",
                    "san": ["example.com", "www.example.com"],
                    "valid_from": (now - timedelta(days=120)).isoformat(),
                    "valid_to": (now + timedelta(days=120)).isoformat(),
                },
                "data": {
                    "requests": [
                        {"request": {"url": "https://example.com", "method": "GET"}, "response": {"status": 200}},
                    ]
                },
            },
        }

        out = process_urlscan_response(payload, now_utc=now)

        self.assertEqual(out["verdict"]["classification"], "CLEAN")
        self.assertGreaterEqual(out["verdict"]["confidence"], 20)
        self.assertLessEqual(out["verdict"]["confidence"], 54)


if __name__ == "__main__":
    unittest.main()
