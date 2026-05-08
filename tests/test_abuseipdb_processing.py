from datetime import datetime, timedelta, timezone
import unittest

from providers.abuseipdb import classify_abuseipdb_check


class TestAbuseIpdbProcessing(unittest.TestCase):
    def test_high_risk_classification(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 90,
                "totalReports": 25,
                "lastReportedAt": (now - timedelta(days=1)).isoformat(),
                "reports": [
                    {"categories": [14, 18], "reportedAt": (now - timedelta(hours=12)).isoformat()},
                ],
            }
        }

        result = classify_abuseipdb_check(payload, now_utc=now)

        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["report_weight"], "HIGH")
        self.assertTrue(result["category_flag"])
        self.assertTrue(result["recency_flag"])
        self.assertEqual(result["final_verdict"], "MALICIOUS")

    def test_medium_with_recent_report_is_suspicious(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "data": {
                "ipAddress": "5.6.7.8",
                "abuseConfidenceScore": 60,
                "totalReports": 3,
                "lastReportedAt": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
                "reports": [{"categories": [11]}],
            }
        }

        result = classify_abuseipdb_check(payload, now_utc=now)

        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["report_weight"], "MEDIUM")
        self.assertTrue(result["recency_flag"])
        self.assertEqual(result["final_verdict"], "SUSPICIOUS")

    def test_low_without_reports_is_likely_benign(self):
        now = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "data": {
                "ipAddress": "9.9.9.9",
                "abuseConfidenceScore": 20,
                "totalReports": 0,
                "lastReportedAt": None,
                "categories": [],
            }
        }

        result = classify_abuseipdb_check(payload, now_utc=now)

        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["report_weight"], "LOW")
        self.assertFalse(result["recency_flag"])
        self.assertEqual(result["final_verdict"], "LIKELY_BENIGN")


if __name__ == "__main__":
    unittest.main()
