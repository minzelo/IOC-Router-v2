import unittest
from unittest.mock import Mock, patch

from providers.hybrid_analysis import hybrid_analysis_enrich


class TestHybridAnalysisProvider(unittest.TestCase):
    @patch("providers.hybrid_analysis.Settings.from_env")
    @patch("providers.hybrid_analysis.requests.request")
    def test_hash_enrichment_with_report(self, mock_request, mock_from_env):
        mock_from_env.return_value = Mock(hybrid_analysis_key="k")
        search_response = Mock()
        search_response.status_code = 200
        search_response.json.return_value = [
            {
                "sha256": "abc123",
                "submit_name": "payload.exe",
                "type": "peexe",
                "size": 1024,
                "vx_family": "Emotet",
                "verdict": "malicious",
                "threat_score": 92,
                "av_detect": 18,
                "analysis_start_time": "2026-03-15T10:00:00Z",
                "environment_description": "Windows 10 64 bit",
                "job_id": "job-123",
            }
        ]

        report_response = Mock()
        report_response.status_code = 200
        report_response.json.return_value = {
            "contacted_domains": [{"domain": "c2.example"}],
            "contacted_hosts": [{"ip": "8.8.8.8"}],
            "process_tree": [
                {"process_name": "powershell.exe", "command_line": "powershell -enc AAAA"},
                {"process_name": "schtasks.exe", "command_line": "schtasks /create /tn test"},
            ],
            "mutexes": ["Global\\emotet"],
            "dropped_files": [{"filename": "stage2.dll", "sha256": "drop123", "type": "dll"}],
            "mitre_attcks": [{"attck_id": "T1059"}, {"attck_id": "T1053"}],
        }

        mock_request.side_effect = [search_response, report_response]

        result = hybrid_analysis_enrich("hash", "44d88612fea8a8f36de82e1278abb02f")

        self.assertEqual(result["source"], "Hybrid Analysis")
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["threat_score"], "92")
        self.assertEqual(result["malware_family"], "Emotet")
        self.assertEqual(result["file_information"]["file_name"], "payload.exe")
        self.assertEqual(result["network_ioc"]["domains"], ["c2.example"])
        self.assertEqual(result["network_ioc"]["ips"], ["8.8.8.8"])
        self.assertEqual(result["behavior"]["mutex"], ["Global\\emotet"])
        self.assertEqual(result["mitre_attack"], ["T1059", "T1053"])
        self.assertTrue(any("schtasks" in item.lower() for item in result["behavior"]["persistence"]))

    @patch("providers.hybrid_analysis.Settings.from_env")
    @patch("providers.hybrid_analysis.requests.request")
    def test_url_quick_scan_enrichment(self, mock_request, mock_from_env):
        mock_from_env.return_value = Mock(hybrid_analysis_key="k")
        submit_response = Mock()
        submit_response.status_code = 200
        submit_response.json.return_value = {"id": "scan-1"}

        detail_response = Mock()
        detail_response.status_code = 200
        detail_response.json.return_value = {
            "verdict": "malicious",
            "threat_score": 85,
            "redirect_chain": ["http://evil.test", "https://evil.test/login"],
            "downloaded_files": [{"filename": "payload.exe", "sha256": "f1"}],
            "contacted_domains": ["evil.test", "cdn.evil.test"],
            "contacted_ips": ["1.2.3.4"],
        }

        mock_request.side_effect = [submit_response, detail_response]

        result = hybrid_analysis_enrich("url", "http://evil.test")

        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["threat_score"], "85")
        self.assertEqual(result["network_ioc"]["domains"], ["evil.test", "cdn.evil.test"])
        self.assertEqual(result["network_ioc"]["ips"], ["1.2.3.4"])
        self.assertEqual(result["behavior"]["dropped_files"][0]["name"], "payload.exe")
        self.assertEqual(result["redirect_chain"], ["http://evil.test", "https://evil.test/login"])

    @patch("providers.hybrid_analysis.Settings.from_env")
    @patch("providers.hybrid_analysis.requests.request")
    def test_domain_correlation_only(self, mock_request, mock_from_env):
        mock_from_env.return_value = Mock(hybrid_analysis_key="k")
        response = Mock()
        response.status_code = 200
        response.json.return_value = [
            {
                "sha256": "hash-1",
                "vx_family": "QakBot",
                "analysis_start_time": "2026-03-10T00:00:00Z",
                "environment_description": "contacted via HTTP",
            }
        ]
        mock_request.return_value = response

        result = hybrid_analysis_enrich("domain", "bad.test")

        self.assertEqual(result["message"], "Not supported by Hybrid Analysis API")
        self.assertEqual(result["related_hashes"], ["hash-1"])
        self.assertEqual(result["malware_family"], "QakBot")
        self.assertEqual(result["first_seen"], "2026-03-10T00:00:00Z")

    def test_email_not_supported(self):
        result = hybrid_analysis_enrich("email", "phish@example.com")
        self.assertEqual(result["message"], "Hybrid Analysis does not analyze email indicators.")


if __name__ == "__main__":
    unittest.main()
