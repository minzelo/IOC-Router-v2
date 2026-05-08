import unittest

from ioc.threat_analysis import analyzeThreat, determineThreatState


class TestThreatAnalysis(unittest.TestCase):
    def _base(self):
        return {
            "evidence": {
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
            },
            "mitre_tactics": [],
            "risk_notes": [],
            "asset_criticality": "standard",
        }

    def test_exposure_only(self):
        data = self._base()
        data["risk_notes"] = ["Outdated service exposed"]
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Exposure")
        self.assertEqual(out["threat_level"], "Low")

    def test_intrusion_attempt_scanning_blocked(self):
        data = self._base()
        data["evidence"]["scanning_or_recon"] = True
        data["evidence"]["attack_prevented"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Intrusion Attempt")
        self.assertEqual(out["threat_level"], "Low")

    def test_compromise_by_malware_execution(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Compromise")
        self.assertEqual(out["threat_level"], "Medium")

    def test_privilege_escalation(self):
        data = self._base()
        data["evidence"]["privilege_escalation"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Privilege Escalation")
        self.assertIn(out["threat_level"], ("High", "Very High"))

    def test_lateral_movement(self):
        data = self._base()
        data["evidence"]["lateral_movement"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Lateral Movement")
        self.assertIn(out["threat_level"], ("High", "Very High"))

    def test_impact_override(self):
        data = self._base()
        data["evidence"]["data_exfiltration"] = True
        data["evidence"]["lateral_movement"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Impact")
        self.assertEqual(out["threat_level"], "Very High")

    def test_highest_severity_priority(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        data["evidence"]["persistence_mechanism"] = True
        self.assertEqual(determineThreatState(data), "Persistence")


if __name__ == "__main__":
    unittest.main()
