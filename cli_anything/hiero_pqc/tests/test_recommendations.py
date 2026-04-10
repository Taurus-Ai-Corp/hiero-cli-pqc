"""Tests for reporter._generate_recommendations() — all 5 conditional branches.

No network or external dependencies required.
"""

import unittest

from cli_anything.hiero_pqc.core.reporter import generate_report, _generate_recommendations


def _make_lead(domain="example.com", score=75, grade="WEAK", algo_display="RSA",
               key_size=2048, days_left=180):
    return {
        "domain": domain,
        "pqc_urgency_score": score,
        "urgency": "HIGH" if score >= 60 else "MEDIUM",
        "factors": {
            "crypto_weakness": {"grade": grade, "raw": 80, "weighted": 28},
            "cert_expiry": {"days_left": days_left, "raw": 100, "weighted": 25},
            "industry": {"value": "finance", "raw": 100, "weighted": 20},
            "company_size": {"value": "enterprise", "raw": 100, "weighted": 20},
        },
        "recommended_service": "Hybrid Signature Implementation",
        "price_range": "$75K-$150K",
        "key_algorithm": "rsaEncryption",
        "key_algorithm_display": algo_display,
        "key_size": key_size,
        "cert_expiry_date": "Jan 01 00:00:00 2027 GMT",
        "issuer": "Test CA",
        "sans": [domain],
    }


class TestKeyMigrationRecommendation(unittest.TestCase):
    """Critical score (>=80) triggers Key Migration recommendation."""

    def test_critical_leads_trigger_key_migration(self):
        leads = [_make_lead(score=85)]
        recs = _generate_recommendations(leads)
        key_mig = [r for r in recs if r["category"] == "Key Migration"]
        self.assertEqual(len(key_mig), 1)
        self.assertEqual(key_mig[0]["priority"], "IMMEDIATE")
        self.assertIn("0-6 months", key_mig[0]["timeline"])

    def test_critical_rec_lists_up_to_5_domains(self):
        leads = [_make_lead(domain=f"d{i}.com", score=90) for i in range(8)]
        recs = _generate_recommendations(leads)
        key_mig = [r for r in recs if r["category"] == "Key Migration"][0]
        # Should list first 5 of 8 domains
        self.assertIn("d0.com", key_mig["recommendation"])
        self.assertIn("d4.com", key_mig["recommendation"])
        self.assertNotIn("d5.com", key_mig["recommendation"])
        self.assertIn("8 domain(s)", key_mig["recommendation"])

    def test_no_critical_leads_no_key_migration(self):
        leads = [_make_lead(score=50)]
        recs = _generate_recommendations(leads)
        key_mig = [r for r in recs if r["category"] == "Key Migration"]
        self.assertEqual(len(key_mig), 0)


class TestHybridSignatureRecommendation(unittest.TestCase):
    """Weak RSA (<=2048 bit) triggers Hybrid Signature recommendation."""

    def test_weak_rsa_triggers_hybrid_rec(self):
        leads = [_make_lead(algo_display="RSA", key_size=2048)]
        recs = _generate_recommendations(leads)
        hybrid = [r for r in recs if r["category"] == "Hybrid Signatures"]
        self.assertEqual(len(hybrid), 1)
        self.assertEqual(hybrid[0]["priority"], "HIGH")
        self.assertIn("ML-DSA", hybrid[0]["recommendation"])

    def test_strong_rsa_no_hybrid_rec(self):
        leads = [_make_lead(algo_display="RSA", key_size=4096, score=50)]
        recs = _generate_recommendations(leads)
        hybrid = [r for r in recs if r["category"] == "Hybrid Signatures"]
        self.assertEqual(len(hybrid), 0)


class TestECDSAMigrationRecommendation(unittest.TestCase):
    """ECDSA leads trigger ECDSA Migration recommendation."""

    def test_ecdsa_triggers_migration_rec(self):
        leads = [_make_lead(algo_display="ECDSA", key_size=256, score=50)]
        recs = _generate_recommendations(leads)
        ecdsa = [r for r in recs if r["category"] == "ECDSA Migration"]
        self.assertEqual(len(ecdsa), 1)
        self.assertEqual(ecdsa[0]["priority"], "MEDIUM")
        self.assertIn("quantum-vulnerable", ecdsa[0]["recommendation"])

    def test_non_ecdsa_no_migration_rec(self):
        leads = [_make_lead(algo_display="RSA", key_size=4096, score=50)]
        recs = _generate_recommendations(leads)
        ecdsa = [r for r in recs if r["category"] == "ECDSA Migration"]
        self.assertEqual(len(ecdsa), 0)


class TestCertRenewalRecommendation(unittest.TestCase):
    """Certificates expiring within 180 days trigger renewal recommendation."""

    def test_expiring_cert_triggers_renewal(self):
        leads = [_make_lead(days_left=90)]
        recs = _generate_recommendations(leads)
        renewal = [r for r in recs if r["category"] == "Certificate Renewal"]
        self.assertEqual(len(renewal), 1)
        self.assertEqual(renewal[0]["priority"], "HIGH")
        self.assertIn("PQC-ready", renewal[0]["recommendation"])

    def test_non_expiring_cert_no_renewal(self):
        leads = [_make_lead(days_left=365)]
        recs = _generate_recommendations(leads)
        renewal = [r for r in recs if r["category"] == "Certificate Renewal"]
        self.assertEqual(len(renewal), 0)


class TestMonitoringRecommendation(unittest.TestCase):
    """Empty leads trigger monitoring fallback recommendation."""

    def test_empty_leads_trigger_monitoring(self):
        recs = _generate_recommendations([])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["category"], "Monitoring")
        self.assertEqual(recs[0]["priority"], "LOW")

    def test_clean_leads_trigger_monitoring(self):
        """Leads with no issues (high key size, no ECDSA, not expiring, low score)."""
        leads = [_make_lead(
            algo_display="Ed25519", key_size=256, score=15, days_left=500,
        )]
        recs = _generate_recommendations(leads)
        monitoring = [r for r in recs if r["category"] == "Monitoring"]
        self.assertEqual(len(monitoring), 1)


class TestMultipleRecommendations(unittest.TestCase):
    """Multiple recommendation types can be generated simultaneously."""

    def test_critical_rsa_ecdsa_expiring(self):
        leads = [
            _make_lead(domain="critical.com", score=90, algo_display="RSA", key_size=2048, days_left=30),
            _make_lead(domain="ec.com", score=50, algo_display="ECDSA", key_size=256, days_left=365),
        ]
        recs = _generate_recommendations(leads)
        categories = {r["category"] for r in recs}
        self.assertIn("Key Migration", categories)
        self.assertIn("Hybrid Signatures", categories)
        self.assertIn("ECDSA Migration", categories)
        self.assertIn("Certificate Renewal", categories)
        # Monitoring should NOT appear since there are issues
        self.assertNotIn("Monitoring", categories)

    def test_rec_fields_complete(self):
        leads = [_make_lead(score=85)]
        recs = _generate_recommendations(leads)
        for rec in recs:
            self.assertIn("priority", rec)
            self.assertIn("category", rec)
            self.assertIn("recommendation", rec)
            self.assertIn("standard", rec)
            self.assertIn("timeline", rec)


class TestReportRecommendationsIntegration(unittest.TestCase):
    """Verify recommendations are included in generate_report output."""

    def test_report_includes_recommendations(self):
        leads = [_make_lead(score=85)]
        report = generate_report(leads)
        self.assertIn("recommendations", report)
        self.assertGreater(len(report["recommendations"]), 0)

    def test_report_scan_metadata_tracks_failures(self):
        leads = [_make_lead()]
        scan_results = [
            {"domain": "example.com", "status": "scanned"},
            {"domain": "failed.com", "status": "error", "error": "timeout"},
        ]
        report = generate_report(leads, scan_results=scan_results)
        self.assertEqual(report["scan_metadata"]["failed_scans"], 1)
        self.assertEqual(report["scan_metadata"]["failures"][0]["domain"], "failed.com")


if __name__ == "__main__":
    unittest.main()
