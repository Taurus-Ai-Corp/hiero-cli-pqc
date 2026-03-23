"""Unit tests for hiero-cli-pqc core modules.

Tests use synthetic data — no network or OpenSSL required.
"""

import json
import unittest

from cli_anything.hiero_pqc.core.scanner import classify_crypto, parse_cert, CRYPTO_GRADES
from cli_anything.hiero_pqc.core.scorer import score_lead, score_leads, SERVICE_TIERS
from cli_anything.hiero_pqc.core.auditor import hash_report, generate_hcs_payload
from cli_anything.hiero_pqc.core.reporter import generate_report, to_csv, to_text


class TestCryptoClassification(unittest.TestCase):
    """Test quantum vulnerability classification."""

    def test_rsa_1024_critical(self):
        self.assertEqual(classify_crypto("rsaEncryption", 1024), "CRITICAL")

    def test_rsa_2048_weak(self):
        self.assertEqual(classify_crypto("rsaEncryption", 2048), "WEAK")

    def test_rsa_3072_moderate(self):
        self.assertEqual(classify_crypto("rsaEncryption", 3072), "MODERATE")

    def test_rsa_4096_strong(self):
        self.assertEqual(classify_crypto("rsaEncryption", 4096), "STRONG")

    def test_ecdsa_256_weak(self):
        self.assertEqual(classify_crypto("id-ecPublicKey", 256), "WEAK")

    def test_ecdsa_384_moderate(self):
        self.assertEqual(classify_crypto("id-ecPublicKey", 384), "MODERATE")

    def test_ed25519_moderate(self):
        self.assertEqual(classify_crypto("ED25519", 256), "MODERATE")

    def test_ml_kem_pqc_ready(self):
        self.assertEqual(classify_crypto("ML-KEM-768", 768), "PQC_READY")

    def test_ml_dsa_pqc_ready(self):
        self.assertEqual(classify_crypto("ML-DSA-65", 0), "PQC_READY")

    def test_dilithium_pqc_ready(self):
        self.assertEqual(classify_crypto("Dilithium3", 0), "PQC_READY")

    def test_kyber_pqc_ready(self):
        self.assertEqual(classify_crypto("Kyber768", 0), "PQC_READY")

    def test_unknown_defaults_weak(self):
        self.assertEqual(classify_crypto("SomeUnknownAlgo", 0), "WEAK")

    def test_all_grades_have_scores(self):
        for grade in CRYPTO_GRADES:
            self.assertIn("score", CRYPTO_GRADES[grade])
            self.assertIn("label", CRYPTO_GRADES[grade])


class TestScorer(unittest.TestCase):
    """Test PQC urgency scoring."""

    def _make_scan(self, grade="WEAK", days=365, algo="RSA", size=2048):
        return {
            "domain": "example.com",
            "status": "scanned",
            "crypto_grade": grade,
            "days_until_expiry": days,
            "key_algorithm": f"{algo}Encryption",
            "key_algorithm_display": algo,
            "key_size": size,
            "not_after": "Jan 01 00:00:00 2027 GMT",
            "issuer": "Test CA",
            "sans": ["example.com", "www.example.com"],
        }

    def test_critical_finance_enterprise_high_score(self):
        scan = self._make_scan(grade="CRITICAL", days=90)
        result = score_lead(scan, "finance", "enterprise")
        self.assertGreaterEqual(result["pqc_urgency_score"], 80)
        self.assertEqual(result["urgency"], "IMMEDIATE")

    def test_pqc_ready_low_score(self):
        scan = self._make_scan(grade="PQC_READY", days=730)
        result = score_lead(scan, "education", "startup")
        self.assertLessEqual(result["pqc_urgency_score"], 20)

    def test_score_has_all_fields(self):
        scan = self._make_scan()
        result = score_lead(scan, "tech", "mid-market")
        self.assertIn("pqc_urgency_score", result)
        self.assertIn("factors", result)
        self.assertIn("recommended_service", result)
        self.assertIn("price_range", result)
        self.assertIn("urgency", result)

    def test_score_leads_sorts_descending(self):
        scans = [
            self._make_scan(grade="STRONG", days=730),
            self._make_scan(grade="CRITICAL", days=30),
            self._make_scan(grade="WEAK", days=365),
        ]
        scored = score_leads(scans)
        scores = [s["pqc_urgency_score"] for s in scored]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_score_leads_skips_errors(self):
        scans = [
            self._make_scan(),
            {"domain": "bad.com", "status": "error", "error": "timeout"},
        ]
        scored = score_leads(scans)
        self.assertEqual(len(scored), 1)

    def test_service_tiers_complete(self):
        """Every possible score maps to a service tier."""
        for s in range(0, 101):
            matched = False
            for tier in SERVICE_TIERS:
                if s >= tier["min_score"]:
                    matched = True
                    break
            self.assertTrue(matched, f"Score {s} has no tier")


class TestAuditor(unittest.TestCase):
    """Test audit trail hashing and payload generation."""

    def test_hash_deterministic(self):
        data = {"domain": "example.com", "score": 85}
        h1 = hash_report(data)
        h2 = hash_report(data)
        self.assertEqual(h1["hash"], h2["hash"])

    def test_hash_changes_with_data(self):
        h1 = hash_report({"score": 85})
        h2 = hash_report({"score": 86})
        self.assertNotEqual(h1["hash"], h2["hash"])

    def test_hash_format(self):
        result = hash_report({"test": True})
        self.assertEqual(len(result["hash"]), 64)  # SHA-256 hex
        self.assertEqual(result["algorithm"], "SHA-256")

    def test_hcs_payload_under_1kb(self):
        payload = generate_hcs_payload(
            "a" * 64, "very-long-domain-name.example.com", 85.5, "WEAK", "PQC Key Migration"
        )
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 1024)

    def test_hcs_payload_fields(self):
        payload = generate_hcs_payload("abc123", "example.com", 90, "CRITICAL", "Key Migration")
        self.assertEqual(payload["type"], "pqc-audit")
        self.assertEqual(payload["report_hash"], "abc123")
        self.assertEqual(payload["domain"], "example.com")


class TestReporter(unittest.TestCase):
    """Test report generation."""

    def _make_scored_lead(self, domain="example.com", score=75, grade="WEAK"):
        return {
            "domain": domain,
            "pqc_urgency_score": score,
            "urgency": "HIGH" if score >= 60 else "MEDIUM",
            "factors": {
                "crypto_weakness": {"grade": grade, "raw": 80, "weighted": 28},
                "cert_expiry": {"days_left": 180, "raw": 100, "weighted": 25},
                "industry": {"value": "finance", "raw": 100, "weighted": 20},
                "company_size": {"value": "enterprise", "raw": 100, "weighted": 20},
            },
            "recommended_service": "Hybrid Signature Implementation",
            "price_range": "$75K-$150K",
            "key_algorithm": "rsaEncryption",
            "key_algorithm_display": "RSA",
            "key_size": 2048,
            "cert_expiry_date": "Jan 01 00:00:00 2027 GMT",
            "issuer": "DigiCert Inc",
            "sans": ["example.com"],
        }

    def test_report_structure(self):
        leads = [self._make_scored_lead()]
        report = generate_report(leads)
        self.assertIn("summary", report)
        self.assertIn("findings", report)
        self.assertIn("recommendations", report)
        self.assertEqual(report["report_type"], "pqc-compliance-assessment")

    def test_report_summary_counts(self):
        leads = [
            self._make_scored_lead(score=85),
            self._make_scored_lead(domain="b.com", score=45),
        ]
        report = generate_report(leads)
        self.assertEqual(report["summary"]["total_domains_assessed"], 2)
        self.assertEqual(report["summary"]["critical_priority"], 1)

    def test_csv_output(self):
        leads = [self._make_scored_lead()]
        csv_str = to_csv(leads)
        self.assertIn("domain", csv_str)
        self.assertIn("example.com", csv_str)
        self.assertIn("pqc_urgency_score", csv_str)

    def test_text_output(self):
        leads = [self._make_scored_lead()]
        report = generate_report(leads)
        text = to_text(report)
        self.assertIn("PQC COMPLIANCE ASSESSMENT REPORT", text)
        self.assertIn("example.com", text)
        self.assertIn("RECOMMENDATIONS", text)

    def test_empty_leads_report(self):
        report = generate_report([])
        self.assertEqual(report["summary"]["total_domains_assessed"], 0)
        self.assertGreater(len(report["recommendations"]), 0)  # Should have "monitoring" rec


if __name__ == "__main__":
    unittest.main()
