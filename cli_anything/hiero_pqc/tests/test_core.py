     1|"""Unit tests for gridera-scan core modules.
     2|
     3|Tests use synthetic data — no network or OpenSSL required.
     4|"""
     5|
     6|import json
     7|import unittest
     8|
     9|from cli_anything.hiero_pqc.core.scanner import classify_crypto, parse_cert, CRYPTO_GRADES
    10|from cli_anything.hiero_pqc.core.scorer import score_lead, score_leads, SERVICE_TIERS
    11|from cli_anything.hiero_pqc.core.auditor import hash_report, generate_hcs_payload
    12|from cli_anything.hiero_pqc.core.reporter import generate_report, to_csv, to_text
    13|
    14|
    15|class TestCryptoClassification(unittest.TestCase):
    16|    """Test quantum vulnerability classification."""
    17|
    18|    def test_rsa_1024_critical(self):
    19|        self.assertEqual(classify_crypto("rsaEncryption", 1024), "CRITICAL")
    20|
    21|    def test_rsa_2048_weak(self):
    22|        self.assertEqual(classify_crypto("rsaEncryption", 2048), "WEAK")
    23|
    24|    def test_rsa_3072_moderate(self):
    25|        self.assertEqual(classify_crypto("rsaEncryption", 3072), "MODERATE")
    26|
    27|    def test_rsa_4096_strong(self):
    28|        self.assertEqual(classify_crypto("rsaEncryption", 4096), "STRONG")
    29|
    30|    def test_ecdsa_256_weak(self):
    31|        self.assertEqual(classify_crypto("id-ecPublicKey", 256), "WEAK")
    32|
    33|    def test_ecdsa_384_moderate(self):
    34|        self.assertEqual(classify_crypto("id-ecPublicKey", 384), "MODERATE")
    35|
    36|    def test_ed25519_moderate(self):
    37|        self.assertEqual(classify_crypto("ED25519", 256), "MODERATE")
    38|
    39|    def test_ml_kem_pqc_ready(self):
    40|        self.assertEqual(classify_crypto("ML-KEM-768", 768), "PQC_READY")
    41|
    42|    def test_ml_dsa_pqc_ready(self):
    43|        self.assertEqual(classify_crypto("ML-DSA-65", 0), "PQC_READY")
    44|
    45|    def test_dilithium_pqc_ready(self):
    46|        self.assertEqual(classify_crypto("Dilithium3", 0), "PQC_READY")
    47|
    48|    def test_kyber_pqc_ready(self):
    49|        self.assertEqual(classify_crypto("Kyber768", 0), "PQC_READY")
    50|
    51|    def test_unknown_defaults_weak(self):
    52|        self.assertEqual(classify_crypto("SomeUnknownAlgo", 0), "WEAK")
    53|
    54|    def test_all_grades_have_scores(self):
    55|        for grade in CRYPTO_GRADES:
    56|            self.assertIn("score", CRYPTO_GRADES[grade])
    57|            self.assertIn("label", CRYPTO_GRADES[grade])
    58|
    59|
    60|class TestScorer(unittest.TestCase):
    61|    """Test PQC urgency scoring."""
    62|
    63|    def _make_scan(self, grade="WEAK", days=365, algo="RSA", size=2048):
    64|        return {
    65|            "domain": "example.com",
    66|            "status": "scanned",
    67|            "crypto_grade": grade,
    68|            "days_until_expiry": days,
    69|            "key_algorithm": f"{algo}Encryption",
    70|            "key_algorithm_display": algo,
    71|            "key_size": size,
    72|            "not_after": "Jan 01 00:00:00 2027 GMT",
    73|            "issuer": "Test CA",
    74|            "sans": ["example.com", "www.example.com"],
    75|        }
    76|
    77|    def test_critical_finance_enterprise_high_score(self):
    78|        scan = self._make_scan(grade="CRITICAL", days=90)
    79|        result = score_lead(scan, "finance", "enterprise")
    80|        self.assertGreaterEqual(result["pqc_urgency_score"], 80)
    81|        self.assertEqual(result["urgency"], "IMMEDIATE")
    82|
    83|    def test_pqc_ready_low_score(self):
    84|        scan = self._make_scan(grade="PQC_READY", days=730)
    85|        result = score_lead(scan, "education", "startup")
    86|        self.assertLessEqual(result["pqc_urgency_score"], 20)
    87|
    88|    def test_score_has_all_fields(self):
    89|        scan = self._make_scan()
    90|        result = score_lead(scan, "tech", "mid-market")
    91|        self.assertIn("pqc_urgency_score", result)
    92|        self.assertIn("factors", result)
    93|        self.assertIn("recommended_service", result)
    94|        self.assertIn("price_range", result)
    95|        self.assertIn("urgency", result)
    96|
    97|    def test_score_leads_sorts_descending(self):
    98|        scans = [
    99|            self._make_scan(grade="STRONG", days=730),
   100|            self._make_scan(grade="CRITICAL", days=30),
   101|            self._make_scan(grade="WEAK", days=365),
   102|        ]
   103|        scored = score_leads(scans)
   104|        scores = [s["pqc_urgency_score"] for s in scored]
   105|        self.assertEqual(scores, sorted(scores, reverse=True))
   106|
   107|    def test_score_leads_skips_errors(self):
   108|        scans = [
   109|            self._make_scan(),
   110|            {"domain": "bad.com", "status": "error", "error": "timeout"},
   111|        ]
   112|        scored = score_leads(scans)
   113|        self.assertEqual(len(scored), 1)
   114|
   115|    def test_service_tiers_complete(self):
   116|        """Every possible score maps to a service tier."""
   117|        for s in range(0, 101):
   118|            matched = False
   119|            for tier in SERVICE_TIERS:
   120|                if s >= tier["min_score"]:
   121|                    matched = True
   122|                    break
   123|            self.assertTrue(matched, f"Score {s} has no tier")
   124|
   125|
   126|class TestAuditor(unittest.TestCase):
   127|    """Test audit trail hashing and payload generation."""
   128|
   129|    def test_hash_deterministic(self):
   130|        data = {"domain": "example.com", "score": 85}
   131|        h1 = hash_report(data)
   132|        h2 = hash_report(data)
   133|        self.assertEqual(h1["hash"], h2["hash"])
   134|
   135|    def test_hash_changes_with_data(self):
   136|        h1 = hash_report({"score": 85})
   137|        h2 = hash_report({"score": 86})
   138|        self.assertNotEqual(h1["hash"], h2["hash"])
   139|
   140|    def test_hash_format(self):
   141|        result = hash_report({"test": True})
   142|        self.assertEqual(len(result["hash"]), 64)  # SHA-256 hex
   143|        self.assertEqual(result["algorithm"], "SHA-256")
   144|
   145|    def test_hcs_payload_under_1kb(self):
   146|        payload = generate_hcs_payload(
   147|            "a" * 64, "very-long-domain-name.example.com", 85.5, "WEAK", "PQC Key Migration"
   148|        )
   149|        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
   150|        self.assertLessEqual(len(encoded), 1024)
   151|
   152|    def test_hcs_payload_fields(self):
   153|        payload = generate_hcs_payload("abc123", "example.com", 90, "CRITICAL", "Key Migration")
   154|        self.assertEqual(payload["type"], "pqc-audit")
   155|        self.assertEqual(payload["report_hash"], "abc123")
   156|        self.assertEqual(payload["domain"], "example.com")
   157|
   158|
   159|class TestReporter(unittest.TestCase):
   160|    """Test report generation."""
   161|
   162|    def _make_scored_lead(self, domain="example.com", score=75, grade="WEAK"):
   163|        return {
   164|            "domain": domain,
   165|            "pqc_urgency_score": score,
   166|            "urgency": "HIGH" if score >= 60 else "MEDIUM",
   167|            "factors": {
   168|                "crypto_weakness": {"grade": grade, "raw": 80, "weighted": 28},
   169|                "cert_expiry": {"days_left": 180, "raw": 100, "weighted": 25},
   170|                "industry": {"value": "finance", "raw": 100, "weighted": 20},
   171|                "company_size": {"value": "enterprise", "raw": 100, "weighted": 20},
   172|            },
   173|            "recommended_service": "Hybrid Signature Implementation",
   174|            "price_range": "$75K-$150K",
   175|            "key_algorithm": "rsaEncryption",
   176|            "key_algorithm_display": "RSA",
   177|            "key_size": 2048,
   178|            "cert_expiry_date": "Jan 01 00:00:00 2027 GMT",
   179|            "issuer": "DigiCert Inc",
   180|            "sans": ["example.com"],
   181|        }
   182|
   183|    def test_report_structure(self):
   184|        leads = [self._make_scored_lead()]
   185|        report = generate_report(leads)
   186|        self.assertIn("summary", report)
   187|        self.assertIn("findings", report)
   188|        self.assertIn("recommendations", report)
   189|        self.assertEqual(report["report_type"], "pqc-compliance-assessment")
   190|
   191|    def test_report_summary_counts(self):
   192|        leads = [
   193|            self._make_scored_lead(score=85),
   194|            self._make_scored_lead(domain="b.com", score=45),
   195|        ]
   196|        report = generate_report(leads)
   197|        self.assertEqual(report["summary"]["total_domains_assessed"], 2)
   198|        self.assertEqual(report["summary"]["critical_priority"], 1)
   199|
   200|    def test_csv_output(self):
   201|        leads = [self._make_scored_lead()]
   202|        csv_str = to_csv(leads)
   203|        self.assertIn("domain", csv_str)
   204|        self.assertIn("example.com", csv_str)
   205|        self.assertIn("pqc_urgency_score", csv_str)
   206|
   207|    def test_text_output(self):
   208|        leads = [self._make_scored_lead()]
   209|        report = generate_report(leads)
   210|        text = to_text(report)
   211|        self.assertIn("PQC COMPLIANCE ASSESSMENT REPORT", text)
   212|        self.assertIn("example.com", text)
   213|        self.assertIn("RECOMMENDATIONS", text)
   214|
   215|    def test_empty_leads_report(self):
   216|        report = generate_report([])
   217|        self.assertEqual(report["summary"]["total_domains_assessed"], 0)
   218|        self.assertGreater(len(report["recommendations"]), 0)  # Should have "monitoring" rec
   219|
   220|
   221|if __name__ == "__main__":
   222|    unittest.main()
   223|