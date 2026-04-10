"""Tests for scorer edge cases — expiry thresholds, tier boundaries, and defaults.

No network or external dependencies required.
"""

import unittest

from cli_anything.hiero_pqc.core.scorer import (
    _expiry_score,
    score_lead,
    score_leads,
    SERVICE_TIERS,
    INDUSTRY_SCORES,
    SIZE_SCORES,
    W_CRYPTO,
    W_EXPIRY,
    W_INDUSTRY,
    W_SIZE,
)


def _make_scan(grade="WEAK", days=365, algo="RSA", size=2048):
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
        "sans": ["example.com"],
    }


class TestExpiryScore(unittest.TestCase):
    """Test _expiry_score() threshold logic."""

    def test_negative_days_already_expired(self):
        self.assertEqual(_expiry_score(-1), 100)

    def test_negative_large_days(self):
        self.assertEqual(_expiry_score(-365), 100)

    def test_zero_days(self):
        """Expires today — should be 100 (within <=180 range)."""
        self.assertEqual(_expiry_score(0), 100)

    def test_180_days_boundary(self):
        self.assertEqual(_expiry_score(180), 100)

    def test_181_days_drops_to_70(self):
        self.assertEqual(_expiry_score(181), 70)

    def test_365_days_boundary(self):
        self.assertEqual(_expiry_score(365), 70)

    def test_366_days_drops_to_40(self):
        self.assertEqual(_expiry_score(366), 40)

    def test_730_days_boundary(self):
        self.assertEqual(_expiry_score(730), 40)

    def test_731_days_drops_to_10(self):
        self.assertEqual(_expiry_score(731), 10)

    def test_very_far_future(self):
        self.assertEqual(_expiry_score(3650), 10)


class TestServiceTierBoundaries(unittest.TestCase):
    """Test that scores map to the correct service tiers at boundaries."""

    def _score_with_total(self, target_total):
        """Create a scan that produces approximately the target total score.

        Uses known industry='other' (30) and size='unknown' (50) defaults,
        then adjusts crypto grade and expiry to hit the target.
        """
        # We test tier matching directly via score_lead output
        # by crafting inputs that produce specific score ranges.
        pass

    def test_tier_immediate_at_80(self):
        # CRITICAL(100)*0.35 + expired(100)*0.25 + finance(100)*0.20 + enterprise(100)*0.20 = 100
        scan = _make_scan(grade="CRITICAL", days=-1)
        result = score_lead(scan, "finance", "enterprise")
        self.assertGreaterEqual(result["pqc_urgency_score"], 80)
        self.assertEqual(result["urgency"], "IMMEDIATE")
        self.assertEqual(result["recommended_service"], "PQC Key Migration")

    def test_tier_high(self):
        # WEAK(80)*0.35 + 365d(70)*0.25 + tech(60)*0.20 + mid-market(70)*0.20 = 28+17.5+12+14 = 71.5
        scan = _make_scan(grade="WEAK", days=365)
        result = score_lead(scan, "tech", "mid-market")
        self.assertGreaterEqual(result["pqc_urgency_score"], 60)
        self.assertLess(result["pqc_urgency_score"], 80)
        self.assertEqual(result["urgency"], "HIGH")

    def test_tier_medium(self):
        # MODERATE(40)*0.35 + 731d(10)*0.25 + education(30)*0.20 + smb(40)*0.20 = 14+2.5+6+8 = 30.5
        # Actually that's LOW. Let's try: MODERATE(40)*0.35 + 365(70)*0.25 + tech(60)*0.20 + smb(40)*0.20
        # = 14+17.5+12+8 = 51.5 → MEDIUM
        scan = _make_scan(grade="MODERATE", days=365)
        result = score_lead(scan, "tech", "smb")
        self.assertGreaterEqual(result["pqc_urgency_score"], 40)
        self.assertLess(result["pqc_urgency_score"], 60)
        self.assertEqual(result["urgency"], "MEDIUM")

    def test_tier_low(self):
        # MODERATE(40)*0.35 + 731d(10)*0.25 + education(30)*0.20 + startup(20)*0.20 = 14+2.5+6+4 = 26.5
        scan = _make_scan(grade="MODERATE", days=731)
        result = score_lead(scan, "education", "startup")
        self.assertGreaterEqual(result["pqc_urgency_score"], 20)
        self.assertLess(result["pqc_urgency_score"], 40)
        self.assertEqual(result["urgency"], "LOW")

    def test_tier_future(self):
        # PQC_READY(0)*0.35 + 731d(10)*0.25 + education(30)*0.20 + startup(20)*0.20 = 0+2.5+6+4 = 12.5
        scan = _make_scan(grade="PQC_READY", days=731)
        result = score_lead(scan, "education", "startup")
        self.assertLess(result["pqc_urgency_score"], 20)
        self.assertEqual(result["urgency"], "FUTURE")


class TestScorerDefaults(unittest.TestCase):
    """Test handling of missing or unknown fields."""

    def test_missing_crypto_grade_defaults_to_error(self):
        scan = _make_scan()
        del scan["crypto_grade"]
        result = score_lead(scan)
        # ERROR maps to crypto score 50
        crypto_component = round(50 * W_CRYPTO, 1)
        self.assertIn("factors", result)
        self.assertEqual(result["factors"]["crypto_weakness"]["raw"], 50)

    def test_unknown_industry_defaults_to_30(self):
        scan = _make_scan()
        result = score_lead(scan, industry="underwater_basket_weaving")
        self.assertEqual(result["factors"]["industry"]["raw"], 30)

    def test_unknown_size_defaults_to_50(self):
        scan = _make_scan()
        result = score_lead(scan, company_size="mega_corp")
        self.assertEqual(result["factors"]["company_size"]["raw"], 50)

    def test_missing_days_defaults_to_negative(self):
        scan = _make_scan()
        del scan["days_until_expiry"]
        result = score_lead(scan)
        # -1 days → expiry_score = 100
        self.assertEqual(result["factors"]["cert_expiry"]["raw"], 100)

    def test_all_industries_in_lookup(self):
        """Every industry key in INDUSTRY_SCORES returns a numeric value."""
        for industry, score in INDUSTRY_SCORES.items():
            self.assertIsInstance(score, (int, float))
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_all_sizes_in_lookup(self):
        """Every size key in SIZE_SCORES returns a numeric value."""
        for size, score in SIZE_SCORES.items():
            self.assertIsInstance(score, (int, float))
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)


class TestScoreLeadsHints(unittest.TestCase):
    """Test score_leads with industry and size hints."""

    def test_industry_hints_override_default(self):
        scans = [_make_scan()]
        scans[0]["domain"] = "bank.com"
        scored = score_leads(
            scans,
            default_industry="other",
            industry_hints={"bank.com": "finance"},
        )
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0]["factors"]["industry"]["value"], "finance")
        self.assertEqual(scored[0]["factors"]["industry"]["raw"], 100)

    def test_size_hints_override_default(self):
        scans = [_make_scan()]
        scans[0]["domain"] = "bigco.com"
        scored = score_leads(
            scans,
            default_size="startup",
            size_hints={"bigco.com": "enterprise"},
        )
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0]["factors"]["company_size"]["value"], "enterprise")
        self.assertEqual(scored[0]["factors"]["company_size"]["raw"], 100)

    def test_hints_only_apply_to_matching_domain(self):
        scans = [_make_scan(), _make_scan()]
        scans[0]["domain"] = "bank.com"
        scans[1]["domain"] = "shop.com"
        scored = score_leads(
            scans,
            default_industry="other",
            industry_hints={"bank.com": "finance"},
        )
        bank = next(s for s in scored if s["domain"] == "bank.com")
        shop = next(s for s in scored if s["domain"] == "shop.com")
        self.assertEqual(bank["factors"]["industry"]["raw"], 100)  # finance
        self.assertEqual(shop["factors"]["industry"]["raw"], 30)   # other

    def test_weights_sum_to_one(self):
        """Factor weights must sum to 1.0 for scoring to be normalized."""
        self.assertAlmostEqual(W_CRYPTO + W_EXPIRY + W_INDUSTRY + W_SIZE, 1.0)


if __name__ == "__main__":
    unittest.main()
