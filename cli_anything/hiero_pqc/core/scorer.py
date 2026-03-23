"""
PQC Vulnerability Scorer — multi-factor lead scoring for quantum migration urgency.

Standalone module — no external dependencies.
Scores domains based on: crypto weakness, cert expiry, industry risk, company size.
"""

from typing import Any, Dict, List


# Service tier mapping based on urgency score
SERVICE_TIERS = [
    {"min_score": 80, "service": "PQC Key Migration", "price_range": "$250K-$1M+", "urgency": "IMMEDIATE"},
    {"min_score": 60, "service": "Hybrid Signature Implementation", "price_range": "$75K-$150K", "urgency": "HIGH"},
    {"min_score": 40, "service": "PQC Readiness Assessment", "price_range": "$25K-$50K", "urgency": "MEDIUM"},
    {"min_score": 20, "service": "Compliance Mapping", "price_range": "$50K-$100K", "urgency": "LOW"},
    {"min_score": 0, "service": "PKI Modernization Consulting", "price_range": "$10K-$50K/mo", "urgency": "FUTURE"},
]

INDUSTRY_SCORES = {
    "finance": 100, "banking": 100, "insurance": 90,
    "healthcare": 95, "government": 100, "defense": 100,
    "fintech": 85, "payments": 85, "crypto": 70,
    "tech": 60, "saas": 50, "ecommerce": 45,
    "education": 30, "other": 30,
}

SIZE_SCORES = {
    "enterprise": 100, "mid-market": 70, "smb": 40, "startup": 20, "unknown": 50,
}

# Factor weights (must sum to 1.0)
W_CRYPTO = 0.35
W_EXPIRY = 0.25
W_INDUSTRY = 0.20
W_SIZE = 0.20

CRYPTO_SCORES = {
    "CRITICAL": 100, "WEAK": 80, "MODERATE": 40, "STRONG": 10, "PQC_READY": 0, "ERROR": 50,
}


def _expiry_score(days: int) -> float:
    """Score based on certificate expiry proximity."""
    if days < 0:
        return 100  # Already expired
    if days <= 180:
        return 100
    if days <= 365:
        return 70
    if days <= 730:
        return 40
    return 10


def score_lead(
    scan_result: Dict[str, Any],
    industry: str = "other",
    company_size: str = "unknown",
) -> Dict[str, Any]:
    """Score a single scanned domain for PQC migration urgency.

    Args:
        scan_result: Output from scanner.scan_domain() with status=="scanned".
        industry: Industry vertical (finance, healthcare, government, etc.).
        company_size: Company size (enterprise, mid-market, smb, startup).

    Returns:
        Scored lead with urgency score, factors breakdown, and recommended service.
    """
    crypto_grade = scan_result.get("crypto_grade", "ERROR")
    days_left = scan_result.get("days_until_expiry", -1)

    crypto_s = CRYPTO_SCORES.get(crypto_grade, 50)
    expiry_s = _expiry_score(days_left)
    industry_s = INDUSTRY_SCORES.get(industry.lower(), 30)
    size_s = SIZE_SCORES.get(company_size.lower(), 50)

    total = round(
        crypto_s * W_CRYPTO
        + expiry_s * W_EXPIRY
        + industry_s * W_INDUSTRY
        + size_s * W_SIZE,
        1,
    )

    # Match to service tier
    tier = SERVICE_TIERS[-1]
    for t in SERVICE_TIERS:
        if total >= t["min_score"]:
            tier = t
            break

    return {
        "domain": scan_result.get("domain", ""),
        "pqc_urgency_score": total,
        "factors": {
            "crypto_weakness": {"grade": crypto_grade, "raw": crypto_s, "weighted": round(crypto_s * W_CRYPTO, 1)},
            "cert_expiry": {"days_left": days_left, "raw": expiry_s, "weighted": round(expiry_s * W_EXPIRY, 1)},
            "industry": {"value": industry, "raw": industry_s, "weighted": round(industry_s * W_INDUSTRY, 1)},
            "company_size": {"value": company_size, "raw": size_s, "weighted": round(size_s * W_SIZE, 1)},
        },
        "recommended_service": tier["service"],
        "price_range": tier["price_range"],
        "urgency": tier["urgency"],
        "key_algorithm": scan_result.get("key_algorithm", "Unknown"),
        "key_algorithm_display": scan_result.get("key_algorithm_display", "Unknown"),
        "key_size": scan_result.get("key_size", 0),
        "cert_expiry_date": scan_result.get("not_after", "Unknown"),
        "issuer": scan_result.get("issuer", "Unknown"),
        "sans": scan_result.get("sans", []),
    }


def score_leads(
    scan_results: List[Dict[str, Any]],
    default_industry: str = "other",
    default_size: str = "unknown",
    industry_hints: Dict[str, str] = None,
    size_hints: Dict[str, str] = None,
) -> List[Dict[str, Any]]:
    """Score multiple scan results, sorted by urgency (highest first).

    Args:
        scan_results: List of scanner outputs.
        default_industry: Default industry if not in hints.
        default_size: Default company size if not in hints.
        industry_hints: {domain: industry} overrides.
        size_hints: {domain: size} overrides.

    Returns:
        Scored leads sorted by pqc_urgency_score descending.
    """
    industry_hints = industry_hints or {}
    size_hints = size_hints or {}
    scored = []

    for result in scan_results:
        if result.get("status") != "scanned":
            continue
        domain = result["domain"]
        industry = industry_hints.get(domain, default_industry)
        size = size_hints.get(domain, default_size)
        scored.append(score_lead(result, industry, size))

    scored.sort(key=lambda x: x["pqc_urgency_score"], reverse=True)
    return scored
