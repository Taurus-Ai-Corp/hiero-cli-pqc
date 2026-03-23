"""
PQC Compliance Report Generator.

Generates structured reports from scan + score results in multiple formats:
JSON, CSV, and human-readable text.
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_report(
    scored_leads: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]] = None,
    metadata: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Generate a full PQC compliance report from scored leads.

    Args:
        scored_leads: Output from scorer.score_leads().
        scan_results: Raw scan data (optional, for reference).
        metadata: Additional report metadata (industry, requestor, etc.).

    Returns:
        Complete report dict with summary, findings, and recommendations.
    """
    metadata = metadata or {}
    total = len(scored_leads)
    critical = [l for l in scored_leads if l.get("pqc_urgency_score", 0) >= 80]
    high = [l for l in scored_leads if 60 <= l.get("pqc_urgency_score", 0) < 80]
    medium = [l for l in scored_leads if 40 <= l.get("pqc_urgency_score", 0) < 60]
    low = [l for l in scored_leads if l.get("pqc_urgency_score", 0) < 40]

    # Algorithm distribution
    algo_dist: Dict[str, int] = {}
    for lead in scored_leads:
        algo = lead.get("key_algorithm_display", "Unknown")
        algo_dist[algo] = algo_dist.get(algo, 0) + 1

    # Grade distribution
    grade_dist: Dict[str, int] = {}
    for lead in scored_leads:
        grade = lead.get("factors", {}).get("crypto_weakness", {}).get("grade", "Unknown")
        grade_dist[grade] = grade_dist.get(grade, 0) + 1

    report = {
        "report_type": "pqc-compliance-assessment",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "hiero-cli-pqc",
        "metadata": metadata,
        "summary": {
            "total_domains_assessed": total,
            "critical_priority": len(critical),
            "high_priority": len(high),
            "medium_priority": len(medium),
            "low_or_future": len(low),
            "algorithm_distribution": algo_dist,
            "grade_distribution": grade_dist,
        },
        "findings": scored_leads,
        "recommendations": _generate_recommendations(scored_leads),
    }

    # Include raw scan data if provided
    if scan_results:
        failed = [r for r in scan_results if r.get("status") != "scanned"]
        report["scan_metadata"] = {
            "total_attempted": len(scan_results),
            "successful_scans": len(scan_results) - len(failed),
            "failed_scans": len(failed),
            "failures": [{"domain": r["domain"], "error": r.get("error", "")} for r in failed],
        }

    return report


def _generate_recommendations(scored_leads: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Generate actionable recommendations based on findings."""
    recs = []

    critical = [l for l in scored_leads if l.get("pqc_urgency_score", 0) >= 80]
    if critical:
        domains = ", ".join(l["domain"] for l in critical[:5])
        recs.append({
            "priority": "IMMEDIATE",
            "category": "Key Migration",
            "recommendation": f"Begin PQC key migration for {len(critical)} domain(s) using RSA-2048 or weaker: {domains}",
            "standard": "NIST SP 800-131A Rev 2, CNSA 2.0",
            "timeline": "0-6 months",
        })

    weak_rsa = [l for l in scored_leads if l.get("key_algorithm_display") == "RSA" and l.get("key_size", 0) <= 2048]
    if weak_rsa:
        recs.append({
            "priority": "HIGH",
            "category": "Hybrid Signatures",
            "recommendation": f"Implement ML-DSA + RSA hybrid signatures for {len(weak_rsa)} domain(s) as transition measure",
            "standard": "NIST FIPS 204 (ML-DSA-65)",
            "timeline": "3-12 months",
        })

    ecdsa = [l for l in scored_leads if l.get("key_algorithm_display") == "ECDSA"]
    if ecdsa:
        recs.append({
            "priority": "MEDIUM",
            "category": "ECDSA Migration",
            "recommendation": f"Plan ECDSA to ML-DSA migration for {len(ecdsa)} domain(s) — all elliptic curves are quantum-vulnerable",
            "standard": "NIST FIPS 204",
            "timeline": "6-18 months",
        })

    expiring = [l for l in scored_leads if l.get("factors", {}).get("cert_expiry", {}).get("days_left", 999) < 180]
    if expiring:
        recs.append({
            "priority": "HIGH",
            "category": "Certificate Renewal",
            "recommendation": f"{len(expiring)} certificate(s) expiring within 180 days — renew with PQC-ready algorithms",
            "standard": "CA/Browser Forum Baseline Requirements",
            "timeline": "Immediate",
        })

    if not recs:
        recs.append({
            "priority": "LOW",
            "category": "Monitoring",
            "recommendation": "All assessed domains show adequate cryptographic posture. Continue monitoring for PQC readiness.",
            "standard": "NIST SP 800-57",
            "timeline": "Ongoing",
        })

    return recs


def to_csv(scored_leads: List[Dict[str, Any]]) -> str:
    """Convert scored leads to CSV format for CRM import.

    Returns CSV string with headers.
    """
    output = io.StringIO()
    fieldnames = [
        "domain", "pqc_urgency_score", "urgency", "crypto_grade",
        "key_algorithm", "key_size", "cert_expiry_date", "days_until_expiry",
        "recommended_service", "price_range", "issuer", "industry", "company_size",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for lead in scored_leads:
        factors = lead.get("factors", {})
        writer.writerow({
            "domain": lead.get("domain", ""),
            "pqc_urgency_score": lead.get("pqc_urgency_score", 0),
            "urgency": lead.get("urgency", ""),
            "crypto_grade": factors.get("crypto_weakness", {}).get("grade", ""),
            "key_algorithm": lead.get("key_algorithm_display", ""),
            "key_size": lead.get("key_size", 0),
            "cert_expiry_date": lead.get("cert_expiry_date", ""),
            "days_until_expiry": factors.get("cert_expiry", {}).get("days_left", -1),
            "recommended_service": lead.get("recommended_service", ""),
            "price_range": lead.get("price_range", ""),
            "issuer": lead.get("issuer", ""),
            "industry": factors.get("industry", {}).get("value", ""),
            "company_size": factors.get("company_size", {}).get("value", ""),
        })

    return output.getvalue()


def to_text(report: Dict[str, Any]) -> str:
    """Generate human-readable text report.

    Returns formatted text suitable for terminal display or plain text file.
    """
    lines = []
    lines.append("=" * 72)
    lines.append("  PQC COMPLIANCE ASSESSMENT REPORT")
    lines.append(f"  Generated: {report.get('generated_at', 'N/A')}")
    lines.append(f"  Tool: hiero-cli-pqc v{report.get('version', '1.0')}")
    lines.append("=" * 72)
    lines.append("")

    summary = report.get("summary", {})
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Domains Assessed:    {summary.get('total_domains_assessed', 0)}")
    lines.append(f"  Critical Priority:   {summary.get('critical_priority', 0)}")
    lines.append(f"  High Priority:       {summary.get('high_priority', 0)}")
    lines.append(f"  Medium Priority:     {summary.get('medium_priority', 0)}")
    lines.append(f"  Low/Future:          {summary.get('low_or_future', 0)}")
    lines.append("")

    algo_dist = summary.get("algorithm_distribution", {})
    if algo_dist:
        lines.append("ALGORITHM DISTRIBUTION")
        lines.append("-" * 40)
        for algo, count in sorted(algo_dist.items(), key=lambda x: -x[1]):
            lines.append(f"  {algo:<20} {count}")
        lines.append("")

    findings = report.get("findings", [])
    if findings:
        lines.append("TOP FINDINGS (by urgency)")
        lines.append("-" * 72)
        for i, lead in enumerate(findings[:20], 1):
            factors = lead.get("factors", {})
            grade = factors.get("crypto_weakness", {}).get("grade", "?")
            lines.append(
                f"  {i:>2}. {lead['domain']:<35} "
                f"Score: {lead['pqc_urgency_score']:>5.1f}  "
                f"Grade: {grade:<10} "
                f"[{lead.get('urgency', '?')}]"
            )
            lines.append(
                f"      {lead.get('key_algorithm_display', '?')} {lead.get('key_size', '?')}-bit  |  "
                f"Expires: {lead.get('cert_expiry_date', 'N/A')[:20]}  |  "
                f"{lead.get('recommended_service', '')}"
            )
        lines.append("")

    recs = report.get("recommendations", [])
    if recs:
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 72)
        for rec in recs:
            lines.append(f"  [{rec['priority']}] {rec['category']}")
            lines.append(f"    {rec['recommendation']}")
            lines.append(f"    Standard: {rec.get('standard', 'N/A')}  |  Timeline: {rec.get('timeline', 'N/A')}")
            lines.append("")

    lines.append("=" * 72)
    lines.append("  Report generated by hiero-cli-pqc | TAURUS AI Corp")
    lines.append("  https://github.com/Taurus-Ai-Corp/hiero-cli-pqc")
    lines.append("=" * 72)

    return "\n".join(lines)
