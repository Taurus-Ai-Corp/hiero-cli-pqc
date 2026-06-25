     1|"""
     2|PQC Compliance Report Generator.
     3|
     4|Generates structured reports from scan + score results in multiple formats:
     5|JSON, CSV, and human-readable text.
     6|"""
     7|
     8|import csv
     9|import io
    10|import json
    11|from datetime import datetime, timezone
    12|from typing import Any, Dict, List
    13|
    14|
    15|def generate_report(
    16|    scored_leads: List[Dict[str, Any]],
    17|    scan_results: List[Dict[str, Any]] = None,
    18|    metadata: Dict[str, Any] = None,
    19|) -> Dict[str, Any]:
    20|    """Generate a full PQC compliance report from scored leads.
    21|
    22|    Args:
    23|        scored_leads: Output from scorer.score_leads().
    24|        scan_results: Raw scan data (optional, for reference).
    25|        metadata: Additional report metadata (industry, requestor, etc.).
    26|
    27|    Returns:
    28|        Complete report dict with summary, findings, and recommendations.
    29|    """
    30|    metadata = metadata or {}
    31|    total = len(scored_leads)
    32|    critical = [l for l in scored_leads if l.get("pqc_urgency_score", 0) >= 80]
    33|    high = [l for l in scored_leads if 60 <= l.get("pqc_urgency_score", 0) < 80]
    34|    medium = [l for l in scored_leads if 40 <= l.get("pqc_urgency_score", 0) < 60]
    35|    low = [l for l in scored_leads if l.get("pqc_urgency_score", 0) < 40]
    36|
    37|    # Algorithm distribution
    38|    algo_dist: Dict[str, int] = {}
    39|    for lead in scored_leads:
    40|        algo = lead.get("key_algorithm_display", "Unknown")
    41|        algo_dist[algo] = algo_dist.get(algo, 0) + 1
    42|
    43|    # Grade distribution
    44|    grade_dist: Dict[str, int] = {}
    45|    for lead in scored_leads:
    46|        grade = lead.get("factors", {}).get("crypto_weakness", {}).get("grade", "Unknown")
    47|        grade_dist[grade] = grade_dist.get(grade, 0) + 1
    48|
    49|    report = {
    50|        "report_type": "pqc-compliance-assessment",
    51|        "version": "1.0",
    52|        "generated_at": datetime.now(timezone.utc).isoformat(),
    53|        "generator": "gridera-scan",
    54|        "metadata": metadata,
    55|        "summary": {
    56|            "total_domains_assessed": total,
    57|            "critical_priority": len(critical),
    58|            "high_priority": len(high),
    59|            "medium_priority": len(medium),
    60|            "low_or_future": len(low),
    61|            "algorithm_distribution": algo_dist,
    62|            "grade_distribution": grade_dist,
    63|        },
    64|        "findings": scored_leads,
    65|        "recommendations": _generate_recommendations(scored_leads),
    66|    }
    67|
    68|    # Include raw scan data if provided
    69|    if scan_results:
    70|        failed = [r for r in scan_results if r.get("status") != "scanned"]
    71|        report["scan_metadata"] = {
    72|            "total_attempted": len(scan_results),
    73|            "successful_scans": len(scan_results) - len(failed),
    74|            "failed_scans": len(failed),
    75|            "failures": [{"domain": r["domain"], "error": r.get("error", "")} for r in failed],
    76|        }
    77|
    78|    return report
    79|
    80|
    81|def _generate_recommendations(scored_leads: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    82|    """Generate actionable recommendations based on findings."""
    83|    recs = []
    84|
    85|    critical = [l for l in scored_leads if l.get("pqc_urgency_score", 0) >= 80]
    86|    if critical:
    87|        domains = ", ".join(l["domain"] for l in critical[:5])
    88|        recs.append({
    89|            "priority": "IMMEDIATE",
    90|            "category": "Key Migration",
    91|            "recommendation": f"Begin PQC key migration for {len(critical)} domain(s) using RSA-2048 or weaker: {domains}",
    92|            "standard": "NIST SP 800-131A Rev 2, CNSA 2.0",
    93|            "timeline": "0-6 months",
    94|        })
    95|
    96|    weak_rsa = [l for l in scored_leads if l.get("key_algorithm_display") == "RSA" and l.get("key_size", 0) <= 2048]
    97|    if weak_rsa:
    98|        recs.append({
    99|            "priority": "HIGH",
   100|            "category": "Hybrid Signatures",
   101|            "recommendation": f"Implement ML-DSA + RSA hybrid signatures for {len(weak_rsa)} domain(s) as transition measure",
   102|            "standard": "NIST FIPS 204 (ML-DSA-65)",
   103|            "timeline": "3-12 months",
   104|        })
   105|
   106|    ecdsa = [l for l in scored_leads if l.get("key_algorithm_display") == "ECDSA"]
   107|    if ecdsa:
   108|        recs.append({
   109|            "priority": "MEDIUM",
   110|            "category": "ECDSA Migration",
   111|            "recommendation": f"Plan ECDSA to ML-DSA migration for {len(ecdsa)} domain(s) — all elliptic curves are quantum-vulnerable",
   112|            "standard": "NIST FIPS 204",
   113|            "timeline": "6-18 months",
   114|        })
   115|
   116|    expiring = [l for l in scored_leads if l.get("factors", {}).get("cert_expiry", {}).get("days_left", 999) < 180]
   117|    if expiring:
   118|        recs.append({
   119|            "priority": "HIGH",
   120|            "category": "Certificate Renewal",
   121|            "recommendation": f"{len(expiring)} certificate(s) expiring within 180 days — renew with PQC-ready algorithms",
   122|            "standard": "CA/Browser Forum Baseline Requirements",
   123|            "timeline": "Immediate",
   124|        })
   125|
   126|    if not recs:
   127|        recs.append({
   128|            "priority": "LOW",
   129|            "category": "Monitoring",
   130|            "recommendation": "All assessed domains show adequate cryptographic posture. Continue monitoring for PQC readiness.",
   131|            "standard": "NIST SP 800-57",
   132|            "timeline": "Ongoing",
   133|        })
   134|
   135|    return recs
   136|
   137|
   138|def to_csv(scored_leads: List[Dict[str, Any]]) -> str:
   139|    """Convert scored leads to CSV format for CRM import.
   140|
   141|    Returns CSV string with headers.
   142|    """
   143|    output = io.StringIO()
   144|    fieldnames = [
   145|        "domain", "pqc_urgency_score", "urgency", "crypto_grade",
   146|        "key_algorithm", "key_size", "cert_expiry_date", "days_until_expiry",
   147|        "recommended_service", "price_range", "issuer", "industry", "company_size",
   148|    ]
   149|    writer = csv.DictWriter(output, fieldnames=fieldnames)
   150|    writer.writeheader()
   151|
   152|    for lead in scored_leads:
   153|        factors = lead.get("factors", {})
   154|        writer.writerow({
   155|            "domain": lead.get("domain", ""),
   156|            "pqc_urgency_score": lead.get("pqc_urgency_score", 0),
   157|            "urgency": lead.get("urgency", ""),
   158|            "crypto_grade": factors.get("crypto_weakness", {}).get("grade", ""),
   159|            "key_algorithm": lead.get("key_algorithm_display", ""),
   160|            "key_size": lead.get("key_size", 0),
   161|            "cert_expiry_date": lead.get("cert_expiry_date", ""),
   162|            "days_until_expiry": factors.get("cert_expiry", {}).get("days_left", -1),
   163|            "recommended_service": lead.get("recommended_service", ""),
   164|            "price_range": lead.get("price_range", ""),
   165|            "issuer": lead.get("issuer", ""),
   166|            "industry": factors.get("industry", {}).get("value", ""),
   167|            "company_size": factors.get("company_size", {}).get("value", ""),
   168|        })
   169|
   170|    return output.getvalue()
   171|
   172|
   173|def to_text(report: Dict[str, Any]) -> str:
   174|    """Generate human-readable text report.
   175|
   176|    Returns formatted text suitable for terminal display or plain text file.
   177|    """
   178|    lines = []
   179|    lines.append("=" * 72)
   180|    lines.append("  PQC COMPLIANCE ASSESSMENT REPORT")
   181|    lines.append(f"  Generated: {report.get('generated_at', 'N/A')}")
   182|    lines.append(f"  Tool: gridera-scan v{report.get('version', '1.0')}")
   183|    lines.append("=" * 72)
   184|    lines.append("")
   185|
   186|    summary = report.get("summary", {})
   187|    lines.append("EXECUTIVE SUMMARY")
   188|    lines.append("-" * 40)
   189|    lines.append(f"  Domains Assessed:    {summary.get('total_domains_assessed', 0)}")
   190|    lines.append(f"  Critical Priority:   {summary.get('critical_priority', 0)}")
   191|    lines.append(f"  High Priority:       {summary.get('high_priority', 0)}")
   192|    lines.append(f"  Medium Priority:     {summary.get('medium_priority', 0)}")
   193|    lines.append(f"  Low/Future:          {summary.get('low_or_future', 0)}")
   194|    lines.append("")
   195|
   196|    algo_dist = summary.get("algorithm_distribution", {})
   197|    if algo_dist:
   198|        lines.append("ALGORITHM DISTRIBUTION")
   199|        lines.append("-" * 40)
   200|        for algo, count in sorted(algo_dist.items(), key=lambda x: -x[1]):
   201|            lines.append(f"  {algo:<20} {count}")
   202|        lines.append("")
   203|
   204|    findings = report.get("findings", [])
   205|    if findings:
   206|        lines.append("TOP FINDINGS (by urgency)")
   207|        lines.append("-" * 72)
   208|        for i, lead in enumerate(findings[:20], 1):
   209|            factors = lead.get("factors", {})
   210|            grade = factors.get("crypto_weakness", {}).get("grade", "?")
   211|            lines.append(
   212|                f"  {i:>2}. {lead['domain']:<35} "
   213|                f"Score: {lead['pqc_urgency_score']:>5.1f}  "
   214|                f"Grade: {grade:<10} "
   215|                f"[{lead.get('urgency', '?')}]"
   216|            )
   217|            lines.append(
   218|                f"      {lead.get('key_algorithm_display', '?')} {lead.get('key_size', '?')}-bit  |  "
   219|                f"Expires: {lead.get('cert_expiry_date', 'N/A')[:20]}  |  "
   220|                f"{lead.get('recommended_service', '')}"
   221|            )
   222|        lines.append("")
   223|
   224|    recs = report.get("recommendations", [])
   225|    if recs:
   226|        lines.append("RECOMMENDATIONS")
   227|        lines.append("-" * 72)
   228|        for rec in recs:
   229|            lines.append(f"  [{rec['priority']}] {rec['category']}")
   230|            lines.append(f"    {rec['recommendation']}")
   231|            lines.append(f"    Standard: {rec.get('standard', 'N/A')}  |  Timeline: {rec.get('timeline', 'N/A')}")
   232|            lines.append("")
   233|
   234|    lines.append("=" * 72)
   235|    lines.append("  Report generated by gridera-scan | TAURUS AI Corp")
   236|    lines.append("  https://github.com/Taurus-Ai-Corp/gridera-scan-cli")
   237|    lines.append("=" * 72)
   238|
   239|    return "\n".join(lines)
   240|