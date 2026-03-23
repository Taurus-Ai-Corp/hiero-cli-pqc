"""
hiero-cli-pqc — Post-Quantum Cryptography audit CLI for the Hiero/Hedera ecosystem.

Open-source tool for scanning SSL certificates, scoring quantum vulnerability,
generating compliance reports, and anchoring audit trails to Hedera HCS.

Part of the Hiero ecosystem: https://hiero.org
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import click

from cli_anything.hiero_pqc.core import __version__
from cli_anything.hiero_pqc.core.scanner import scan_domain, scan_domains, CRYPTO_GRADES
from cli_anything.hiero_pqc.core.scorer import score_lead, score_leads, SERVICE_TIERS
from cli_anything.hiero_pqc.core.auditor import hash_report, verify_hash_on_topic, generate_hcs_payload, get_topic_messages
from cli_anything.hiero_pqc.core.reporter import generate_report, to_csv, to_text


def _output(data, as_json=False):
    """Print output in JSON or human-readable format."""
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    click.echo(f"  {k}: {json.dumps(v, indent=4, default=str)}")
                else:
                    click.echo(f"  {k}: {v}")
        else:
            click.echo(str(data))


def _run_async(coro):
    """Run async coroutine in sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


@click.group(invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
@click.pass_context
def cli(ctx, as_json):
    """hiero-cli-pqc — Post-Quantum Cryptography audit tool for Hiero/Hedera.

    Scan SSL certificates, score quantum vulnerability, generate compliance
    reports, and anchor audit trails to Hedera Consensus Service.
    """
    ctx.ensure_object(dict)
    ctx.obj["json"] = as_json
    if ctx.invoked_subcommand is None:
        click.echo(f"hiero-cli-pqc v{__version__}")
        click.echo("Post-Quantum Cryptography audit tool for the Hiero ecosystem")
        click.echo("")
        click.echo("Commands:")
        click.echo("  scan       Scan SSL certificate(s) for quantum vulnerability")
        click.echo("  score      Score scan results for PQC migration urgency")
        click.echo("  report     Full pipeline: scan → score → report")
        click.echo("  audit      Hedera HCS audit trail operations")
        click.echo("  pipeline   Batch pipeline for multiple domains")
        click.echo("  info       Show tool information")
        click.echo("")
        click.echo("Run 'hiero-cli-pqc COMMAND --help' for details.")


@cli.command()
@click.argument("domain")
@click.option("--timeout", default=15, help="Connection timeout in seconds")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def scan(domain, timeout, as_json):
    """Scan a domain's SSL certificate for quantum vulnerability."""
    if not as_json:
        click.echo(f"Scanning {domain}...")

    result = _run_async(scan_domain(domain, timeout))

    if result.get("status") == "error":
        if as_json:
            _output({"success": False, **result}, as_json=True)
        else:
            click.echo(f"Error: {result.get('error', 'Unknown error')}", err=True)
        sys.exit(1)

    if as_json:
        _output({"success": True, **result}, as_json=True)
    else:
        grade = result.get("crypto_grade", "ERROR")
        grade_info = CRYPTO_GRADES.get(grade, {})
        click.echo(f"\n  Domain:     {result['domain']}")
        click.echo(f"  Algorithm:  {result.get('key_algorithm_display', '?')} ({result.get('key_size', '?')}-bit)")
        click.echo(f"  Signature:  {result.get('signature_algorithm', '?')}")
        click.echo(f"  Grade:      {grade} — {grade_info.get('label', '')}")
        click.echo(f"  Issuer:     {result.get('issuer', '?')}")
        click.echo(f"  Expires:    {result.get('not_after', '?')} ({result.get('days_until_expiry', '?')} days)")
        click.echo(f"  SANs:       {', '.join(result.get('sans', [])[:5])}")


@cli.command(name="scan-batch")
@click.argument("domains_file", type=click.Path(exists=True))
@click.option("--concurrency", default=10, help="Max concurrent scans")
@click.option("--timeout", default=15, help="Per-domain timeout in seconds")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def scan_batch(domains_file, concurrency, timeout, as_json):
    """Scan multiple domains from a file (one per line)."""
    domains = Path(domains_file).read_text().strip().splitlines()
    domains = [d.strip() for d in domains if d.strip() and not d.startswith("#")]

    if not domains:
        click.echo("No domains found in file.", err=True)
        sys.exit(1)

    if not as_json:
        click.echo(f"Scanning {len(domains)} domains (concurrency={concurrency})...")

    results = _run_async(scan_domains(domains, concurrency, timeout))
    successful = [r for r in results if r.get("status") == "scanned"]

    if as_json:
        _output({
            "success": True,
            "total": len(domains),
            "scanned": len(successful),
            "failed": len(domains) - len(successful),
            "results": results,
        }, as_json=True)
    else:
        click.echo(f"\nScanned {len(successful)}/{len(domains)} domains\n")
        for r in results:
            if r.get("status") == "scanned":
                grade = r.get("crypto_grade", "?")
                click.echo(
                    f"  {r['domain']:<40} "
                    f"{r.get('key_algorithm_display', '?'):<8} "
                    f"{r.get('key_size', '?'):>5}-bit  "
                    f"Grade: {grade}"
                )
            else:
                click.echo(f"  {r['domain']:<40} ERROR: {r.get('error', '?')}")


@cli.command()
@click.argument("scan_json", type=click.Path(exists=True))
@click.option("--industry", default="other", help="Default industry (finance, healthcare, government, tech, etc.)")
@click.option("--size", default="unknown", help="Default company size (enterprise, mid-market, smb, startup)")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def score(scan_json, industry, size, as_json):
    """Score scan results for PQC migration urgency.

    SCAN_JSON is a JSON file with scan results (output from 'scan-batch --json').
    """
    data = json.loads(Path(scan_json).read_text())

    # Handle both direct results list and wrapped format
    if isinstance(data, list):
        scan_results = data
    elif isinstance(data, dict):
        scan_results = data.get("results", [])
    else:
        click.echo("Invalid scan data format.", err=True)
        sys.exit(1)

    scored = score_leads(scan_results, default_industry=industry, default_size=size)

    if as_json:
        _output({
            "success": True,
            "total_scored": len(scored),
            "high_priority": len([s for s in scored if s["pqc_urgency_score"] >= 60]),
            "scored_leads": scored,
        }, as_json=True)
    else:
        click.echo(f"\nScored {len(scored)} domains\n")
        for i, lead in enumerate(scored, 1):
            click.echo(
                f"  {i:>2}. {lead['domain']:<35} "
                f"Score: {lead['pqc_urgency_score']:>5.1f}  "
                f"[{lead['urgency']}]  "
                f"{lead['recommended_service']}"
            )


@cli.command()
@click.argument("domain")
@click.option("--industry", default="other", help="Industry vertical")
@click.option("--size", default="unknown", help="Company size")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "text"]), default="text", help="Output format")
@click.option("--output", "output_file", type=click.Path(), help="Write report to file")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format (same as --format json)")
def report(domain, industry, size, fmt, output_file, as_json):
    """Full pipeline: scan a domain, score it, and generate a compliance report."""
    if as_json:
        fmt = "json"

    if fmt != "json":
        click.echo(f"Scanning {domain}...")

    # Step 1: Scan
    scan_result = _run_async(scan_domain(domain))
    if scan_result.get("status") != "scanned":
        if fmt == "json":
            _output({"success": False, "error": scan_result.get("error", "Scan failed")}, as_json=True)
        else:
            click.echo(f"Error: {scan_result.get('error', 'Scan failed')}", err=True)
        sys.exit(1)

    # Step 2: Score
    scored = score_lead(scan_result, industry, size)

    # Step 3: Generate report
    full_report = generate_report(
        [scored],
        [scan_result],
        metadata={"industry": industry, "company_size": size, "target": domain},
    )

    # Step 4: Output
    if fmt == "json":
        output_content = json.dumps(full_report, indent=2, default=str)
    elif fmt == "csv":
        output_content = to_csv([scored])
    else:
        output_content = to_text(full_report)

    if output_file:
        Path(output_file).write_text(output_content)
        if fmt != "json":
            click.echo(f"\nReport written to {output_file}")
    else:
        click.echo(output_content)


@cli.command()
@click.argument("domains_file", type=click.Path(exists=True))
@click.option("--industry", default="other", help="Default industry")
@click.option("--size", default="unknown", help="Default company size")
@click.option("--concurrency", default=10, help="Max concurrent scans")
@click.option("--output", "output_dir", type=click.Path(), default="./pqc-audit", help="Output directory")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def pipeline(domains_file, industry, size, concurrency, output_dir, as_json):
    """Full batch pipeline: scan multiple domains, score, report, and hash.

    DOMAINS_FILE is a text file with one domain per line.
    """
    domains = Path(domains_file).read_text().strip().splitlines()
    domains = [d.strip() for d in domains if d.strip() and not d.startswith("#")]

    if not domains:
        click.echo("No domains found in file.", err=True)
        sys.exit(1)

    if not as_json:
        click.echo(f"Pipeline: {len(domains)} domains | industry={industry} | size={size}")

    # Step 1: Scan all
    if not as_json:
        click.echo("  [1/4] Scanning certificates...")
    scan_results = _run_async(scan_domains(domains, concurrency))
    successful = [r for r in scan_results if r.get("status") == "scanned"]
    if not as_json:
        click.echo(f"         {len(successful)}/{len(domains)} scanned successfully")

    # Step 2: Score
    if not as_json:
        click.echo("  [2/4] Scoring quantum vulnerability...")
    scored = score_leads(scan_results, default_industry=industry, default_size=size)
    high_priority = len([s for s in scored if s["pqc_urgency_score"] >= 60])
    if not as_json:
        click.echo(f"         {high_priority} high-priority leads found")

    # Step 3: Generate report
    if not as_json:
        click.echo("  [3/4] Generating compliance report...")
    full_report = generate_report(
        scored, scan_results,
        metadata={"industry": industry, "company_size": size, "domains_file": domains_file},
    )

    # Step 4: Hash for audit trail
    if not as_json:
        click.echo("  [4/4] Generating audit hash...")
    report_hash = hash_report(full_report)

    # Write outputs
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    (out / "report.json").write_text(json.dumps(full_report, indent=2, default=str))
    (out / "leads.csv").write_text(to_csv(scored))
    (out / "report.txt").write_text(to_text(full_report))
    (out / "audit_hash.json").write_text(json.dumps(report_hash, indent=2))

    # Generate HCS payloads for top leads
    hcs_payloads = []
    for lead in scored[:10]:  # Top 10
        payload = generate_hcs_payload(
            report_hash["hash"],
            lead["domain"],
            lead["pqc_urgency_score"],
            lead.get("factors", {}).get("crypto_weakness", {}).get("grade", "?"),
            lead["recommended_service"],
        )
        hcs_payloads.append(payload)
    (out / "hcs_payloads.json").write_text(json.dumps(hcs_payloads, indent=2, default=str))

    if as_json:
        _output({
            "success": True,
            "output_dir": str(out),
            "domains_scanned": len(successful),
            "domains_failed": len(domains) - len(successful),
            "leads_scored": len(scored),
            "high_priority": high_priority,
            "report_hash": report_hash["hash"],
            "files": {
                "report": str(out / "report.json"),
                "csv": str(out / "leads.csv"),
                "text": str(out / "report.txt"),
                "audit_hash": str(out / "audit_hash.json"),
                "hcs_payloads": str(out / "hcs_payloads.json"),
            },
        }, as_json=True)
    else:
        click.echo(f"\n  Pipeline complete!")
        click.echo(f"  Output:       {out}/")
        click.echo(f"  Scanned:      {len(successful)}/{len(domains)}")
        click.echo(f"  High-priority: {high_priority}")
        click.echo(f"  Report hash:  {report_hash['hash'][:16]}...")
        click.echo(f"\n  Files:")
        click.echo(f"    report.json      — Full compliance report")
        click.echo(f"    leads.csv        — CRM-importable leads")
        click.echo(f"    report.txt       — Human-readable report")
        click.echo(f"    audit_hash.json  — SHA-256 for Hedera anchoring")
        click.echo(f"    hcs_payloads.json — Ready-to-submit HCS messages")


@cli.group()
def audit():
    """Hedera HCS audit trail operations."""
    pass


@audit.command(name="hash")
@click.argument("report_file", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def audit_hash(report_file, as_json):
    """Generate SHA-256 hash of a report for Hedera anchoring."""
    data = json.loads(Path(report_file).read_text())
    result = hash_report(data)

    if as_json:
        _output({"success": True, **result}, as_json=True)
    else:
        click.echo(f"\n  Hash:      {result['hash']}")
        click.echo(f"  Algorithm: {result['algorithm']}")
        click.echo(f"  Timestamp: {result['timestamp']}")
        click.echo(f"  Size:      {result['canonical_bytes']} bytes")


@audit.command(name="verify")
@click.argument("topic_id")
@click.argument("expected_hash")
@click.option("--network", default="testnet", help="Hedera network (testnet, mainnet)")
@click.option("--limit", default=100, help="Max messages to search")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def audit_verify(topic_id, expected_hash, network, limit, as_json):
    """Verify a report hash exists on a Hedera HCS topic."""
    result = verify_hash_on_topic(topic_id, expected_hash, network, limit)

    if as_json:
        _output(result, as_json=True)
    else:
        if result.get("verified"):
            click.echo(f"\n  VERIFIED on Hedera {network}")
            click.echo(f"  Topic:      {topic_id}")
            click.echo(f"  Sequence:   {result.get('sequence_number', '?')}")
            click.echo(f"  Timestamp:  {result.get('consensus_timestamp', '?')}")
        else:
            click.echo(f"\n  NOT FOUND on Hedera {network}")
            click.echo(f"  Topic:      {topic_id}")
            click.echo(f"  Searched:   {result.get('messages_searched', '?')} messages")


@audit.command(name="messages")
@click.argument("topic_id")
@click.option("--network", default="testnet", help="Hedera network")
@click.option("--limit", default=10, help="Max messages")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def audit_messages(topic_id, network, limit, as_json):
    """Get recent messages from a Hedera HCS topic."""
    result = get_topic_messages(topic_id, network, limit)

    if as_json:
        _output(result, as_json=True)
    else:
        if not result.get("success"):
            click.echo(f"Error: {result.get('error', '?')}", err=True)
            sys.exit(1)
        click.echo(f"\n  Topic: {topic_id} ({network})")
        for msg in result.get("messages", []):
            click.echo(f"\n  #{msg.get('sequence_number', '?')} @ {msg.get('consensus_timestamp', '?')}")
            content = msg.get("message", "")
            if isinstance(content, dict):
                click.echo(f"    {json.dumps(content, indent=4)}")
            else:
                click.echo(f"    {content[:200]}")


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format")
def info(as_json):
    """Show tool information and capabilities."""
    data = {
        "name": "hiero-cli-pqc",
        "version": __version__,
        "description": "Post-Quantum Cryptography audit tool for the Hiero/Hedera ecosystem",
        "author": "TAURUS AI Corp",
        "license": "MIT",
        "repository": "https://github.com/Taurus-Ai-Corp/hiero-cli-pqc",
        "capabilities": [
            "SSL/TLS certificate scanning via OpenSSL",
            "Quantum vulnerability classification (NIST FIPS 203/204)",
            "Multi-factor PQC migration urgency scoring",
            "Compliance report generation (JSON, CSV, text)",
            "Hedera HCS audit trail anchoring",
            "Batch domain scanning with concurrency control",
        ],
        "crypto_grades": list(CRYPTO_GRADES.keys()),
        "service_tiers": [t["service"] for t in SERVICE_TIERS],
        "dependencies": ["click>=8.0", "openssl (system)"],
    }

    if as_json:
        _output(data, as_json=True)
    else:
        click.echo(f"\n  {data['name']} v{data['version']}")
        click.echo(f"  {data['description']}")
        click.echo(f"  Author:  {data['author']}")
        click.echo(f"  License: {data['license']}")
        click.echo(f"\n  Capabilities:")
        for cap in data["capabilities"]:
            click.echo(f"    - {cap}")


if __name__ == "__main__":
    cli()
