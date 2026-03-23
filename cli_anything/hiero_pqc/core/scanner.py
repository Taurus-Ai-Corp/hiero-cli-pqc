"""
SSL/TLS Certificate Scanner for PQC vulnerability assessment.

Standalone module — no external dependencies beyond Python stdlib.
Uses OpenSSL CLI (must be installed) to analyze certificate crypto strength.
"""

import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


# Crypto strength classification for quantum readiness
CRYPTO_GRADES = {
    "CRITICAL": {"score": 100, "label": "Critical — Quantum-vulnerable, immediate action needed"},
    "WEAK": {"score": 80, "label": "Weak — Quantum-vulnerable, migration recommended"},
    "MODERATE": {"score": 40, "label": "Moderate — Acceptable short-term, plan migration"},
    "STRONG": {"score": 10, "label": "Strong — Classical security adequate, PQC future-proofing"},
    "PQC_READY": {"score": 0, "label": "PQC-Ready — Post-quantum algorithms detected"},
    "ERROR": {"score": 50, "label": "Error — Could not determine, manual review needed"},
}


def classify_crypto(algorithm: str, key_size: int) -> str:
    """Classify cryptographic algorithm strength against quantum threats.

    Returns one of: CRITICAL, WEAK, MODERATE, STRONG, PQC_READY, ERROR.
    """
    algo = algorithm.upper()

    # Post-quantum algorithms
    if any(pqc in algo for pqc in ("DILITHIUM", "KYBER", "ML-KEM", "ML-DSA", "SLH-DSA", "SPHINCS")):
        return "PQC_READY"

    # RSA — key size determines quantum vulnerability
    if "RSA" in algo:
        if key_size <= 1024:
            return "CRITICAL"
        if key_size <= 2048:
            return "WEAK"
        if key_size <= 3072:
            return "MODERATE"
        return "STRONG"

    # Elliptic curve — all current curves are quantum-vulnerable
    if "ECDSA" in algo or "EC" in algo:
        if key_size <= 256:
            return "WEAK"
        if key_size <= 384:
            return "MODERATE"
        return "STRONG"

    # EdDSA
    if "ED25519" in algo or "ED448" in algo:
        return "MODERATE"

    return "WEAK"


def parse_cert(cert_text: str) -> Dict[str, Any]:
    """Parse OpenSSL x509 -text output into structured data."""
    result: Dict[str, Any] = {
        "key_algorithm": "Unknown",
        "key_algorithm_display": "Unknown",
        "key_size": 0,
        "signature_algorithm": "Unknown",
        "issuer": "Unknown",
        "subject": "Unknown",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": -1,
        "sans": [],
    }

    # Key algorithm + size
    pk_match = re.search(r"Public Key Algorithm:\s*(.+)", cert_text)
    if pk_match:
        raw_algo = pk_match.group(1).strip()
        result["key_algorithm"] = raw_algo
        ra = raw_algo.lower()
        if "rsa" in ra:
            result["key_algorithm_display"] = "RSA"
        elif "ec" in ra:
            result["key_algorithm_display"] = "ECDSA"
        elif "ed25519" in ra:
            result["key_algorithm_display"] = "Ed25519"
        elif "ed448" in ra:
            result["key_algorithm_display"] = "Ed448"
        else:
            result["key_algorithm_display"] = raw_algo

    size_match = re.search(r"(?:RSA\s+)?Public[- ]Key:\s*\((\d+)\s*bit\)", cert_text)
    if size_match:
        result["key_size"] = int(size_match.group(1))
    elif "256 bit" in cert_text or "prime256v1" in cert_text:
        result["key_size"] = 256
    elif "384 bit" in cert_text or "secp384r1" in cert_text:
        result["key_size"] = 384

    # Signature algorithm
    sig_match = re.search(r"Signature Algorithm:\s*(.+)", cert_text)
    if sig_match:
        result["signature_algorithm"] = sig_match.group(1).strip()

    # Issuer / Subject
    issuer_match = re.search(r"Issuer:\s*(.+)", cert_text)
    if issuer_match:
        result["issuer"] = issuer_match.group(1).strip()
    subj_match = re.search(r"Subject:\s*(.+)", cert_text)
    if subj_match:
        result["subject"] = subj_match.group(1).strip()

    # Validity dates
    nb_match = re.search(r"Not Before:\s*(.+)", cert_text)
    na_match = re.search(r"Not After\s*:\s*(.+)", cert_text)
    if nb_match:
        result["not_before"] = nb_match.group(1).strip()
    if na_match:
        raw_date = na_match.group(1).strip()
        result["not_after"] = raw_date
        try:
            expiry = datetime.strptime(raw_date, "%b %d %H:%M:%S %Y %Z")
            delta = expiry - datetime.now()
            result["days_until_expiry"] = max(delta.days, 0)
        except ValueError:
            pass

    # Subject Alternative Names
    san_match = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.+)", cert_text)
    if san_match:
        sans_raw = san_match.group(1)
        result["sans"] = [
            s.strip().replace("DNS:", "")
            for s in sans_raw.split(",")
            if "DNS:" in s
        ]

    return result


async def scan_domain(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """Scan a single domain's SSL certificate and classify crypto strength.

    Returns dict with domain, status, crypto_grade, and parsed certificate data.
    """
    try:
        # Get full certificate text
        cmd = (
            f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null"
            f" | openssl x509 -text -noout 2>/dev/null"
        )
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        cert_text = stdout.decode(errors="replace")

        if "Certificate:" not in cert_text and "Issuer:" not in cert_text:
            return {"domain": domain, "status": "error", "error": "Could not retrieve certificate"}

        parsed = parse_cert(cert_text)
        parsed["domain"] = domain
        parsed["status"] = "scanned"
        parsed["crypto_grade"] = classify_crypto(
            parsed.get("key_algorithm", ""), parsed.get("key_size", 0)
        )
        parsed["grade_detail"] = CRYPTO_GRADES.get(parsed["crypto_grade"], {}).get("label", "")
        parsed["scan_timestamp"] = datetime.utcnow().isoformat() + "Z"
        return parsed

    except asyncio.TimeoutError:
        return {"domain": domain, "status": "error", "error": f"Connection timeout ({timeout}s)"}
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e)}


async def scan_domains(
    domains: List[str], concurrency: int = 10, timeout: int = 15
) -> List[Dict[str, Any]]:
    """Scan multiple domains concurrently.

    Args:
        domains: List of domain names to scan.
        concurrency: Max concurrent scans (default 10).
        timeout: Per-domain timeout in seconds (default 15).

    Returns:
        List of scan results, one per domain.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _limited(domain: str) -> Dict[str, Any]:
        async with sem:
            return await scan_domain(domain.strip(), timeout)

    tasks = [_limited(d) for d in domains if d.strip()]
    return await asyncio.gather(*tasks)
