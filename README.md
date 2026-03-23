# hiero-cli-pqc

Post-Quantum Cryptography audit CLI for the [Hiero](https://hiero.org) / [Hedera](https://hedera.com) ecosystem.

Scan SSL certificates, score quantum vulnerability, generate compliance reports, and anchor audit trails to Hedera Consensus Service (HCS).

## Why This Matters

**NIST has finalized post-quantum cryptography standards** (FIPS 203/204/205). Organizations using RSA-2048, ECDSA P-256, and other classical algorithms are vulnerable to "harvest now, decrypt later" quantum attacks. This tool identifies which domains need migration and how urgently.

## Quick Start

```bash
pip install cli-anything-hiero-pqc

# Scan a single domain
hiero-pqc scan rbc.com

# Full compliance report
hiero-pqc report rbc.com --industry finance --size enterprise

# Batch pipeline (scan → score → report → audit hash)
hiero-pqc pipeline targets.txt --industry finance --output ./results
```

## Features

- **SSL/TLS Certificate Scanning** — Uses OpenSSL to analyze certificate crypto strength
- **Quantum Vulnerability Classification** — Grades algorithms against NIST PQC standards
- **Multi-Factor Urgency Scoring** — 4-factor weighted score (crypto weakness, cert expiry, industry, company size)
- **Compliance Reports** — JSON, CSV (CRM-importable), and human-readable text
- **Hedera HCS Audit Trail** — SHA-256 hashing + verification against Hedera Consensus Service
- **Batch Processing** — Concurrent scanning with configurable parallelism

## Crypto Grading

| Grade | Score | Algorithms | Action |
|-------|-------|-----------|--------|
| CRITICAL | 100 | RSA-1024 | Immediate migration |
| WEAK | 80 | RSA-2048, ECDSA P-256 | Migration recommended |
| MODERATE | 40 | RSA-3072, ECDSA P-384, Ed25519 | Plan migration |
| STRONG | 10 | RSA-4096+ | Future-proofing |
| PQC_READY | 0 | ML-KEM, ML-DSA, SLH-DSA | Compliant |

## Service Tiers

| Score | Service | Price Range |
|-------|---------|-------------|
| 80+ | PQC Key Migration | $250K–$1M+ |
| 60+ | Hybrid Signature Implementation | $75K–$150K |
| 40+ | PQC Readiness Assessment | $25K–$50K |
| 20+ | Compliance Mapping | $50K–$100K |
| <20 | PKI Modernization Consulting | $10K–$50K/mo |

## Commands

```
hiero-pqc scan <domain>           # Scan single domain
hiero-pqc scan-batch <file>       # Scan multiple domains
hiero-pqc score <scan.json>       # Score scan results
hiero-pqc report <domain>         # Full pipeline for one domain
hiero-pqc pipeline <file>         # Batch: scan → score → report → hash
hiero-pqc audit hash <file>       # Generate SHA-256 for Hedera anchoring
hiero-pqc audit verify <topic> <hash>  # Verify hash on Hedera HCS
hiero-pqc audit messages <topic>  # View HCS topic messages
hiero-pqc info                    # Tool capabilities
```

All commands support `--json` for machine-readable output.

## Output Files (Pipeline)

| File | Format | Purpose |
|------|--------|---------|
| `report.json` | JSON | Full compliance report |
| `leads.csv` | CSV | CRM-importable (HubSpot, Salesforce) |
| `report.txt` | Text | Human-readable executive summary |
| `audit_hash.json` | JSON | SHA-256 hash for Hedera anchoring |
| `hcs_payloads.json` | JSON | Ready-to-submit HCS messages |

## Architecture

```
Domain URL → OpenSSL s_client → Certificate Parser → Crypto Classifier
                                                           ↓
                                                    4-Factor Scorer
                                                     (crypto × expiry × industry × size)
                                                           ↓
                                              Report Generator → SHA-256 Hash
                                                                      ↓
                                                              Hedera HCS Anchor
```

## Standards Referenced

- **NIST FIPS 203** — ML-KEM (Kyber) Key Encapsulation
- **NIST FIPS 204** — ML-DSA (Dilithium) Digital Signatures
- **NIST FIPS 205** — SLH-DSA (SPHINCS+) Stateless Hash Signatures
- **NIST SP 800-131A Rev 2** — Transitioning Cryptographic Algorithms
- **CNSA 2.0** — NSA Commercial National Security Algorithm Suite

## Requirements

- Python 3.9+
- OpenSSL (system binary)
- `click>=8.0`

## License

MIT — TAURUS AI Corp

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Built for the [Hiero](https://hiero.org) open-source ecosystem.
