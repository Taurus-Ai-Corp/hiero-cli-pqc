"""Tests for scanner.parse_cert() — certificate text parsing with synthetic OpenSSL output.

No network or OpenSSL binary required.
"""

import unittest
from datetime import datetime, timedelta

from cli_anything.hiero_pqc.core.scanner import parse_cert


# --- Synthetic certificate text fixtures ---

RSA_2048_CERT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:00:00:00:00:01:15:4b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = BE, O = GlobalSign nv-sa, CN = GlobalSign RSA OV SSL CA 2018
        Validity
            Not Before: Jan 15 09:30:00 2024 GMT
            Not After : Jul 15 09:30:00 2025 GMT
        Subject: C = US, ST = California, O = Example Inc, CN = example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:ab:cd:ef...
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:example.com, DNS:www.example.com, DNS:api.example.com
"""

ECDSA_256_CERT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Mar 01 00:00:00 2024 GMT
            Not After : May 30 00:00:00 2024 GMT
        Subject: CN = ec-test.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:ec-test.example.com
"""

ECDSA_384_CERT = """\
Certificate:
    Data:
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = US, O = DigiCert Inc, CN = DigiCert ECC CA
        Validity
            Not Before: Feb 01 00:00:00 2024 GMT
            Not After : Feb 01 00:00:00 2026 GMT
        Subject: CN = ec384.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                ASN1 OID: secp384r1
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:ec384.example.com, DNS:www.ec384.example.com
"""

ED25519_CERT = """\
Certificate:
    Data:
        Signature Algorithm: ED25519
        Issuer: CN = Test CA
        Validity
            Not Before: Jan 01 00:00:00 2024 GMT
            Not After : Jan 01 00:00:00 2030 GMT
        Subject: CN = ed25519.example.com
        Subject Public Key Info:
            Public Key Algorithm: ED25519
"""

RSA_4096_CERT = """\
Certificate:
    Data:
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = US, O = DigiCert Inc, CN = DigiCert SHA2 Extended Validation Server CA
        Validity
            Not Before: Jun 01 12:00:00 2024 GMT
            Not After : Jun 01 12:00:00 2026 GMT
        Subject: C = US, O = Big Corp, CN = secure.bigcorp.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:secure.bigcorp.com, DNS:*.bigcorp.com
"""

PRIME256V1_CERT_NO_BIT = """\
Certificate:
    Data:
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Fallback CA
        Validity
            Not Before: Jan 01 00:00:00 2024 GMT
            Not After : Jan 01 00:00:00 2025 GMT
        Subject: CN = fallback.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                ASN1 OID: prime256v1
"""

SECP384R1_CERT_NO_BIT = """\
Certificate:
    Data:
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: CN = Fallback CA
        Validity
            Not Before: Jan 01 00:00:00 2024 GMT
            Not After : Jan 01 00:00:00 2025 GMT
        Subject: CN = fallback384.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                ASN1 OID: secp384r1
"""

MIXED_SAN_CERT = """\
Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = Test CA
        Validity
            Not Before: Jan 01 00:00:00 2024 GMT
            Not After : Jan 01 00:00:00 2025 GMT
        Subject: CN = mixed-san.example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:mixed-san.example.com, IP Address:192.168.1.1, email:admin@example.com, DNS:www.mixed-san.example.com
"""


class TestParseCertRSA(unittest.TestCase):
    """Test parse_cert with RSA certificates."""

    def test_parses_rsa_2048_key_size(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(result["key_size"], 2048)

    def test_parses_rsa_algorithm(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(result["key_algorithm"], "rsaEncryption")
        self.assertEqual(result["key_algorithm_display"], "RSA")

    def test_parses_rsa_4096_key_size(self):
        result = parse_cert(RSA_4096_CERT)
        self.assertEqual(result["key_size"], 4096)

    def test_parses_signature_algorithm(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(result["signature_algorithm"], "sha256WithRSAEncryption")

    def test_parses_rsa_4096_signature_algorithm(self):
        result = parse_cert(RSA_4096_CERT)
        self.assertEqual(result["signature_algorithm"], "sha384WithRSAEncryption")


class TestParseCertECDSA(unittest.TestCase):
    """Test parse_cert with ECDSA certificates."""

    def test_parses_ecdsa_256_key_size(self):
        result = parse_cert(ECDSA_256_CERT)
        self.assertEqual(result["key_size"], 256)

    def test_parses_ecdsa_384_key_size(self):
        result = parse_cert(ECDSA_384_CERT)
        self.assertEqual(result["key_size"], 384)

    def test_ecdsa_algorithm_display(self):
        result = parse_cert(ECDSA_256_CERT)
        self.assertEqual(result["key_algorithm"], "id-ecPublicKey")
        self.assertEqual(result["key_algorithm_display"], "ECDSA")

    def test_prime256v1_fallback_detection(self):
        """Detects 256-bit key from prime256v1 OID when bit notation is absent."""
        result = parse_cert(PRIME256V1_CERT_NO_BIT)
        self.assertEqual(result["key_size"], 256)

    def test_secp384r1_fallback_detection(self):
        """Detects 384-bit key from secp384r1 OID when bit notation is absent."""
        result = parse_cert(SECP384R1_CERT_NO_BIT)
        self.assertEqual(result["key_size"], 384)


class TestParseCertEdDSA(unittest.TestCase):
    """Test parse_cert with EdDSA certificates."""

    def test_ed25519_algorithm_display(self):
        result = parse_cert(ED25519_CERT)
        self.assertEqual(result["key_algorithm_display"], "Ed25519")


class TestParseCertIssuerSubject(unittest.TestCase):
    """Test issuer and subject extraction."""

    def test_parses_issuer(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertIn("GlobalSign", result["issuer"])

    def test_parses_subject(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertIn("example.com", result["subject"])

    def test_parses_simple_issuer(self):
        result = parse_cert(ED25519_CERT)
        self.assertEqual(result["issuer"], "CN = Test CA")


class TestParseCertValidity(unittest.TestCase):
    """Test date parsing and expiry calculation."""

    def test_parses_not_before(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(result["not_before"], "Jan 15 09:30:00 2024 GMT")

    def test_parses_not_after(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(result["not_after"], "Jul 15 09:30:00 2025 GMT")

    def test_days_until_expiry_non_negative(self):
        """days_until_expiry is clamped to 0 minimum."""
        # ECDSA_256_CERT expires May 30 2024 — already expired
        result = parse_cert(ECDSA_256_CERT)
        self.assertGreaterEqual(result["days_until_expiry"], 0)

    def test_future_cert_has_positive_days(self):
        """A cert expiring far in the future has positive days_until_expiry."""
        result = parse_cert(ED25519_CERT)  # expires Jan 2030
        self.assertGreater(result["days_until_expiry"], 0)

    def test_malformed_date_graceful(self):
        """Malformed date doesn't crash — days_until_expiry stays -1."""
        cert_text = """\
Certificate:
    Validity
        Not After : THIS-IS-NOT-A-DATE
"""
        result = parse_cert(cert_text)
        self.assertEqual(result["days_until_expiry"], -1)
        self.assertEqual(result["not_after"], "THIS-IS-NOT-A-DATE")


class TestParseCertSAN(unittest.TestCase):
    """Test Subject Alternative Name extraction."""

    def test_parses_multiple_sans(self):
        result = parse_cert(RSA_2048_CERT)
        self.assertEqual(
            result["sans"],
            ["example.com", "www.example.com", "api.example.com"],
        )

    def test_single_san(self):
        result = parse_cert(ECDSA_256_CERT)
        self.assertEqual(result["sans"], ["ec-test.example.com"])

    def test_filters_non_dns_sans(self):
        """IP and email SAN entries are excluded; only DNS entries are kept."""
        result = parse_cert(MIXED_SAN_CERT)
        self.assertEqual(
            result["sans"],
            ["mixed-san.example.com", "www.mixed-san.example.com"],
        )

    def test_no_san_returns_empty_list(self):
        cert_text = """\
Certificate:
    Issuer: CN = No SAN CA
"""
        result = parse_cert(cert_text)
        self.assertEqual(result["sans"], [])


class TestParseCertDefaults(unittest.TestCase):
    """Test graceful defaults for missing or empty input."""

    def test_empty_string_returns_defaults(self):
        result = parse_cert("")
        self.assertEqual(result["key_algorithm"], "Unknown")
        self.assertEqual(result["key_algorithm_display"], "Unknown")
        self.assertEqual(result["key_size"], 0)
        self.assertEqual(result["issuer"], "Unknown")
        self.assertEqual(result["subject"], "Unknown")
        self.assertEqual(result["days_until_expiry"], -1)
        self.assertEqual(result["sans"], [])

    def test_garbage_input_returns_defaults(self):
        result = parse_cert("this is not a certificate at all")
        self.assertEqual(result["key_algorithm"], "Unknown")
        self.assertEqual(result["key_size"], 0)


if __name__ == "__main__":
    unittest.main()
