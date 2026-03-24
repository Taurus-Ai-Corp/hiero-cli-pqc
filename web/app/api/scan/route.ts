import { NextRequest, NextResponse } from "next/server";
import * as tls from "tls";
import * as crypto from "crypto";

const CRYPTO_GRADES: Record<string, { score: number; label: string }> = {
  CRITICAL: { score: 100, label: "Critical — Quantum-vulnerable, immediate action needed" },
  WEAK: { score: 80, label: "Weak — Quantum-vulnerable, migration recommended" },
  MODERATE: { score: 40, label: "Moderate — Acceptable short-term, plan migration" },
  STRONG: { score: 10, label: "Strong — Classical security adequate" },
  PQC_READY: { score: 0, label: "PQC-Ready — Post-quantum algorithms detected" },
};

function classifyCrypto(algorithm: string, keySize: number): string {
  const algo = algorithm.toUpperCase();
  if (["DILITHIUM", "KYBER", "ML-KEM", "ML-DSA", "SLH-DSA"].some((p) => algo.includes(p))) return "PQC_READY";
  if (algo.includes("RSA")) {
    if (keySize <= 1024) return "CRITICAL";
    if (keySize <= 2048) return "WEAK";
    if (keySize <= 3072) return "MODERATE";
    return "STRONG";
  }
  if (algo.includes("EC") || algo.includes("ECDSA")) {
    if (keySize <= 256) return "WEAK";
    if (keySize <= 384) return "MODERATE";
    return "STRONG";
  }
  if (algo.includes("ED25519") || algo.includes("ED448")) return "MODERATE";
  return "WEAK";
}

function scoreLead(grade: string, daysLeft: number): {
  score: number;
  urgency: string;
  service: string;
  priceRange: string;
} {
  const cryptoScores: Record<string, number> = { CRITICAL: 100, WEAK: 80, MODERATE: 40, STRONG: 10, PQC_READY: 0 };
  const cs = cryptoScores[grade] ?? 50;
  let es = 10;
  if (daysLeft < 0) es = 100;
  else if (daysLeft <= 180) es = 100;
  else if (daysLeft <= 365) es = 70;
  else if (daysLeft <= 730) es = 40;

  const total = Math.round((cs * 0.35 + es * 0.25 + 100 * 0.20 + 100 * 0.20) * 10) / 10;

  if (total >= 80) return { score: total, urgency: "IMMEDIATE", service: "PQC Key Migration", priceRange: "$250K–$1M+" };
  if (total >= 60) return { score: total, urgency: "HIGH", service: "Hybrid Signature Implementation", priceRange: "$75K–$150K" };
  if (total >= 40) return { score: total, urgency: "MEDIUM", service: "PQC Readiness Assessment", priceRange: "$25K–$50K" };
  return { score: total, urgency: "LOW", service: "PKI Modernization", priceRange: "$10K–$50K/mo" };
}

async function scanDomain(domain: string): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve({ domain, status: "error", error: "Connection timeout (10s)" });
    }, 10000);

    try {
      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        try {
          const cert = socket.getPeerX509Certificate?.();
          if (!cert) {
            socket.end();
            resolve({ domain, status: "error", error: "No certificate returned" });
            return;
          }

          const pubKey = cert.publicKey;
          const keyType = pubKey.asymmetricKeyType ?? "unknown";
          let keySize = 0;
          // asymmetricKeySize not in all TS type defs — use detail export
          const keyDetail = (pubKey as crypto.KeyObject).export({ type: "spki", format: "der" });
          if (keyType === "rsa") {
            // RSA key size from DER: rough heuristic from buffer length
            const derLen = keyDetail.length;
            if (derLen > 550) keySize = 4096;
            else if (derLen > 390) keySize = 3072;
            else if (derLen > 280) keySize = 2048;
            else keySize = 1024;
          } else if (keyType === "ec") {
            const derLen = keyDetail.length;
            keySize = derLen > 120 ? 384 : 256;
          } else if (keyType === "ed25519") {
            keySize = 256;
          }

          let algoDisplay = keyType.toUpperCase();
          if (keyType === "rsa") algoDisplay = "RSA";
          else if (keyType === "ec") algoDisplay = "ECDSA";
          else if (keyType === "ed25519") algoDisplay = "Ed25519";

          const notAfter = new Date(cert.validTo);
          const daysLeft = Math.max(0, Math.floor((notAfter.getTime() - Date.now()) / 86400000));
          const grade = classifyCrypto(algoDisplay, keySize);
          const gradeInfo = CRYPTO_GRADES[grade];
          const scoring = scoreLead(grade, daysLeft);

          socket.end();
          resolve({
            domain,
            status: "scanned",
            keyAlgorithm: algoDisplay,
            keySize,
            cryptoGrade: grade,
            gradeLabel: gradeInfo?.label ?? "",
            gradeScore: gradeInfo?.score ?? 50,
            issuer: cert.issuer ?? "Unknown",
            subject: cert.subject ?? "Unknown",
            validFrom: cert.validFrom,
            validTo: cert.validTo,
            daysUntilExpiry: daysLeft,
            serialNumber: cert.serialNumber,
            pqcScore: scoring.score,
            urgency: scoring.urgency,
            recommendedService: scoring.service,
            priceRange: scoring.priceRange,
            scanTimestamp: new Date().toISOString(),
          });
        } catch (e) {
          socket.end();
          resolve({ domain, status: "error", error: `Parse error: ${e}` });
        }
      });

      socket.on("error", (err) => {
        clearTimeout(timeout);
        resolve({ domain, status: "error", error: err.message });
      });
    } catch (e) {
      clearTimeout(timeout);
      resolve({ domain, status: "error", error: `${e}` });
    }
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const domain = (body.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");

    if (!domain || domain.length < 3 || !domain.includes(".")) {
      return NextResponse.json({ success: false, error: "Invalid domain" }, { status: 400 });
    }

    const result = await scanDomain(domain);
    return NextResponse.json({ success: result.status === "scanned", ...result });
  } catch {
    return NextResponse.json({ success: false, error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    service: "hiero-cli-pqc",
    version: "0.1.0",
    description: "Post-Quantum Cryptography vulnerability scanner",
    usage: "POST /api/scan with { domain: 'example.com' }",
  });
}
