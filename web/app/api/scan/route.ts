     1|import { NextRequest, NextResponse } from "next/server";
     2|import * as tls from "tls";
     3|import * as crypto from "crypto";
     4|
     5|const CRYPTO_GRADES: Record<string, { score: number; label: string }> = {
     6|  CRITICAL: { score: 100, label: "Critical — Quantum-vulnerable, immediate action needed" },
     7|  WEAK: { score: 80, label: "Weak — Quantum-vulnerable, migration recommended" },
     8|  MODERATE: { score: 40, label: "Moderate — Acceptable short-term, plan migration" },
     9|  STRONG: { score: 10, label: "Strong — Classical security adequate" },
    10|  PQC_READY: { score: 0, label: "PQC-Ready — Post-quantum algorithms detected" },
    11|};
    12|
    13|function classifyCrypto(algorithm: string, keySize: number): string {
    14|  const algo = algorithm.toUpperCase();
    15|  if (["DILITHIUM", "KYBER", "ML-KEM", "ML-DSA", "SLH-DSA"].some((p) => algo.includes(p))) return "PQC_READY";
    16|  if (algo.includes("RSA")) {
    17|    if (keySize <= 1024) return "CRITICAL";
    18|    if (keySize <= 2048) return "WEAK";
    19|    if (keySize <= 3072) return "MODERATE";
    20|    return "STRONG";
    21|  }
    22|  if (algo.includes("EC") || algo.includes("ECDSA")) {
    23|    if (keySize <= 256) return "WEAK";
    24|    if (keySize <= 384) return "MODERATE";
    25|    return "STRONG";
    26|  }
    27|  if (algo.includes("ED25519") || algo.includes("ED448")) return "MODERATE";
    28|  return "WEAK";
    29|}
    30|
    31|function scoreLead(grade: string, daysLeft: number): {
    32|  score: number;
    33|  urgency: string;
    34|  service: string;
    35|  priceRange: string;
    36|} {
    37|  const cryptoScores: Record<string, number> = { CRITICAL: 100, WEAK: 80, MODERATE: 40, STRONG: 10, PQC_READY: 0 };
    38|  const cs = cryptoScores[grade] ?? 50;
    39|  let es = 10;
    40|  if (daysLeft < 0) es = 100;
    41|  else if (daysLeft <= 180) es = 100;
    42|  else if (daysLeft <= 365) es = 70;
    43|  else if (daysLeft <= 730) es = 40;
    44|
    45|  const total = Math.round((cs * 0.35 + es * 0.25 + 100 * 0.20 + 100 * 0.20) * 10) / 10;
    46|
    47|  if (total >= 80) return { score: total, urgency: "IMMEDIATE", service: "PQC Key Migration", priceRange: "$250K–$1M+" };
    48|  if (total >= 60) return { score: total, urgency: "HIGH", service: "Hybrid Signature Implementation", priceRange: "$75K–$150K" };
    49|  if (total >= 40) return { score: total, urgency: "MEDIUM", service: "PQC Readiness Assessment", priceRange: "$25K–$50K" };
    50|  return { score: total, urgency: "LOW", service: "PKI Modernization", priceRange: "$10K–$50K/mo" };
    51|}
    52|
    53|async function scanDomain(domain: string): Promise<Record<string, unknown>> {
    54|  return new Promise((resolve) => {
    55|    const timeout = setTimeout(() => {
    56|      resolve({ domain, status: "error", error: "Connection timeout (10s)" });
    57|    }, 10000);
    58|
    59|    try {
    60|      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
    61|        clearTimeout(timeout);
    62|        try {
    63|          const cert = socket.getPeerX509Certificate?.();
    64|          if (!cert) {
    65|            socket.end();
    66|            resolve({ domain, status: "error", error: "No certificate returned" });
    67|            return;
    68|          }
    69|
    70|          const pubKey = cert.publicKey;
    71|          const keyType = pubKey.asymmetricKeyType ?? "unknown";
    72|          let keySize = 0;
    73|          // asymmetricKeySize not in all TS type defs — use detail export
    74|          const keyDetail = (pubKey as crypto.KeyObject).export({ type: "spki", format: "der" });
    75|          if (keyType === "rsa") {
    76|            // RSA key size from DER: rough heuristic from buffer length
    77|            const derLen = keyDetail.length;
    78|            if (derLen > 550) keySize = 4096;
    79|            else if (derLen > 390) keySize = 3072;
    80|            else if (derLen > 280) keySize = 2048;
    81|            else keySize = 1024;
    82|          } else if (keyType === "ec") {
    83|            const derLen = keyDetail.length;
    84|            keySize = derLen > 120 ? 384 : 256;
    85|          } else if (keyType === "ed25519") {
    86|            keySize = 256;
    87|          }
    88|
    89|          let algoDisplay = keyType.toUpperCase();
    90|          if (keyType === "rsa") algoDisplay = "RSA";
    91|          else if (keyType === "ec") algoDisplay = "ECDSA";
    92|          else if (keyType === "ed25519") algoDisplay = "Ed25519";
    93|
    94|          const notAfter = new Date(cert.validTo);
    95|          const daysLeft = Math.max(0, Math.floor((notAfter.getTime() - Date.now()) / 86400000));
    96|          const grade = classifyCrypto(algoDisplay, keySize);
    97|          const gradeInfo = CRYPTO_GRADES[grade];
    98|          const scoring = scoreLead(grade, daysLeft);
    99|
   100|          socket.end();
   101|          resolve({
   102|            domain,
   103|            status: "scanned",
   104|            keyAlgorithm: algoDisplay,
   105|            keySize,
   106|            cryptoGrade: grade,
   107|            gradeLabel: gradeInfo?.label ?? "",
   108|            gradeScore: gradeInfo?.score ?? 50,
   109|            issuer: cert.issuer ?? "Unknown",
   110|            subject: cert.subject ?? "Unknown",
   111|            validFrom: cert.validFrom,
   112|            validTo: cert.validTo,
   113|            daysUntilExpiry: daysLeft,
   114|            serialNumber: cert.serialNumber,
   115|            pqcScore: scoring.score,
   116|            urgency: scoring.urgency,
   117|            recommendedService: scoring.service,
   118|            priceRange: scoring.priceRange,
   119|            scanTimestamp: new Date().toISOString(),
   120|          });
   121|        } catch (e) {
   122|          socket.end();
   123|          resolve({ domain, status: "error", error: `Parse error: ${e}` });
   124|        }
   125|      });
   126|
   127|      socket.on("error", (err) => {
   128|        clearTimeout(timeout);
   129|        resolve({ domain, status: "error", error: err.message });
   130|      });
   131|    } catch (e) {
   132|      clearTimeout(timeout);
   133|      resolve({ domain, status: "error", error: `${e}` });
   134|    }
   135|  });
   136|}
   137|
   138|export async function POST(request: NextRequest) {
   139|  try {
   140|    const body = await request.json();
   141|    const domain = (body.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
   142|
   143|    if (!domain || domain.length < 3 || !domain.includes(".")) {
   144|      return NextResponse.json({ success: false, error: "Invalid domain" }, { status: 400 });
   145|    }
   146|
   147|    const result = await scanDomain(domain);
   148|    return NextResponse.json({ success: result.status === "scanned", ...result });
   149|  } catch {
   150|    return NextResponse.json({ success: false, error: "Internal server error" }, { status: 500 });
   151|  }
   152|}
   153|
   154|export async function GET() {
   155|  return NextResponse.json({
   156|    service: "gridera-scan",
   157|    version: "0.1.0",
   158|    description: "Post-Quantum Cryptography vulnerability scanner",
   159|    usage: "POST /api/scan with { domain: 'example.com' }",
   160|  });
   161|}
   162|