"use client";

import { useState } from "react";

type ScanResult = {
  success: boolean;
  domain?: string;
  keyAlgorithm?: string;
  keySize?: number;
  cryptoGrade?: string;
  gradeLabel?: string;
  daysUntilExpiry?: number;
  issuer?: string;
  validTo?: string;
  pqcScore?: number;
  urgency?: string;
  recommendedService?: string;
  priceRange?: string;
  error?: string;
};

const GRADE_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-950 border-red-800",
  WEAK: "text-orange-400 bg-orange-950 border-orange-800",
  MODERATE: "text-yellow-400 bg-yellow-950 border-yellow-800",
  STRONG: "text-green-400 bg-green-950 border-green-800",
  PQC_READY: "text-emerald-400 bg-emerald-950 border-emerald-800",
};

const URGENCY_COLORS: Record<string, string> = {
  IMMEDIATE: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-zinc-400",
};

export default function Home() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim() }),
      });
      const data = await res.json();
      setResult(data);
    } catch {
      setResult({ success: false, error: "Network error. Please try again." });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col font-[family-name:var(--font-geist-sans)]">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-emerald-500 rounded-full" />
            <span className="font-[family-name:var(--font-geist-mono)] text-sm text-zinc-400">hiero-cli-pqc</span>
          </div>
          <a
            href="https://github.com/Taurus-Ai-Corp/hiero-cli-pqc"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            GitHub
          </a>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-16">
        <div className="max-w-2xl w-full text-center space-y-6">
          <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
            Is Your Organization
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-400 to-red-500">
              Quantum-Safe?
            </span>
          </h1>
          <p className="text-zinc-400 text-lg max-w-xl mx-auto">
            Free instant scan. Enter any domain to check if its SSL certificate
            is ready for the post-quantum era.
          </p>

          {/* Scan Form */}
          <form onSubmit={handleScan} className="flex gap-3 max-w-lg mx-auto mt-8">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="rbc.com"
              className="flex-1 px-4 py-3 bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 font-[family-name:var(--font-geist-mono)] text-sm"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !domain.trim()}
              className="px-6 py-3 bg-zinc-100 text-zinc-900 rounded-lg font-medium text-sm hover:bg-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
            >
              {loading ? "Scanning..." : "Scan Now"}
            </button>
          </form>

          {/* Results */}
          {result && (
            <div className="mt-10 text-left max-w-lg mx-auto">
              {result.success ? (
                <div className="space-y-4">
                  {/* Grade Badge */}
                  <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm font-medium ${GRADE_COLORS[result.cryptoGrade ?? "WEAK"]}`}>
                    {result.cryptoGrade}
                  </div>

                  {/* Score Card */}
                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-zinc-400 text-sm">PQC Urgency Score</span>
                      <span className="text-3xl font-bold font-[family-name:var(--font-geist-mono)]">
                        {result.pqcScore}<span className="text-zinc-600 text-lg">/100</span>
                      </span>
                    </div>

                    <div className="w-full bg-zinc-800 rounded-full h-2">
                      <div
                        className="h-2 rounded-full transition-all duration-500 bg-gradient-to-r from-orange-500 to-red-500"
                        style={{ width: `${result.pqcScore}%` }}
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4 pt-2">
                      <div>
                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Algorithm</div>
                        <div className="font-[family-name:var(--font-geist-mono)] text-sm mt-1">
                          {result.keyAlgorithm} {result.keySize}-bit
                        </div>
                      </div>
                      <div>
                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Cert Expiry</div>
                        <div className="font-[family-name:var(--font-geist-mono)] text-sm mt-1">
                          {result.daysUntilExpiry} days
                        </div>
                      </div>
                      <div>
                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Urgency</div>
                        <div className={`text-sm font-medium mt-1 ${URGENCY_COLORS[result.urgency ?? "LOW"]}`}>
                          {result.urgency}
                        </div>
                      </div>
                      <div>
                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Issuer</div>
                        <div className="text-sm text-zinc-300 mt-1 truncate" title={result.issuer}>
                          {result.issuer?.split("CN=")[1] ?? result.issuer?.substring(0, 30)}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Recommendation */}
                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
                    <div className="text-zinc-500 text-xs uppercase tracking-wider mb-2">Recommended Action</div>
                    <div className="font-medium">{result.recommendedService}</div>
                    <p className="text-zinc-400 text-sm mt-2">{result.gradeLabel}</p>
                  </div>

                  {/* CTA */}
                  <div className="bg-gradient-to-r from-zinc-900 to-zinc-800 border border-zinc-700 rounded-xl p-6 text-center space-y-3">
                    <h3 className="font-semibold text-lg">Get the Full Assessment</h3>
                    <p className="text-zinc-400 text-sm">
                      Complete scan of all subdomains, endpoints, and a prioritized
                      migration roadmap with Hedera-anchored audit trail.
                    </p>
                    <a
                      href={`mailto:admin@taurusai.io?subject=PQC%20Assessment%20Request%20-%20${result.domain}&body=Domain%3A%20${result.domain}%0APQC%20Score%3A%20${result.pqcScore}%2F100%0AGrade%3A%20${result.cryptoGrade}%0A%0APlease%20send%20me%20a%20full%20PQC%20compliance%20assessment.`}
                      className="inline-block px-6 py-3 bg-zinc-100 text-zinc-900 rounded-lg font-medium text-sm hover:bg-zinc-200 transition-colors"
                    >
                      Request Assessment — Starting at $500
                    </a>
                  </div>
                </div>
              ) : (
                <div className="bg-red-950 border border-red-800 rounded-xl p-6 text-red-300">
                  <span className="font-medium">Scan failed:</span> {result.error}
                </div>
              )}
            </div>
          )}

          {/* Trust Indicators */}
          <div className="mt-16 pt-8 border-t border-zinc-800">
            <div className="grid grid-cols-3 gap-8 text-center">
              <div>
                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">NIST</div>
                <div className="text-zinc-500 text-xs mt-1">FIPS 203/204/205</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">CNSA 2.0</div>
                <div className="text-zinc-500 text-xs mt-1">NSA Compliance</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">Hedera</div>
                <div className="text-zinc-500 text-xs mt-1">Audit Trail</div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 px-6 py-6">
        <div className="max-w-4xl mx-auto flex items-center justify-between text-sm text-zinc-500">
          <span>TAURUS AI Corp</span>
          <span className="font-[family-name:var(--font-geist-mono)]">hiero-cli-pqc v0.1.0</span>
        </div>
      </footer>
    </div>
  );
}
