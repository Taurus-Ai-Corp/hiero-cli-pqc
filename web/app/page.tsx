     1|"use client";
     2|
     3|import { useState } from "react";
     4|
     5|type ScanResult = {
     6|  success: boolean;
     7|  domain?: string;
     8|  keyAlgorithm?: string;
     9|  keySize?: number;
    10|  cryptoGrade?: string;
    11|  gradeLabel?: string;
    12|  daysUntilExpiry?: number;
    13|  issuer?: string;
    14|  validTo?: string;
    15|  pqcScore?: number;
    16|  urgency?: string;
    17|  recommendedService?: string;
    18|  priceRange?: string;
    19|  error?: string;
    20|};
    21|
    22|const GRADE_COLORS: Record<string, string> = {
    23|  CRITICAL: "text-red-400 bg-red-950 border-red-800",
    24|  WEAK: "text-orange-400 bg-orange-950 border-orange-800",
    25|  MODERATE: "text-yellow-400 bg-yellow-950 border-yellow-800",
    26|  STRONG: "text-green-400 bg-green-950 border-green-800",
    27|  PQC_READY: "text-emerald-400 bg-emerald-950 border-emerald-800",
    28|};
    29|
    30|const URGENCY_COLORS: Record<string, string> = {
    31|  IMMEDIATE: "text-red-400",
    32|  HIGH: "text-orange-400",
    33|  MEDIUM: "text-yellow-400",
    34|  LOW: "text-zinc-400",
    35|};
    36|
    37|export default function Home() {
    38|  const [domain, setDomain] = useState("");
    39|  const [loading, setLoading] = useState(false);
    40|  const [result, setResult] = useState<ScanResult | null>(null);
    41|
    42|  async function handleScan(e: React.FormEvent) {
    43|    e.preventDefault();
    44|    if (!domain.trim()) return;
    45|    setLoading(true);
    46|    setResult(null);
    47|    try {
    48|      const res = await fetch("/api/scan", {
    49|        method: "POST",
    50|        headers: { "Content-Type": "application/json" },
    51|        body: JSON.stringify({ domain: domain.trim() }),
    52|      });
    53|      const data = await res.json();
    54|      setResult(data);
    55|    } catch {
    56|      setResult({ success: false, error: "Network error. Please try again." });
    57|    } finally {
    58|      setLoading(false);
    59|    }
    60|  }
    61|
    62|  return (
    63|    <div className="min-h-screen flex flex-col font-[family-name:var(--font-geist-sans)]">
    64|      {/* Header */}
    65|      <header className="border-b border-zinc-800 px-6 py-4">
    66|        <div className="max-w-4xl mx-auto flex items-center justify-between">
    67|          <div className="flex items-center gap-2">
    68|            <div className="w-2 h-2 bg-emerald-500 rounded-full" />
    69|            <span className="font-[family-name:var(--font-geist-mono)] text-sm text-zinc-400">gridera-scan</span>
    70|          </div>
    71|          <a
    72|            href="https://github.com/Taurus-Ai-Corp/gridera-scan-cli"
    73|            target="_blank"
    74|            rel="noopener noreferrer"
    75|            className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
    76|          >
    77|            GitHub
    78|          </a>
    79|        </div>
    80|      </header>
    81|
    82|      {/* Hero */}
    83|      <main className="flex-1 flex flex-col items-center justify-center px-6 py-16">
    84|        <div className="max-w-2xl w-full text-center space-y-6">
    85|          <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
    86|            Is Your Organization
    87|            <br />
    88|            <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-400 to-red-500">
    89|              Quantum-Safe?
    90|            </span>
    91|          </h1>
    92|          <p className="text-zinc-400 text-lg max-w-xl mx-auto">
    93|            Free instant scan. Enter any domain to check if its SSL certificate
    94|            is ready for the post-quantum era.
    95|          </p>
    96|
    97|          {/* Scan Form */}
    98|          <form onSubmit={handleScan} className="flex gap-3 max-w-lg mx-auto mt-8">
    99|            <input
   100|              type="text"
   101|              value={domain}
   102|              onChange={(e) => setDomain(e.target.value)}
   103|              placeholder="rbc.com"
   104|              className="flex-1 px-4 py-3 bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 font-[family-name:var(--font-geist-mono)] text-sm"
   105|              disabled={loading}
   106|            />
   107|            <button
   108|              type="submit"
   109|              disabled={loading || !domain.trim()}
   110|              className="px-6 py-3 bg-zinc-100 text-zinc-900 rounded-lg font-medium text-sm hover:bg-zinc-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
   111|            >
   112|              {loading ? "Scanning..." : "Scan Now"}
   113|            </button>
   114|          </form>
   115|
   116|          {/* Results */}
   117|          {result && (
   118|            <div className="mt-10 text-left max-w-lg mx-auto">
   119|              {result.success ? (
   120|                <div className="space-y-4">
   121|                  {/* Grade Badge */}
   122|                  <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm font-medium ${GRADE_COLORS[result.cryptoGrade ?? "WEAK"]}`}>
   123|                    {result.cryptoGrade}
   124|                  </div>
   125|
   126|                  {/* Score Card */}
   127|                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-4">
   128|                    <div className="flex items-center justify-between">
   129|                      <span className="text-zinc-400 text-sm">PQC Urgency Score</span>
   130|                      <span className="text-3xl font-bold font-[family-name:var(--font-geist-mono)]">
   131|                        {result.pqcScore}<span className="text-zinc-600 text-lg">/100</span>
   132|                      </span>
   133|                    </div>
   134|
   135|                    <div className="w-full bg-zinc-800 rounded-full h-2">
   136|                      <div
   137|                        className="h-2 rounded-full transition-all duration-500 bg-gradient-to-r from-orange-500 to-red-500"
   138|                        style={{ width: `${result.pqcScore}%` }}
   139|                      />
   140|                    </div>
   141|
   142|                    <div className="grid grid-cols-2 gap-4 pt-2">
   143|                      <div>
   144|                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Algorithm</div>
   145|                        <div className="font-[family-name:var(--font-geist-mono)] text-sm mt-1">
   146|                          {result.keyAlgorithm} {result.keySize}-bit
   147|                        </div>
   148|                      </div>
   149|                      <div>
   150|                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Cert Expiry</div>
   151|                        <div className="font-[family-name:var(--font-geist-mono)] text-sm mt-1">
   152|                          {result.daysUntilExpiry} days
   153|                        </div>
   154|                      </div>
   155|                      <div>
   156|                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Urgency</div>
   157|                        <div className={`text-sm font-medium mt-1 ${URGENCY_COLORS[result.urgency ?? "LOW"]}`}>
   158|                          {result.urgency}
   159|                        </div>
   160|                      </div>
   161|                      <div>
   162|                        <div className="text-zinc-500 text-xs uppercase tracking-wider">Issuer</div>
   163|                        <div className="text-sm text-zinc-300 mt-1 truncate" title={result.issuer}>
   164|                          {result.issuer?.split("CN=")[1] ?? result.issuer?.substring(0, 30)}
   165|                        </div>
   166|                      </div>
   167|                    </div>
   168|                  </div>
   169|
   170|                  {/* Recommendation */}
   171|                  <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
   172|                    <div className="text-zinc-500 text-xs uppercase tracking-wider mb-2">Recommended Action</div>
   173|                    <div className="font-medium">{result.recommendedService}</div>
   174|                    <p className="text-zinc-400 text-sm mt-2">{result.gradeLabel}</p>
   175|                  </div>
   176|
   177|                  {/* CTA */}
   178|                  <div className="bg-gradient-to-r from-zinc-900 to-zinc-800 border border-zinc-700 rounded-xl p-6 text-center space-y-3">
   179|                    <h3 className="font-semibold text-lg">Get the Full Assessment</h3>
   180|                    <p className="text-zinc-400 text-sm">
   181|                      Complete scan of all subdomains, endpoints, and a prioritized
   182|                      migration roadmap with Hedera-anchored audit trail.
   183|                    </p>
   184|                    <a
   185|                      href={`mailto:admin@taurusai.io?subject=PQC%20Assessment%20Request%20-%20${result.domain}&body=Domain%3A%20${result.domain}%0APQC%20Score%3A%20${result.pqcScore}%2F100%0AGrade%3A%20${result.cryptoGrade}%0A%0APlease%20send%20me%20a%20full%20PQC%20compliance%20assessment.`}
   186|                      className="inline-block px-6 py-3 bg-zinc-100 text-zinc-900 rounded-lg font-medium text-sm hover:bg-zinc-200 transition-colors"
   187|                    >
   188|                      Request Assessment — Starting at $500
   189|                    </a>
   190|                  </div>
   191|                </div>
   192|              ) : (
   193|                <div className="bg-red-950 border border-red-800 rounded-xl p-6 text-red-300">
   194|                  <span className="font-medium">Scan failed:</span> {result.error}
   195|                </div>
   196|              )}
   197|            </div>
   198|          )}
   199|
   200|          {/* Trust Indicators */}
   201|          <div className="mt-16 pt-8 border-t border-zinc-800">
   202|            <div className="grid grid-cols-3 gap-8 text-center">
   203|              <div>
   204|                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">NIST</div>
   205|                <div className="text-zinc-500 text-xs mt-1">FIPS 203/204/205</div>
   206|              </div>
   207|              <div>
   208|                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">CNSA 2.0</div>
   209|                <div className="text-zinc-500 text-xs mt-1">NSA Compliance</div>
   210|              </div>
   211|              <div>
   212|                <div className="text-2xl font-bold font-[family-name:var(--font-geist-mono)]">Hedera</div>
   213|                <div className="text-zinc-500 text-xs mt-1">Audit Trail</div>
   214|              </div>
   215|            </div>
   216|          </div>
   217|        </div>
   218|      </main>
   219|
   220|      {/* Footer */}
   221|      <footer className="border-t border-zinc-800 px-6 py-6">
   222|        <div className="max-w-4xl mx-auto flex items-center justify-between text-sm text-zinc-500">
   223|          <span>TAURUS AI Corp</span>
   224|          <span className="font-[family-name:var(--font-geist-mono)]">gridera-scan v0.1.0</span>
   225|        </div>
   226|      </footer>
   227|    </div>
   228|  );
   229|}
   230|