import React from "react";

const defaultAnalysis = {
  caseId: "SEC-2091",
  timestamp: "2026-09-10 09:42 UTC",
  subject: "Urgent: Account Verification Required - Immediate Action Needed",
  sender: "security-update@secure-portal-verify.com",
  senderAlias: "bank-security@official-portal.net",
  riskLevel: "Critical",
  threatScore: 92,
  summary: [
    {
      title: "NLP Analysis",
      status: "High Risk",
      confidence: 96,
      finding: "Urgency language and impersonation were detected in the message body.",
    },
    {
      title: "Header Forensics",
      status: "Failed",
      confidence: 89,
      finding: "SPF and DKIM verification failed for the sender domain.",
    },
    {
      title: "URL Intelligence",
      status: "Malicious",
      confidence: 94,
      finding: "Suspicious redirect link matches a credential harvesting pattern.",
    },
    {
      title: "Geolocation",
      status: "Untrusted",
      confidence: 83,
      finding: "Origin appears to be a high-risk region with inconsistent routing history.",
    },
    {
      title: "Threat Intelligence",
      status: "Known Campaign",
      confidence: 91,
      finding: "Matches historical finance-themed phishing campaign indicators.",
    },
  ],
  indicators: [
    "Urgency language detected",
    "Suspicious URLs found",
    "SPF failure",
    "DKIM failure",
    "Sender spoofing suspected",
  ],
  origin: {
    sourceIp: "203.0.113.18",
    country: "Singapore",
    city: "Singapore",
    confidence: "94%",
  },
  threatIntel: {
    domainReputation: "Low reputation / suspicious",
    blacklistMatches: "4 public blacklists",
    knownCampaignMatches: "FinancePhish Campaign v3",
  },
  verdict: {
    riskLevel: "Critical",
    recommendedAction:
      "Quarantine message, block sender, and notify the user to reset credentials.",
    analystNotes:
      "The email mirrors a credential harvesting campaign targeting finance users and uses spoofed branding to create urgency.",
  },
};

const riskStyles = {
  Safe: { badge: "border-emerald-400/30 bg-emerald-500/10 text-emerald-300" },
  Medium: { badge: "border-amber-400/30 bg-amber-500/10 text-amber-300" },
  High: { badge: "border-orange-400/30 bg-orange-500/10 text-orange-300" },
  Critical: { badge: "border-rose-400/35 bg-rose-500/10 text-rose-300" },
};

export default function ThreatAnalysis({ data = defaultAnalysis, onBack, onReAnalyze, onDownloadForensicReport }) {
  const score = data.threatScore ?? 92;
  const risk = data.riskLevel ?? "Critical";
  const gaugeStyle = {
    background: `conic-gradient(#22d3ee ${(score / 100) * 360}deg, rgba(148,163,184,0.18) 0deg)`,
  };

  return (
    <div className="min-h-screen bg-[#040b13] text-slate-100 antialiased">
      <div className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.12),transparent_25%),radial-gradient(circle_at_top_right,_rgba(59,130,246,0.12),transparent_30%),radial-gradient(circle_at_bottom,_rgba(96,165,250,0.08),transparent_28%)]" />

        <div className="relative mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <header className="mb-6 flex flex-col gap-4 rounded-[28px] border border-white/10 bg-slate-950/70 p-4 shadow-[0_0_30px_rgba(14,165,233,0.08)] backdrop-blur-xl md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-[0.3em] text-cyan-300/80">Threat Defense</p>
              <h1 className="mt-2 text-2xl font-semibold text-white">Threat Analysis</h1>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
              <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-cyan-200">
                Case ID: {data.caseId}
              </span>
              <span className="rounded-full border border-white/10 bg-slate-900/60 px-3 py-2">
                {data.timestamp}
              </span>
            </div>
          </header>

          <main className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <section className="space-y-6">
              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_30px_70px_rgba(2,6,23,0.75)] backdrop-blur-xl">
                <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.28em] text-slate-400">Threat Score</p>
                    <h2 className="mt-2 text-2xl font-semibold text-white">Email Threat Assessment</h2>
                  </div>

                  <span className={`rounded-full border px-3 py-2 text-xs uppercase tracking-[0.2em] ${riskStyles[risk]?.badge || "border-cyan-400/30 bg-cyan-500/10 text-cyan-300"}`}>
                    {risk}
                  </span>
                </div>

                <div className="grid gap-6 lg:grid-cols-[250px_1fr] lg:items-center">
                  <div className="flex justify-center">
                    <div className="relative flex h-52 w-52 items-center justify-center rounded-full p-3" style={gaugeStyle}>
                      <div className="flex h-full w-full flex-col items-center justify-center rounded-full border border-white/10 bg-slate-950">
                        <div className="text-4xl font-bold text-white">{score}</div>
                        <div className="mt-1 text-xs uppercase tracking-[0.3em] text-slate-400">/100</div>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                      <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Subject</p>
                      <p className="mt-2 text-lg font-medium text-white">{data.subject}</p>
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                      <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Sender</p>
                      <p className="mt-2 text-base font-medium text-white">{data.sender}</p>
                      <p className="mt-1 text-sm text-slate-400">Alias: {data.senderAlias}</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <div className="mb-5 flex items-center justify-between">
                  <h3 className="text-xl font-semibold text-white">Analysis Summary</h3>
                  <span className="text-xs uppercase tracking-[0.25em] text-cyan-300">5 Modules</span>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {data.summary.map((item) => (
                    <div key={item.title} className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                      <div className="mb-3 flex items-center justify-between">
                        <p className="text-sm font-medium text-white">{item.title}</p>
                        <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-2 py-1 text-[10px] uppercase tracking-[0.18em] text-cyan-300">
                          {item.status}
                        </span>
                      </div>

                      <div className="mb-3 flex items-center justify-between text-xs text-slate-400">
                        <span>Confidence</span>
                        <span className="text-slate-200">{item.confidence}%</span>
                      </div>

                      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full bg-[linear-gradient(90deg,#22d3ee,#60a5fa,#a78bfa)]"
                          style={{ width: `${item.confidence}%` }}
                        />
                      </div>

                      <p className="mt-3 text-sm leading-6 text-slate-300">{item.finding}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <aside className="space-y-6">
              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Threat Indicators</h3>
                <div className="mt-4 space-y-3">
                  {data.indicators.map((item) => (
                    <div key={item} className="flex items-center gap-3 rounded-2xl border border-white/10 bg-[#0b1220] px-3 py-3 text-sm text-slate-300">
                      <span className="h-2 w-2 rounded-full bg-rose-400" />
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-[30px] border border-cyan-400/20 bg-[linear-gradient(180deg,rgba(15,23,42,0.92),rgba(9,14,25,0.96))] p-5 shadow-[0_0_30px_rgba(14,165,233,0.08)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Origin Intelligence</h3>

                <div className="mt-4 space-y-3">
                  <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-[#0b1220] px-3 py-3 text-sm">
                    <span className="text-slate-400">Source IP</span>
                    <span className="font-medium text-white">{data.origin.sourceIp}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-[#0b1220] px-3 py-3 text-sm">
                    <span className="text-slate-400">Country</span>
                    <span className="font-medium text-white">{data.origin.country}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-[#0b1220] px-3 py-3 text-sm">
                    <span className="text-slate-400">City</span>
                    <span className="font-medium text-white">{data.origin.city}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-[#0b1220] px-3 py-3 text-sm">
                    <span className="text-slate-400">Confidence</span>
                    <span className="font-medium text-cyan-300">{data.origin.confidence}</span>
                  </div>
                </div>
              </div>

              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Threat Intelligence</h3>

                <div className="mt-4 space-y-3 text-sm">
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Domain Reputation</p>
                    <p className="mt-1 font-medium text-white">{data.threatIntel.domainReputation}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Blacklist Matches</p>
                    <p className="mt-1 font-medium text-white">{data.threatIntel.blacklistMatches}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Known Campaign Matches</p>
                    <p className="mt-1 font-medium text-white">{data.threatIntel.knownCampaignMatches}</p>
                  </div>
                </div>
              </div>
            </aside>
          </main>

          <section className="mt-6 rounded-[30px] border border-rose-400/20 bg-[linear-gradient(135deg,rgba(30,41,59,0.9),rgba(15,23,42,0.96))] p-5 shadow-[0_0_30px_rgba(244,63,94,0.08)] backdrop-blur-xl">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <p className="text-[10px] uppercase tracking-[0.28em] text-slate-400">Final Verdict</p>
                <h3 className="mt-2 text-2xl font-semibold text-white">{data.verdict.riskLevel} Risk</h3>
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={onDownloadForensicReport}
                  className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/50"
                >
                  Download Forensic Report
                </button>
                <button
                  onClick={onReAnalyze}
                  className="rounded-full border border-white/10 bg-slate-900/70 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-cyan-400/20"
                >
                  Re-analyze Email
                </button>
                <button
                  onClick={onBack}
                  className="rounded-full border border-white/10 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-cyan-400/20"
                >
                  Back to Dashboard
                </button>
              </div>
            </div>

            <div className="mt-5 grid gap-5 lg:grid-cols-[0.8fr_1.2fr]">
              <div className="rounded-2xl border border-rose-400/20 bg-rose-500/5 p-4">
                <p className="text-[10px] uppercase tracking-[0.25em] text-rose-300">Recommended Action</p>
                <p className="mt-3 text-base font-medium text-white">{data.verdict.recommendedAction}</p>
              </div>

              <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                <p className="text-[10px] uppercase tracking-[0.25em] text-slate-400">Analyst Notes</p>
                <p className="mt-3 text-sm leading-7 text-slate-300">{data.verdict.analystNotes}</p>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
