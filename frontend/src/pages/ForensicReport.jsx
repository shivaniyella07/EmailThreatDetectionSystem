import React from "react";
import { jsPDF } from "jspdf";

const reportData = {
  caseId: "SEC-2091",
  dateTime: "2026-09-10 09:42 UTC",
  analystStatus: "Escalated to SOC Lead",
  threatScore: 92,
  riskLevel: "Critical",
  finalVerdict: "Phishing / credential theft attempt confirmed",
  sender: "security-update@secure-portal-verify.com",
  subject: "Urgent: Account Verification Required - Immediate Action Needed",
  receivedTime: "2026-09-10 08:58 UTC",
  findings: [
    {
      title: "NLP Analysis Results",
      result: "Urgency language and impersonation indicators were present in the subject and body.",
    },
    {
      title: "Header Forensics Results",
      result: "SPF, DKIM, and DMARC checks failed. Sender domain does not align with verified infrastructure.",
    },
    {
      title: "URL Intelligence Results",
      result: "Suspicious redirect link matched known credential harvesting infrastructure and was marked malicious.",
    },
    {
      title: "Geolocation Results",
      result: "Originated from Singapore with a 94% confidence score and inconsistent ASN routing behavior.",
    },
    {
      title: "Threat Intelligence Results",
      result: "Domain and campaign patterns matched a finance-themed phishing cluster tracked by the SOC.",
    },
  ],
  suspiciousUrls: [
    "https://secure-portal-verify-login.com/account",
    "https://verify-bank-login-update.net/authentication",
  ],
  spfStatus: "Fail",
  dkimStatus: "Fail",
  dmarcStatus: "Fail",
  sourceIp: "203.0.113.18",
  geolocation: "Singapore, Singapore",
  threatIndicators: [
    "Urgency language detected",
    "Suspicious URLs found",
    "SPF failure",
    "DKIM failure",
    "Sender spoofing suspected",
  ],
  recommendedActions: [
    "Block Sender",
    "Quarantine Email",
    "User Awareness Review",
  ],
};

function exportJsonReport(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `forensic-report-${data.caseId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadPdfReport(data) {
  const doc = new jsPDF();

  doc.setFillColor(8, 15, 24);
  doc.rect(0, 0, 210, 297, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("Forensic Report", 14, 18);

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  let y = 30;

  const rows = [
    ["Case ID", data.caseId],
    ["Threat Score", `${data.threatScore}/100`],
    ["Risk Level", data.riskLevel],
    ["Sender", data.sender],
    ["Subject", data.subject],
    ["Source IP", data.sourceIp],
    ["Geolocation", data.geolocation],
    ["Final Verdict", data.finalVerdict],
  ];

  rows.forEach(([label, value]) => {
    if (y > 260) {
      doc.addPage();
      y = 20;
    }
    doc.setTextColor(147, 197, 253);
    doc.text(`${label}:`, 14, y);
    doc.setTextColor(255, 255, 255);
    doc.text(String(value), 62, y, { maxWidth: 130 });
    y += 8;
  });

  y += 8;
  doc.setTextColor(147, 197, 253);
  doc.text("Threat Indicators:", 14, y);
  y += 8;
  doc.setTextColor(255, 255, 255);
  data.threatIndicators.forEach((item) => {
    if (y > 260) {
      doc.addPage();
      y = 20;
    }
    doc.text(`• ${item}`, 18, y);
    y += 7;
  });

  y += 5;
  doc.setTextColor(147, 197, 253);
  doc.text("Recommended Actions:", 14, y);
  y += 8;
  doc.setTextColor(255, 255, 255);
  data.recommendedActions.forEach((item) => {
    if (y > 260) {
      doc.addPage();
      y = 20;
    }
    doc.text(`• ${item}`, 18, y);
    y += 7;
  });

  doc.save(`forensic-report-${data.caseId}.pdf`);
}

export default function ForensicReport({ data = reportData, onBack }) {
  return (
    <div className="min-h-screen bg-[#040b13] text-slate-100 antialiased">
      <div className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.12),transparent_25%),radial-gradient(circle_at_top_right,_rgba(59,130,246,0.1),transparent_30%)]" />

        <div className="relative mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <header className="mb-6 rounded-[28px] border border-white/10 bg-slate-950/70 p-4 shadow-[0_0_30px_rgba(14,165,233,0.08)] backdrop-blur-xl">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-[10px] uppercase tracking-[0.3em] text-cyan-300/80">Threat Defense</p>
                <h1 className="mt-2 text-2xl font-semibold text-white">Forensic Report</h1>
              </div>

              <div className="flex flex-wrap gap-3">
                <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-200">
                  Case ID: {data.caseId}
                </span>
                <span className="rounded-full border border-white/10 bg-slate-900/60 px-3 py-2 text-sm text-slate-300">
                  {data.dateTime}
                </span>
              </div>
            </div>
          </header>

          <main className="space-y-6">
            <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_30px_70px_rgba(2,6,23,0.75)] backdrop-blur-xl">
                <div className="mb-5 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.28em] text-slate-400">Executive Summary</p>
                    <h2 className="mt-2 text-2xl font-semibold text-white">Threat Assessment Summary</h2>
                  </div>
                  <span className="rounded-full border border-rose-400/35 bg-rose-500/10 px-3 py-2 text-xs uppercase tracking-[0.2em] text-rose-300">
                    {data.riskLevel}
                  </span>
                </div>

                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Threat Score</p>
                    <p className="mt-2 text-3xl font-bold text-white">{data.threatScore}</p>
                    <p className="mt-1 text-xs text-cyan-300">/100</p>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Risk Level</p>
                    <p className="mt-2 text-lg font-semibold text-white">{data.riskLevel}</p>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                    <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Analyst Status</p>
                    <p className="mt-2 text-sm font-medium text-cyan-300">{data.analystStatus}</p>
                  </div>
                </div>

                <div className="mt-5 rounded-2xl border border-rose-400/20 bg-rose-500/5 p-4">
                  <p className="text-[10px] uppercase tracking-[0.24em] text-rose-300">Final Verdict</p>
                  <p className="mt-2 text-base font-medium text-white">{data.finalVerdict}</p>
                </div>
              </div>

              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Email Information</h3>
                <div className="mt-4 space-y-3 text-sm">
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Sender</p>
                    <p className="mt-1 font-medium text-white">{data.sender}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Subject</p>
                    <p className="mt-1 font-medium text-white">{data.subject}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Received Time</p>
                    <p className="mt-1 font-medium text-white">{data.receivedTime}</p>
                  </div>
                </div>
              </div>
            </section>

            <section className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
              <div className="mb-5">
                <p className="text-[10px] uppercase tracking-[0.28em] text-slate-400">Analysis Findings</p>
                <h3 className="mt-2 text-2xl font-semibold text-white">Module Findings</h3>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                {data.findings.map((finding) => (
                  <div key={finding.title} className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                    <p className="text-base font-medium text-white">{finding.title}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{finding.result}</p>
                  </div>
                ))}
              </div>
            </section>

            <section className="grid gap-6 xl:grid-cols-[1fr_1fr]">
              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Evidence</h3>
                <div className="mt-4 space-y-3 text-sm">
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Suspicious URLs</p>
                    <ul className="mt-2 space-y-1 text-slate-300">
                      {data.suspiciousUrls.map((url) => (
                        <li key={url}>• {url}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">SPF Status</p>
                    <p className="mt-1 font-medium text-white">{data.spfStatus}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">DKIM Status</p>
                    <p className="mt-1 font-medium text-white">{data.dkimStatus}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">DMARC Status</p>
                    <p className="mt-1 font-medium text-white">{data.dmarcStatus}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-3">
                    <p className="text-slate-400">Source IP</p>
                    <p className="mt-1 font-medium text-white">{data.sourceIp}</p>
                  </div>
                </div>
              </div>

              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <h3 className="text-xl font-semibold text-white">Recommended Actions</h3>
                <div className="mt-4 space-y-3">
                  {data.recommendedActions.map((action) => (
                    <div key={action} className="rounded-2xl border border-cyan-400/20 bg-cyan-500/5 px-3 py-3 text-sm text-cyan-100">
                      {action}
                    </div>
                  ))}
                </div>

                <div className="mt-5 rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                  <p className="text-[10px] uppercase tracking-[0.24em] text-slate-400">Threat Indicators</p>
                  <ul className="mt-2 space-y-2 text-sm text-slate-300">
                    {data.threatIndicators.map((item) => (
                      <li key={item} className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-rose-400" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>

            <section className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_30px_rgba(14,165,233,0.06)] backdrop-blur-xl">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-[10px] uppercase tracking-[0.3em] text-slate-400">Report Actions</p>
                  <h3 className="mt-2 text-2xl font-semibold text-white">Export and Navigation</h3>
                </div>

                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={() => downloadPdfReport(data)}
                    className="rounded-full bg-[linear-gradient(135deg,#22d3ee,#3b82f6)] px-4 py-2.5 text-sm font-semibold text-slate-950 shadow-[0_0_25px_rgba(34,211,238,0.35)] transition hover:brightness-110"
                  >
                    Download PDF
                  </button>

                  <button
                    onClick={() => exportJsonReport(data)}
                    className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-4 py-2.5 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/50"
                  >
                    Export JSON
                  </button>

                  <button
                    onClick={onBack}
                    className="rounded-full border border-white/10 bg-slate-900/70 px-4 py-2.5 text-sm font-medium text-slate-100 transition hover:border-cyan-400/20"
                  >
                    Back to Dashboard
                  </button>
                </div>
              </div>
            </section>
          </main>
        </div>
      </div>
    </div>
  );
}
