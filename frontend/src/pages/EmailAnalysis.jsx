import React, { useState } from "react";
import { jsPDF } from "jspdf";

const suspiciousIndicators = [
  "Urgent action required",
  "Suspicious sender domain",
  "Create password prompt",
  "Credential harvesting intent",
  "Link mismatch / spoofed domain",
  "High-risk impersonation pattern",
];

const scoreBreakdown = [
  { label: "Sender Reputation", value: 91 },
  { label: "Domain Trust", value: 87 },
  { label: "Content Risk", value: 94 },
  { label: "Link Analysis", value: 89 },
];

function Icon({ name }) {
  const common = "h-5 w-5";

  switch (name) {
    case "shield":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M12 3.5 18.5 6v5.7c0 4.7-2.8 8.8-6.5 10.8-3.7-2-6.5-6.1-6.5-10.8V6L12 3.5Z" />
          <path d="m9.5 12 1.6 1.6 3.4-3.8" />
        </svg>
      );
    case "mail":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <rect x="3" y="5" width="18" height="14" rx="2.5" />
          <path d="m4 7 8 6 8-6" />
        </svg>
      );
    case "alert":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="M12 3.5 19 17a2 2 0 0 1-1.7 3H6.7A2 2 0 0 1 5 17l7-13.5Z" />
          <path d="M12 8.5v4.3M12 16.8h.01" />
        </svg>
      );
    case "spark":
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={common}>
          <path d="m12 2 1.8 5.2L19 9l-5.2 1.8L12 16l-1.8-5.2L5 9l5.2-1.8L12 2Z" />
        </svg>
      );
    default:
      return null;
  }
}

export default function EmailAnalysis({ onAnalyze }) {
  const [emailData, setEmailData] = useState({
    senderEmail: "",
    subject: "",
    body: "",
    fileName: "",
  });
  const [validationMessage, setValidationMessage] = useState("");

  const handleChange = (event) => {
    const { name, value } = event.target;
    setEmailData((previous) => ({
      ...previous,
      [name]: value,
    }));

    if (validationMessage) {
      setValidationMessage("");
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    const isEmlFile = file.name.toLowerCase().endsWith(".eml");

    setEmailData((previous) => ({
      ...previous,
      fileName: file.name,
    }));

    if (!isEmlFile) {
      return;
    }

    try {
      const text = await file.text();
      const matchSubject = text.match(/Subject:\s*([\s\S]*?)(?:\r?\n\r?\n|$)/i);
      const matchFrom = text.match(/From:\s*([^\r\n]+)/i);
      const bodyMatch = text.match(/\r?\n\r?\n([\s\S]*)/);

      setEmailData((previous) => ({
        ...previous,
        senderEmail: matchFrom ? matchFrom[1].trim() : previous.senderEmail,
        subject: matchSubject ? matchSubject[1].trim() : previous.subject,
        body: bodyMatch ? bodyMatch[1].trim() : previous.body,
      }));
    } catch {
      setEmailData((previous) => ({
        ...previous,
        fileName: file.name,
      }));
    }
  };

  const handleAnalyze = () => {
    const senderEmail = emailData.senderEmail.trim();
    const subject = emailData.subject.trim();
    const body = emailData.body.trim();

    if (!senderEmail || !subject || !body) {
      setValidationMessage("Please enter the sender email, subject, and email body before analyzing.");
      return;
    }

    setValidationMessage("");
    onAnalyze?.(emailData);
  };

  const handleExportReport = () => {
    const senderEmail = emailData.senderEmail.trim();
    const subject = emailData.subject.trim();
    const body = emailData.body.trim();

    if (!senderEmail || !subject || !body) {
      setValidationMessage("Please enter the sender email, subject, and email body before exporting the report.");
      return;
    }

    const doc = new jsPDF();

    doc.setFillColor(8, 15, 24);
    doc.rect(0, 0, 210, 297, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("Email Threat Analysis Report", 14, 18);

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    let y = 32;

    const rows = [
      ["Sender Email", senderEmail],
      ["Subject", subject],
      ["Source File", emailData.fileName || "Manual Entry"],
      ["Threat Level", "Critical"],
      ["Risk Score", "92 / 100"],
    ];

    rows.forEach(([label, value]) => {
      doc.setTextColor(147, 197, 253);
      doc.text(`${label}:`, 14, y);
      doc.setTextColor(255, 255, 255);
      doc.text(String(value), 62, y, { maxWidth: 130 });
      y += 8;
    });

    y += 8;
    doc.setTextColor(147, 197, 253);
    doc.text("Email Body:", 14, y);
    y += 8;
    doc.setTextColor(255, 255, 255);
    const bodyLines = doc.splitTextToSize(body, 160);
    bodyLines.forEach((line) => {
      if (y > 260) {
        doc.addPage();
        y = 20;
      }
      doc.text(line, 14, y);
      y += 6;
    });

    doc.save(`email-analysis-report-${Date.now()}.pdf`);
    setValidationMessage("");
  };

  return (
    <div className="min-h-screen bg-[#040b13] text-slate-100 antialiased">
      <div className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.14),transparent_28%),radial-gradient(circle_at_top_right,_rgba(168,85,247,0.18),transparent_22%),radial-gradient(circle_at_bottom,_rgba(14,165,233,0.12),transparent_30%)]" />
        <div className="pointer-events-none absolute left-[-5rem] top-20 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="pointer-events-none absolute right-[-4rem] top-12 h-80 w-80 rounded-full bg-violet-500/10 blur-3xl" />

        <div className="relative mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <header className="mb-6 flex flex-col gap-4 rounded-[28px] border border-white/10 bg-slate-950/70 px-5 py-4 shadow-[0_0_30px_rgba(34,211,238,0.08)] backdrop-blur-xl md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/35 bg-cyan-500/10 text-cyan-200 shadow-[0_0_22px_rgba(34,211,238,0.25)]">
                <Icon name="shield" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-[0.28em] text-cyan-300/70">Threat Defense</p>
                <h1 className="text-lg font-semibold text-white">Email Analysis</h1>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="rounded-full border border-emerald-400/30 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-300">
                Case ID: SEC-2091
              </span>
              <button
                onClick={handleExportReport}
                className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/50"
              >
                Export Report
              </button>
            </div>
          </header>

          <main className="grid gap-6 xl:grid-cols-[1.5fr_0.8fr]">
            <section className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_30px_70px_rgba(2,6,23,0.75)] backdrop-blur-xl">
              <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-[10px] uppercase tracking-[0.32em] text-slate-400">Inbox Threat Review</p>
                  <h2 className="mt-2 text-2xl font-semibold text-white">Message Analysis</h2>
                </div>
                <button
                  onClick={handleAnalyze}
                  className="rounded-full bg-[linear-gradient(135deg,#22d3ee,#3b82f6)] px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-[0_0_25px_rgba(34,211,238,0.35)] transition hover:brightness-110"
                >
                  Analyze Email
                </button>
              </div>

              {validationMessage && (
                <div className="mb-5 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
                  {validationMessage}
                </div>
              )}

              <div className="space-y-5">
                <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                  <label htmlFor="senderEmail" className="mb-2 block text-[10px] uppercase tracking-[0.25em] text-slate-400">
                    Sender Email
                  </label>
                  <input
                    id="senderEmail"
                    name="senderEmail"
                    type="email"
                    value={emailData.senderEmail}
                    onChange={handleChange}
                    placeholder="security-update@secure-portal-verify.com"
                    className="w-full rounded-xl border border-white/10 bg-slate-950/80 px-3 py-2.5 text-base text-white outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400/40"
                  />
                </div>

                <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                  <label htmlFor="subject" className="mb-2 block text-[10px] uppercase tracking-[0.25em] text-slate-400">
                    Subject
                  </label>
                  <input
                    id="subject"
                    name="subject"
                    type="text"
                    value={emailData.subject}
                    onChange={handleChange}
                    placeholder="Urgent: Account Verification Required"
                    className="w-full rounded-xl border border-white/10 bg-slate-950/80 px-3 py-2.5 text-base text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                  />
                </div>

                <div className="rounded-2xl border border-white/10 bg-[#0b1220] p-4">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <label htmlFor="emailBody" className="text-[10px] uppercase tracking-[0.25em] text-slate-400">
                      Email Body
                    </label>
                    <span className="text-xs text-cyan-300">Mime Type: HTML</span>
                  </div>

                  <textarea
                    id="emailBody"
                    name="body"
                    value={emailData.body}
                    onChange={handleChange}
                    rows="10"
                    placeholder="Paste email content here..."
                    className="w-full resize-none rounded-xl border border-white/10 bg-slate-950/80 px-3 py-3 text-sm leading-7 text-slate-200 outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                  />
                </div>

                <div className="rounded-2xl border border-dashed border-cyan-400/35 bg-[#0b1220] p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <label htmlFor="emlUpload" className="block text-[10px] uppercase tracking-[0.25em] text-slate-400">
                        Upload .eml File
                      </label>
                      <p className="mt-2 text-sm text-slate-300">{emailData.fileName || "No file selected"}</p>
                    </div>

                    <label className="cursor-pointer rounded-full border border-cyan-400/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/50">
                      Choose .eml
                      <input id="emlUpload" type="file" accept=".eml" onChange={handleFileUpload} className="hidden" />
                    </label>
                  </div>
                </div>
              </div>
            </section>

            <aside className="space-y-6">
              <div className="rounded-[30px] border border-cyan-400/20 bg-[linear-gradient(180deg,rgba(15,23,42,0.92),rgba(9,14,25,0.96))] p-5 shadow-[0_0_30px_rgba(34,211,238,0.08)] backdrop-blur-xl">
                <div className="mb-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-200">
                      <Icon name="spark" />
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-[0.25em] text-slate-400">Threat Score</p>
                      <p className="text-xl font-semibold text-white">92 / 100</p>
                    </div>
                  </div>
                  <span className="rounded-full border border-rose-400/35 bg-rose-500/10 px-2.5 py-1 text-[10px] uppercase tracking-[0.2em] text-rose-300">
                    Critical
                  </span>
                </div>

                <div className="mt-4 h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full w-[92%] rounded-full bg-[linear-gradient(90deg,#22d3ee,#60a5fa,#8b5cf6,#f43f5e)] shadow-[0_0_20px_rgba(34,211,238,0.44)]" />
                </div>

                <div className="mt-4 space-y-3">
                  {scoreBreakdown.map((item) => (
                    <div key={item.label}>
                      <div className="mb-1 flex items-center justify-between text-xs text-slate-400">
                        <span>{item.label}</span>
                        <span className="text-slate-200">{item.value}</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                        <div className="h-full rounded-full bg-[linear-gradient(90deg,#22d3ee,#38bdf8,#a78bfa)]" style={{ width: `${item.value}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-[30px] border border-white/10 bg-slate-950/60 p-5 shadow-[0_0_25px_rgba(14,165,233,0.06)] backdrop-blur-xl">
                <div className="mb-4 flex items-center gap-3">
                  <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-amber-400/30 bg-amber-500/10 text-amber-200">
                    <Icon name="alert" />
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.25em] text-slate-400">Risk Level</p>
                    <p className="text-xl font-semibold text-white">High Confidence Threat</p>
                  </div>
                </div>

                <div className="rounded-2xl border border-rose-400/20 bg-rose-500/5 p-3">
                  <p className="text-sm font-medium text-rose-300">Likely phishing / credential theft</p>
                </div>

                <div className="mt-5 space-y-3">
                  <p className="text-[10px] uppercase tracking-[0.25em] text-slate-400">Suspicious indicators</p>
                  {suspiciousIndicators.map((item) => (
                    <div key={item} className="flex items-center gap-2 rounded-xl border border-white/10 bg-[#0b1220] px-3 py-2 text-sm text-slate-300">
                      <span className="h-2 w-2 rounded-full bg-rose-400" />
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </aside>
          </main>
        </div>
      </div>
    </div>
  );
}