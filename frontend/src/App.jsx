import { useEffect, useState } from "react";
import { jsPDF } from "jspdf";
import Dashboard from "./pages/Dashboard";
import EmailAnalysis from "./pages/EmailAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";

const HEALTH_URL = "http://127.0.0.1:8000/api/health";

const navItems = [
  { id: "dashboard", label: "Dashboard" },
  { id: "email", label: "Email Analysis" },
  { id: "threat-analysis", label: "Threat Analysis" },
  { id: "geolocation", label: "Geolocation" },
  { id: "forensics", label: "Forensics" },
  { id: "reports", label: "Reports" },
];

const sampleThreatData = {
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

const buildThreatReportFromEmail = (emailData = {}) => {
  const sender = (emailData.senderEmail || sampleThreatData.sender).trim();
  const subject = (emailData.subject || sampleThreatData.subject).trim();
  const body = (emailData.body || "").trim();

  const bodyPreview = body.length > 140 ? `${body.slice(0, 140)}...` : body;
  const riskScore = body.toLowerCase().includes("verify") || body.toLowerCase().includes("urgent") ? 92 : 76;

  return {
    ...sampleThreatData,
    caseId: `SEC-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toLocaleString("en-GB", {
      timeZone: "UTC",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }) + " UTC",
    subject,
    sender,
    senderAlias: sender,
    riskLevel: riskScore >= 85 ? "Critical" : "High",
    threatScore: riskScore,
    verdict: {
      ...sampleThreatData.verdict,
      riskLevel: riskScore >= 85 ? "Critical" : "High",
      recommendedAction:
        riskScore >= 85
          ? "Quarantine the message, block the sender, and alert the recipient to reset credentials."
          : "Flag the message for review and monitor the sender for further activity.",
      analystNotes: bodyPreview
        ? `The analyzed message references: "${bodyPreview}" and matches risky urgency patterns commonly seen in phishing attempts.`
        : sampleThreatData.verdict.analystNotes,
    },
    summary: sampleThreatData.summary.map((item, index) => ({
      ...item,
      finding:
        index === 0
          ? `Message content references urgency and credential confirmation language from the sender "${sender}".`
          : item.finding,
    })),
  };
};

function App() {
  const [page, setPage] = useState("dashboard");
  const [backendOnline, setBackendOnline] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(sampleThreatData);

  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const response = await fetch(HEALTH_URL);
        if (!response.ok) throw new Error("Health check failed");

        const data = await response.json();
        if (!cancelled) setBackendOnline(data.status === "healthy");
      } catch {
        if (!cancelled) setBackendOnline(false);
      }
    }

    checkHealth();
    const intervalId = setInterval(checkHealth, 8000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const handleAnalyzeEmail = (emailData = {}) => {
    setIsLoading(true);
    window.setTimeout(() => {
      const generatedReport = buildThreatReportFromEmail(emailData);
      setAnalysisData(generatedReport);
      setPage("threat-analysis");
      setIsLoading(false);
    }, 1400);
  };

  const handleBackToDashboard = () => {
    setPage("dashboard");
  };

  const handleReAnalyze = () => {
    setPage("email");
  };

  const generateForensicReportPdf = (report = analysisData) => {
    const doc = new jsPDF();
    doc.setFillColor(255, 255, 255);
    doc.rect(0, 0, 210, 297, "F");

    doc.setTextColor(15, 23, 42);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("Email Threat Detection Report", 14, 18);

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    let y = 32;

    const rows = [
      ["Case ID", report.caseId],
      ["Threat Score", `${report.threatScore}/100`],
      ["Risk Level", report.riskLevel],
      ["Sender", report.sender],
      ["Subject", report.subject],
      ["Source IP", report.origin.sourceIp],
      ["Geolocation", `${report.origin.country}, ${report.origin.city}`],
      ["Final Verdict", report.verdict.riskLevel],
    ];

    rows.forEach(([label, value]) => {
      doc.setTextColor(30, 41, 59);
      doc.text(`${label}:`, 14, y);
      doc.setTextColor(15, 23, 42);
      doc.text(String(value), 62, y, { maxWidth: 130 });
      y += 8;
    });

    y += 8;
    doc.text("Threat Indicators:", 14, y);
    y += 8;
    report.indicators.forEach((item) => {
      doc.text(`• ${item}`, 18, y);
      y += 7;
    });

    y += 6;
    doc.text("Recommended Actions:", 14, y);
    y += 8;
    report.summary.forEach((item) => {
      doc.text(`• ${item.title}: ${item.finding}`, 18, y, { maxWidth: 160 });
      y += 10;
    });

    return doc;
  };

  const handleViewForensicReport = () => {
    const doc = generateForensicReportPdf(analysisData);
    const blob = doc.output("blob");
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const handleDownloadForensicReport = () => {
    const doc = generateForensicReportPdf(analysisData);
    doc.save(`forensic-report-${analysisData.caseId}.pdf`);
  };

  const renderPage = () => {
    if (page === "dashboard") {
      return <Dashboard backendOnline={backendOnline} onNavigate={setPage} onViewReport={handleViewForensicReport} onDownloadReport={handleDownloadForensicReport} />;
    }

    if (page === "email") {
      return <EmailAnalysis onAnalyze={handleAnalyzeEmail} />;
    }

    if (page === "threat-analysis") {
      return (
        <ThreatAnalysis
          data={analysisData}
          onBack={handleBackToDashboard}
          onReAnalyze={handleReAnalyze}
          onDownloadForensicReport={handleDownloadForensicReport}
        />
      );
    }

    return <Dashboard backendOnline={backendOnline} onNavigate={setPage} onViewReport={handleViewForensicReport} onDownloadReport={handleDownloadForensicReport} />;
  };

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <div className="flex min-h-screen">
        <aside className="hidden w-72 shrink-0 border-r border-slate-200 bg-white lg:flex lg:flex-col">
          <div className="border-b border-slate-200 px-6 py-5">
            <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Platform</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-[-0.06em] text-slate-900">ThreatLens</h1>
          </div>

          <nav className="flex-1 space-y-1 px-4 py-5">
            {navItems.map((item) => {
              const isActive = page === item.id;
              const isDisabled = ["geolocation", "forensics", "reports"].includes(item.id);

              return (
                <button
                  key={item.id}
                  onClick={() => {
                    if (!isDisabled) {
                      setPage(item.id);
                    }
                  }}
                  disabled={isDisabled}
                  className={`flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                    isDisabled
                      ? "cursor-not-allowed text-slate-400 opacity-70"
                      : isActive
                        ? "bg-slate-900 text-white shadow-sm"
                        : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  }`}
                >
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </aside>

        <div className="flex-1">
          <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/80 backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
              <div>
                <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">AI Email Threat Detection</p>
                <h2 className="mt-1 text-xl font-semibold text-slate-900">
                  {page === "dashboard" ? "Dashboard" : page === "email" ? "Email Analysis" : "Threat Analysis"}
                </h2>
              </div>

              <div className="flex items-center gap-3">
                <div className="hidden rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 md:block">
                  Sep 10, 2026
                </div>
              </div>
            </div>
          </header>

          <main className="p-4 sm:p-6 lg:p-8">{renderPage()}</main>
        </div>
      </div>

      {isLoading && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/20 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-6 py-5 shadow-xl">
            <div className="h-12 w-12 animate-spin rounded-full border-2 border-slate-200 border-t-slate-900" />
            <div className="text-sm font-medium uppercase tracking-[0.22em] text-slate-700">Analyzing Email</div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;