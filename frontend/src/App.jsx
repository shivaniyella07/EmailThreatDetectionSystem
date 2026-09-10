import { useEffect, useState } from "react";
import { jsPDF } from "jspdf";
import Dashboard from "./pages/Dashboard";
import EmailAnalysis from "./pages/EmailAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";
const HEALTH_URL = `${API_BASE_URL}/api/health`;
const THREAT_ANALYSIS_URL = `${API_BASE_URL}/api/threat-analysis`;

const navItems = [
  { id: "dashboard", label: "Dashboard" },
  { id: "email", label: "Email Analysis" },
  { id: "threat-analysis", label: "Threat Analysis" },
  { id: "geolocation", label: "Geolocation" },
  { id: "forensics", label: "Forensics" },
  { id: "reports", label: "Reports" },
];

const normalizeRiskLevel = (value = "SAFE") => {
  const next = String(value || "SAFE").toUpperCase();
  if (next === "HIGH_RISK") return "High";
  if (next === "SUSPICIOUS") return "Medium";
  if (next === "SAFE") return "Safe";
  return "Safe";
};

const normalizeSummaryEntry = (key, value) => {
  const titleLookup = {
    nlp: "NLP Analysis",
    header: "Header Forensics",
    header_analysis: "Header Forensics",
    url: "URL Intelligence",
    geolocation: "Geolocation",
    threat_intelligence: "Threat Intelligence",
  };

  const title = titleLookup[key] || key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  const riskLevel = value?.risk_level || value?.riskLevel || "SAFE";
  const score = Number(value?.risk_score ?? value?.threatScore ?? 0);
  const indicators = Array.isArray(value?.indicators) ? value.indicators : [];
  const details = value?.details && typeof value.details === "object" ? Object.values(value.details) : [];
  const finding = indicators[0] || details.find((entry) => typeof entry === "string" && entry.trim()) || "No additional indicators reported.";

  return {
    title,
    status: normalizeRiskLevel(riskLevel) === "High" ? "High Risk" : normalizeRiskLevel(riskLevel) === "Medium" ? "Medium Risk" : "Low Risk",
    confidence: Math.max(0, Math.min(100, score)),
    finding: String(finding),
  };
};

const buildSummaryFromResponse = (analyses = {}) => {
  const entries = Object.entries(analyses)
    .filter(([, value]) => value && typeof value === "object")
    .map(([key, value]) => normalizeSummaryEntry(key, value));

  return entries.length ? entries : [{ title: "NLP Analysis", status: "Low Risk", confidence: 0, finding: "No findings were returned from the backend." }];
};

const buildNormalizedReport = (backendData = {}, emailData = {}) => {
  const overall = backendData.overall || {};
  const analyses = backendData.analyses || {};
  const threatIntel = backendData.threat_intelligence || {};
  const riskLevelRaw = backendData.risk_level || overall.risk_level || "SAFE";
  const riskLevel = normalizeRiskLevel(riskLevelRaw);
  const score = Number(backendData.risk_score ?? overall.risk_score ?? 0);

  const topReasons = [
    ...(Array.isArray(backendData.top_reasons) ? backendData.top_reasons : []),
    ...(Array.isArray(backendData.reasons) ? backendData.reasons : []),
  ];

  const indicators = [...new Set([
    ...topReasons,
    ...Object.values(analyses).flatMap((module) => (module && Array.isArray(module.indicators) ? module.indicators : [])),
    ...(Array.isArray(threatIntel.indicators) ? threatIntel.indicators : []),
  ].filter(Boolean))].slice(0, 5);

  const ipDetails = (analyses.ip && analyses.ip.details) || {};
  const geoDetails = (analyses.geolocation && analyses.geolocation.details) || {};
  const threatIntelFindings = Array.isArray(threatIntel.findings) ? threatIntel.findings : [];
  const sourceIp = ipDetails.chosen_sending_node || ipDetails.ip_address || ipDetails.originating_ip || "Unknown";

  return {
    caseId: `SEC-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toLocaleString("en-GB", {
      timeZone: "UTC",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }) + " UTC",
    subject: backendData.email?.subject || emailData.subject || "Email Threat Assessment",
    sender: backendData.email?.from || emailData.senderEmail || "Unknown sender",
    senderAlias: backendData.email?.from || emailData.senderEmail || "Unknown sender",
    riskLevel,
    threatScore: score,
    summary: buildSummaryFromResponse(analyses),
    indicators: indicators.length ? indicators : ["Awaiting backend assessment"],
    origin: {
      sourceIp,
      country: geoDetails.country || "Unknown",
      city: geoDetails.city || geoDetails.region || "Unknown",
      confidence: geoDetails.confidence ? `${geoDetails.confidence}%` : `${Math.max(0, Math.min(100, score))}%`,
    },
    threatIntel: {
      domainReputation: threatIntel.details?.domain_reputation || threatIntel.details?.threat_category || "No known domain reputation match",
      blacklistMatches: threatIntel.details?.blacklist_matches || threatIntel.details?.blacklists || "No public blacklist matches",
      knownCampaignMatches: threatIntelFindings.find((item) => item?.campaign)?.campaign || "No known campaign match",
    },
    verdict: {
      riskLevel,
      recommendedAction: backendData.recommendation || overall.recommendation || "Review the message with the security team and verify the sender through an independent channel.",
      analystNotes: topReasons[0] || backendData.classification || "Backend analysis identified suspicious indicators that justify manual review.",
    },
  };
};

function App() {
  const [page, setPage] = useState("dashboard");
  const [backendOnline, setBackendOnline] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [analysisError, setAnalysisError] = useState("");

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

  const handleAnalyzeEmail = async (emailData = {}) => {
    setIsLoading(true);
    setAnalysisError("");

    try {
      const response = await fetch(THREAT_ANALYSIS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email_text: emailData.body || "",
          subject: emailData.subject || "",
          sender: emailData.senderEmail || "",
          headers: "",
          enable_external: false,
        }),
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }

      if (!response.ok) {
        const detailString = Array.isArray(payload?.detail)
          ? payload.detail.map((item) => item.msg || item).join("; ")
          : typeof payload?.detail === "string"
            ? payload.detail
            : "The backend rejected the request.";
        throw new Error(detailString || `Request failed with status ${response.status}`);
      }

      const normalizedReport = buildNormalizedReport(payload || {}, emailData);
      setAnalysisData(normalizedReport);
      setPage("threat-analysis");
    } catch (error) {
      setAnalysisError(error instanceof Error ? error.message : "Unable to reach the backend. Please confirm the API is running on port 8001.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackToDashboard = () => setPage("dashboard");
  const handleReAnalyze = () => setPage("email");

  const generateForensicReportPdf = (report = analysisData) => {
    if (!report) return null;
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
    (report.indicators || []).forEach((item) => {
      doc.text(`• ${item}`, 18, y);
      y += 7;
    });

    y += 6;
    doc.text("Recommended Actions:", 14, y);
    y += 8;
    (report.summary || []).forEach((item) => {
      doc.text(`• ${item.title}: ${item.finding}`, 18, y, { maxWidth: 160 });
      y += 10;
    });

    return doc;
  };

  const handleViewForensicReport = () => {
    if (!analysisData) {
      setAnalysisError("Analyze an email before viewing the forensic report.");
      return;
    }
    const doc = generateForensicReportPdf(analysisData);
    const blob = doc.output("blob");
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const handleDownloadForensicReport = () => {
    if (!analysisData) {
      setAnalysisError("Analyze an email before downloading the forensic report.");
      return;
    }
    const doc = generateForensicReportPdf(analysisData);
    doc.save(`forensic-report-${analysisData.caseId}.pdf`);
  };

  const renderPage = () => {
    if (page === "dashboard") {
      return (
        <Dashboard
          analysisData={analysisData}
          onNavigate={setPage}
          onViewReport={handleViewForensicReport}
          onDownloadReport={handleDownloadForensicReport}
        />
      );
    }

    if (page === "email") {
      return <EmailAnalysis analysisData={analysisData} isLoading={isLoading} errorMessage={analysisError} onAnalyze={handleAnalyzeEmail} />;
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

    return (
      <Dashboard
        analysisData={analysisData}
        onNavigate={setPage}
        onViewReport={handleViewForensicReport}
        onDownloadReport={handleDownloadForensicReport}
      />
    );
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
                    if (!isDisabled) setPage(item.id);
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