import { useEffect, useState } from "react";
import Dashboard from "./pages/Dashboard";
import EmailAnalysis from "./pages/EmailAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";
import ForensicReport from "./ForensicReport";
import Geolocation from "./pages/Geolocation";
import Forensics from "./pages/Forensics";

const API_BASE_URL = "http://127.0.0.1:8001";
const HEALTH_URL = `${API_BASE_URL}/api/health`;
const ANALYZE_URL = `${API_BASE_URL}/api/threat-analysis`;

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard" },
  { id: "email", label: "Email Analysis", icon: "email" },
  { id: "threat-analysis", label: "Threat Analysis", icon: "analysis" },
  { id: "geolocation", label: "Geolocation", icon: "map" },
  { id: "forensics", label: "Forensics", icon: "forensics" },
  { id: "reports", label: "Reports", icon: "reports" },
];

const normalizeAnalysis = (payload = {}) => {
  const analyses = payload.analyses || {};

  return {
    ...payload,
    email: payload.email || {},
    overall: {
      risk_score: payload.overall?.risk_score ?? payload.risk_score ?? 0,
      risk_level: payload.overall?.risk_level ?? payload.risk_level ?? "SAFE",
      classification: payload.overall?.classification ?? payload.classification ?? "SAFE",
      confidence: payload.overall?.confidence ?? "LOW",
      recommendation:
        payload.overall?.recommendation ??
        payload.recommendation ??
        "No significant threat indicators detected.",
      top_reasons: payload.overall?.top_reasons ?? payload.top_reasons ?? [],
    },
    analyses: {
      nlp: analyses.nlp || {},
      header: analyses.header || {},
      url: analyses.url || {},
      ip: analyses.ip || {},
      geolocation: analyses.geolocation || {},
      threat_intelligence: analyses.threat_intelligence || {},
    },
    threat_intelligence: payload.threat_intelligence || analyses.threat_intelligence || {},
    top_reasons: payload.top_reasons || payload.overall?.top_reasons || [],
    category_scores: payload.category_scores || {},
    recommendation: payload.recommendation || payload.overall?.recommendation || "No significant threat indicators detected.",
    disclaimer: payload.disclaimer || "Analysis provides security intelligence and risk assessment; it does not prove attacker identity.",
  };
};

function SidebarIcon({ name }) {
  const base = "h-4 w-4";

  const icons = {
    dashboard: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <path d="M4 13.5h7V4H4v9.5Zm9 0h7V10h-7v3.5ZM13 20h7v-6h-7v6ZM4 20h7v-4H4v4Z" />
      </svg>
    ),
    email: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <rect x="3" y="5" width="18" height="14" rx="2.5" />
        <path d="m4 7 8 6 8-6" />
      </svg>
    ),
    analysis: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <path d="M5 18V6m7 12V9m7 9V4" />
      </svg>
    ),
    map: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <path d="M9 18 3 20V6l6-2 6 2 6-2v14l-6 2-6-2Z" />
        <path d="M9 6v12M15 4v12" />
      </svg>
    ),
    forensics: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <path d="M7 18h10M8 14h8M10 10h4M6 6h12v12H6z" />
      </svg>
    ),
    reports: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={base}>
        <path d="M8 3.5h7l4 4V19a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5.5a2 2 0 0 1 2-2Z" />
        <path d="M15 3.5v4h4M9 12h6M9 16h6" />
      </svg>
    ),
  };

  return icons[name] || null;
}

function App() {
  const [page, setPage] = useState("dashboard");
  const [backendOnline, setBackendOnline] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const checkHealth = async () => {
      try {
        const response = await fetch(HEALTH_URL, { cache: "no-store" });
        if (!response.ok) throw new Error("Health check failed");

        const data = await response.json();
        if (!cancelled) setBackendOnline(data.status === "healthy");
      } catch {
        if (!cancelled) setBackendOnline(false);
      }
    };

    checkHealth();
    const intervalId = setInterval(checkHealth, 8000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const handleAnalyzeEmail = async (emailData = {}) => {
    setIsLoading(true);

    try {
      const response = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email_text: emailData.body || "",
          subject: emailData.subject || "",
          sender: emailData.senderEmail || "",
          from_email: emailData.senderEmail || "",
          to: emailData.to || "",
          headers: emailData.headers || "",
          enable_external: false,
        }),
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.status}`);
      }

      const result = await response.json();
      setAnalysisData(normalizeAnalysis(result));
      setPage("threat-analysis");
    } catch (error) {
      console.error("Email analysis error:", error);
      window.alert(
        "Unable to connect to the analysis server. Make sure the FastAPI backend is running on port 8001."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackToDashboard = () => setPage("dashboard");
  const handleReAnalyze = () => setPage("email");

  const renderPage = () => {
    if (page === "dashboard") {
      return <Dashboard analysisData={analysisData} backendOnline={backendOnline} onNavigate={setPage} />;
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
        />
      );
    }

    if (page === "geolocation") {
      return <Geolocation data={analysisData} onBack={handleBackToDashboard} />;
    }

    if (page === "forensics") {
      return <Forensics data={analysisData} onBack={handleBackToDashboard} />;
    }

    if (page === "reports") {
      return <ForensicReport data={analysisData} onBack={handleBackToDashboard} />;
    }

    return <Dashboard analysisData={analysisData} backendOnline={backendOnline} onNavigate={setPage} />;
  };

  const pageMeta = {
    dashboard: { title: "Dashboard", subtitle: "SOC overview and live intelligence summary" },
    email: { title: "Email Analysis", subtitle: "Inspect and analyze email content" },
    "threat-analysis": { title: "Threat Analysis", subtitle: "Multi-layer AI-powered email security assessment" },
    geolocation: { title: "Geolocation", subtitle: "Threat-origin intelligence estimate" },
    forensics: { title: "Forensics", subtitle: "Email header and authentication review" },
    reports: { title: "Reports", subtitle: "Executive-ready incident summary" },
  };

  const currentPage = pageMeta[page] || pageMeta.dashboard;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased">
      <div className="flex min-h-screen">
        <aside className="hidden w-72 shrink-0 border-r border-slate-800 bg-slate-950/95 lg:flex lg:flex-col">
          <div className="border-b border-slate-800 px-6 py-6">
            <p className="text-[10px] uppercase tracking-[0.28em] text-sky-300/80">Platform</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-[-0.06em] text-white">EmailThreat</h1>
            <p className="mt-2 text-sm text-slate-400">Threat Intelligence Platform</p>
          </div>

          <nav className="flex-1 space-y-1 px-3 py-5">
            {navItems.map((item) => {
              const isActive = page === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => setPage(item.id)}
                  className={`flex w-full items-center gap-3 rounded-2xl px-3 py-2.5 text-sm font-medium transition ${
                    isActive
                      ? "border border-sky-500/30 bg-sky-500/10 text-white shadow-[0_0_25px_rgba(56,189,248,0.12)]"
                      : "text-slate-300 hover:bg-slate-900 hover:text-white"
                  }`}
                >
                  <span className={`flex h-8 w-8 items-center justify-center rounded-xl ${isActive ? "bg-sky-500/15 text-sky-300" : "bg-slate-900 text-slate-400"}`}>
                    <SidebarIcon name={item.icon} />
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="border-t border-slate-800 p-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="text-[10px] uppercase tracking-[0.25em] text-slate-500">System Status</p>
              <div className="mt-3 flex items-center gap-2 text-sm">
                <span className={`h-2.5 w-2.5 rounded-full ${backendOnline ? "bg-emerald-400" : "bg-rose-400"}`} />
                <span className={backendOnline ? "text-emerald-300" : "text-rose-300"}>
                  {backendOnline ? "API Connected" : "API Offline"}
                </span>
              </div>
            </div>
          </div>
        </aside>

        <div className="flex-1">
          <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/80 backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
              <div>
                <p className="text-[10px] uppercase tracking-[0.28em] text-slate-500">AI Email Threat Detection</p>
                <h2 className="mt-1 text-xl font-semibold text-white">{currentPage.title}</h2>
                <p className="mt-1 text-sm text-slate-400">{currentPage.subtitle}</p>
              </div>

              <div className="flex items-center gap-3">
                <div className={`rounded-full border px-3 py-2 text-xs font-medium ${backendOnline ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-rose-500/30 bg-rose-500/10 text-rose-300"}`}>
                  {backendOnline ? "Connected" : "Offline"}
                </div>
                <button
                  onClick={() => setPage("email")}
                  className="rounded-full border border-sky-500/30 bg-sky-500/10 px-4 py-2 text-sm font-medium text-sky-200 transition hover:border-sky-400/60"
                >
                  Analyze Email
                </button>
              </div>
            </div>
          </header>

          <main className="p-4 sm:p-6 lg:p-8">{renderPage()}</main>
        </div>
      </div>

      {isLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm">
          <div className="rounded-3xl border border-slate-700 bg-slate-900 px-6 py-5 shadow-[0_0_30px_rgba(56,189,248,0.15)]">
            <div className="flex items-center gap-4">
              <div className="h-10 w-10 animate-spin rounded-full border-2 border-slate-700 border-t-sky-400" />
              <div>
                <div className="text-sm font-medium uppercase tracking-[0.22em] text-slate-300">Analyzing email</div>
                <div className="mt-1 text-xs text-slate-400">Running NLP analysis • Checking headers • Inspecting URLs • Correlating threat intelligence</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
