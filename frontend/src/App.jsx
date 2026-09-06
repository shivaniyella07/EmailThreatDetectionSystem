import { useEffect, useState } from "react";

const MODULES = [
  {
    title: "Email Analysis",
    description: "Parse message content and structure without executing attachments.",
  },
  {
    title: "Threat Detection",
    description: "Rule-based phishing and social-engineering signals.",
  },
  {
    title: "Header Forensics",
    description: "Inspect routing headers and SPF, DKIM, and DMARC when present.",
  },
  {
    title: "URL Intelligence",
    description: "Extract and review suspicious URLs as text only.",
  },
  {
    title: "IP Geolocation",
    description: "Approximate origin intelligence from Received-header IPs.",
  },
  {
    title: "Threat Intelligence",
    description: "Correlate indicators across modules for analyst context.",
  },
  {
    title: "Forensic Reports",
    description: "Downloadable, explainable findings for incident review.",
  },
];

const HEALTH_URL = "http://127.0.0.1:8000/api/health";

function App() {
  const [backendOnline, setBackendOnline] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const response = await fetch(HEALTH_URL);
        if (!response.ok) {
          throw new Error("Health check failed");
        }
        const data = await response.json();
        if (!cancelled) {
          setBackendOnline(data.status === "healthy");
        }
      } catch {
        if (!cancelled) {
          setBackendOnline(false);
        }
      }
    }

    checkHealth();
    const intervalId = setInterval(checkHealth, 8000);
    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const connectionLabel =
    backendOnline === null ? "CHECKING" : backendOnline ? "CONNECTED" : "OFFLINE";

  const connectionColor =
    backendOnline === null
      ? "text-amber-300 border-amber-400/40 bg-amber-400/10"
      : backendOnline
        ? "text-emerald-300 border-emerald-400/40 bg-emerald-400/10"
        : "text-rose-300 border-rose-400/40 bg-rose-400/10";

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100">
      <header className="border-b border-slate-800/80 bg-[#0b1220]/90">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-6 py-6 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="font-mono text-xs tracking-[0.2em] text-cyan-400">
              AICTE HACKATHON · DEFENSIVE CYBERSECURITY
            </p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight md:text-3xl">
              AI-Powered Email Threat Detection, GeoLocation and Forensic
              Intelligence Platform
            </h1>
          </div>
          <div
            className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 font-mono text-sm ${connectionColor}`}
          >
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                backendOnline
                  ? "bg-emerald-400"
                  : backendOnline === null
                    ? "bg-amber-400"
                    : "bg-rose-400"
              }`}
            />
            System {connectionLabel}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        <section className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <div className="rounded-2xl border border-slate-800 bg-[#0d1628] p-6">
            <h2 className="text-lg font-semibold text-white">Mission</h2>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
              Analyze suspicious emails for phishing, header forensics, URL
              intelligence, and approximate origin context. This platform is
              defensive only: attachments are never executed, and URLs are never
              opened automatically.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-[#0d1628] p-6">
            <h2 className="text-lg font-semibold text-white">Backend connection</h2>
            <p className="mt-3 font-mono text-sm text-slate-400">GET /api/health</p>
            <p className={`mt-4 font-mono text-2xl font-semibold ${connectionColor.split(" ")[0]}`}>
              {connectionLabel}
            </p>
            <p className="mt-2 text-sm text-slate-400">
              {backendOnline
                ? "FastAPI is reachable at 127.0.0.1:8000."
                : backendOnline === null
                  ? "Checking the health endpoint..."
                  : "Start the FastAPI server to connect the dashboard."}
            </p>
          </div>
        </section>

        <section className="mt-10">
          <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
            Analyst modules
          </h2>
          <p className="mt-2 text-sm text-slate-500">
            Placeholders for Phase 2+. Analysis is not implemented yet.
          </p>
          <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {MODULES.map((module) => (
              <article
                key={module.title}
                className="rounded-xl border border-slate-800 bg-[#0d1628] p-5"
              >
                <h3 className="font-medium text-cyan-100">{module.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  {module.description}
                </p>
                <p className="mt-4 font-mono text-xs text-slate-500">Coming in a later phase</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
