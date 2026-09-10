import React from "react";

const overviewStats = [
  { label: "Threat Score", value: "92", delta: "+12.4%", tone: "navy" },
  { label: "Risk Level", value: "Critical", delta: "Escalated", tone: "red" },
  { label: "Emails Analyzed", value: "18.4K", delta: "+8.1%", tone: "teal" },
  { label: "Threats Detected", value: "247", delta: "-3.2%", tone: "slate" },
];

const recentInvestigations = [
  { caseId: "SEC-2091", sender: "security-update@secure-portal-verify.com", risk: "Critical", status: "Escalated" },
  { caseId: "SEC-2087", sender: "ops@northwind-hr.co", risk: "High", status: "In review" },
  { caseId: "SEC-2074", sender: "billing@advisory-partner.net", risk: "Medium", status: "Contained" },
  { caseId: "SEC-2068", sender: "alert@internal-support.io", risk: "Low", status: "Closed" },
];

const alertList = [
  { title: "Credential harvesting attempt", severity: "Critical", time: "2 mins ago" },
  { title: "Brand spoofing campaign detected", severity: "High", time: "18 mins ago" },
  { title: "Suspicious redirection observed", severity: "Medium", time: "42 mins ago" },
];

const threatBreakdown = [
  { label: "Credential Theft", value: 36, color: "bg-slate-900" },
  { label: "BEC", value: 24, color: "bg-teal-500" },
  { label: "Malware Delivery", value: 18, color: "bg-blue-600" },
  { label: "Brand Spoofing", value: 12, color: "bg-red-500" },
];

function Dashboard({ onNavigate, onViewReport, onDownloadReport }) {
  return (
    <div className="space-y-6">
      <section className="overflow-hidden rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.04)]">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Welcome back</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">Security operations overview</h1>
          </div>

          <button
            onClick={() => onNavigate("email")}
            className="inline-flex items-center justify-center rounded-full bg-slate-900 px-5 py-3 text-sm font-medium text-white transition hover:bg-slate-800"
          >
            Analyze New Email
          </button>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {overviewStats.map((stat) => (
            <div key={stat.label} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">{stat.label}</span>
                <span
                  className={`rounded-full px-2 py-1 text-[10px] font-medium ${
                    stat.tone === "red"
                      ? "bg-red-50 text-red-700"
                      : stat.tone === "teal"
                        ? "bg-teal-50 text-teal-700"
                        : stat.tone === "navy"
                          ? "bg-slate-200 text-slate-700"
                          : "bg-slate-200 text-slate-700"
                  }`}
                >
                  {stat.delta}
                </span>
              </div>
              <div className="mt-5 text-3xl font-semibold text-slate-900">{stat.value}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
        <div className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.04)]">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Performance</p>
              <h2 className="mt-2 text-xl font-semibold text-slate-900">Threat Activity</h2>
            </div>
            <button onClick={onViewReport} className="text-sm font-medium text-slate-600">View report</button>
          </div>

          <div className="flex h-52 items-end gap-3">
            {[42, 58, 48, 72, 60, 92, 76, 86, 68, 82, 90, 74].map((height, idx) => (
              <div key={idx} className="flex-1">
                <div
                  className={`w-full rounded-t-xl ${idx % 2 === 0 ? "bg-slate-900" : "bg-teal-500"}`}
                  style={{ height: `${height}%` }}
                />
              </div>
            ))}
          </div>

          <div className="mt-4 flex justify-between text-xs text-slate-500">
            <span>Jan</span>
            <span>Feb</span>
            <span>Mar</span>
            <span>Apr</span>
            <span>May</span>
            <span>Jun</span>
            <span>Jul</span>
            <span>Aug</span>
            <span>Sep</span>
            <span>Oct</span>
            <span>Nov</span>
            <span>Dec</span>
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.04)]">
          <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Threat mix</p>
          <h2 className="mt-2 text-xl font-semibold text-slate-900">Attack Categories</h2>

          <div className="mt-5 space-y-4">
            {threatBreakdown.map((item) => (
              <div key={item.label}>
                <div className="mb-2 flex items-center justify-between text-sm text-slate-600">
                  <span>{item.label}</span>
                  <span className="font-medium text-slate-900">{item.value}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                  <div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.3fr_0.7fr]">
        <div className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.04)]">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Investigation queue</p>
              <h2 className="mt-2 text-xl font-semibold text-slate-900">Recent Investigations</h2>
            </div>
            <button onClick={onDownloadReport} className="text-sm font-medium text-slate-600">Export</button>
          </div>

          <div className="overflow-hidden rounded-2xl border border-slate-200">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="px-4 py-3 font-medium">Case ID</th>
                  <th className="px-4 py-3 font-medium">Sender</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 bg-white">
                {recentInvestigations.map((investigation) => (
                  <tr key={investigation.caseId} className="hover:bg-slate-50">
                    <td className="px-4 py-3 font-medium text-slate-900">{investigation.caseId}</td>
                    <td className="px-4 py-3 text-slate-600">{investigation.sender}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-1 text-[10px] font-medium ${
                          investigation.risk === "Critical"
                            ? "bg-red-50 text-red-700"
                            : investigation.risk === "High"
                              ? "bg-amber-50 text-amber-700"
                              : investigation.risk === "Medium"
                                ? "bg-slate-200 text-slate-700"
                                : "bg-emerald-50 text-emerald-700"
                        }`}
                      >
                        {investigation.risk}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-600">{investigation.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-[28px] border border-slate-200 bg-white p-6 shadow-[0_12px_40px_rgba(15,23,42,0.04)]">
          <p className="text-[10px] uppercase tracking-[0.24em] text-slate-500">Live alerts</p>
          <h2 className="mt-2 text-xl font-semibold text-slate-900">Active Alerts</h2>

          <div className="mt-5 space-y-3">
            {alertList.map((alert) => (
              <div key={alert.title} className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-medium text-slate-900">{alert.title}</p>
                    <p className="mt-1 text-xs text-slate-500">{alert.time}</p>
                  </div>
                  <span
                    className={`rounded-full px-2 py-1 text-[10px] font-medium ${
                      alert.severity === "Critical"
                        ? "bg-red-50 text-red-700"
                        : alert.severity === "High"
                          ? "bg-amber-50 text-amber-700"
                          : "bg-slate-200 text-slate-700"
                    }`}
                  >
                    {alert.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

export default Dashboard;
