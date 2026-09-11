# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

Defensive cybersecurity platform for a 6-member AICTE hackathon team.

**Intended workflow:** connect Gmail with Google OAuth 2.0 → select an email → run parallel analysis engines (NLP, headers, URLs, IP/geolocation, threat intel) → explainable score 0–100 (`SAFE` / `SUSPICIOUS` / `HIGH_RISK`). A **manual paste** path is the hackathon backup if OAuth is not available.

**What works today:** FastAPI `GET /api/health` and a React dashboard that shows **CONNECTED** or **OFFLINE**. A Gmail OAuth-ready API foundation with credential-free mock mailbox support is available; analysis engines continue to be integrated incrementally (see docs). Do not commit OAuth secrets.

## Organization and domain

- **Organization:** All India Council for Technical Education (AICTE)
- **Domain:** Software – Blockchain & Cybersecurity
- **Repository:** EmailThreatDetectionSystem

## Security rules

- Gmail access must use **Google OAuth 2.0**. Never collect or store Gmail passwords.
- Never execute email attachments.
- Never automatically open or visit suspicious URLs; analyze URL strings only.
- Do not commit secrets or OAuth credentials. Copy `backend/.env.example` to `backend/.env`.
- IP geolocation is **approximate network intelligence**. Analysis does not prove attacker identity.

## Repository layout

```
backend/     FastAPI application (Python 3.12)
frontend/    React + Vite dashboard
docs/        Architecture, API contract, team modules
samples/     Sanitized sample emails (later)
```

## Prerequisites (Windows)

- Python 3.12 (`py -3.12`)
- Node.js 18+ and npm

## Run the backend

```powershell
cd C:\Users\shiva\EmailThreatDetectionSystem\backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Run the frontend

In a **second** PowerShell window:

```powershell
cd C:\Users\shiva\EmailThreatDetectionSystem\frontend
npm install
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). The homepage should show **CONNECTED** when the backend is running.

This frontend uses Vite 5 so it runs on Node.js 18. Do not upgrade to the latest Vite (6+) until the team is on Node 20+.

## Team

See [docs/team_modules.md](docs/team_modules.md) for the six member assignments (backend/Gmail orchestration, NLP, headers, URL/IP/geo, risk engine, frontend). Use Git branches per feature to avoid merge conflicts.

## Documentation

- [docs/architecture.md](docs/architecture.md) — Gmail + manual workflow, pipeline, scoring weights
- [docs/api_contract.md](docs/api_contract.md) — live health API and planned analysis JSON
- [docs/team_modules.md](docs/team_modules.md) — ownership and integration rules
