# Team Modules

Six members work on **separate files** and share data through `backend/app/schemas/` and `docs/api_contract.md`. Prefer feature branches named `memberN/short-topic`.

## Member 1 — Backend Core and API Integration

**Owns**

- `backend/app/main.py`
- `backend/app/api/`
- `backend/app/core/`
- `backend/app/database/` (SQLite later)
- `backend/app/services/email_parser.py`
- `backend/requirements.txt`

**Responsibilities**

- FastAPI app, CORS, routing
- Environment configuration
- Shared email parse step (text only; never execute attachments)
- Database interface that can move from SQLite to PostgreSQL later
- Wiring modules together **after** each module’s JSON contract is stable

## Member 2 — AI/NLP Phishing and Social Engineering

**Owns**

- `backend/app/services/nlp_analyzer.py`
- Related schemas (e.g. NLP findings)

**Responsibilities**

- Rule-based phishing / urgency / impersonation signals in Phase 2
- Keep hooks for later spaCy or Hugging Face models
- Do not train a heavy ML model in early phases

## Member 3 — Email Header and Protocol Forensics

**Owns**

- `backend/app/services/header_analyzer.py`
- Related schemas

**Responsibilities**

- Received-header chain and routing clues
- SPF, DKIM, DMARC **when those headers exist**
- Sender spoofing and identity mismatch signals

## Member 4 — URL Analysis, IP Extraction, Geolocation

**Owns**

- `backend/app/services/url_analyzer.py`
- `backend/app/services/ip_analyzer.py`
- `backend/app/services/geolocation.py`
- Related schemas

**Responsibilities**

- Extract URLs and analyze them **as text only** (never visit them automatically)
- Extract originating IPs from Received headers
- Approximate IP geolocation; always label as intelligence, not identity proof

## Member 5 — Threat Intelligence and Risk Scoring

**Owns**

- `backend/app/services/threat_intelligence.py`
- `backend/app/services/risk_engine.py`
- Related schemas

**Responsibilities**

- Correlate indicators from other modules
- Explainable score 0–100
- Classification: SAFE, SUSPICIOUS, HIGH RISK
- Human-readable reasons for the score

## Member 6 — Frontend Dashboard, Visualization, Reports

**Owns**

- `frontend/`
- Future report download UI

**Responsibilities**

- Analyst dashboard (React + Vite + Tailwind)
- Backend health / connection status
- Later: charts (Recharts), maps (Leaflet + OpenStreetMap), forensic report download
- Consume only documented JSON contracts

## Conflict avoidance

- Do not edit another member’s owned files without agreement.
- Schema changes require an update to `docs/api_contract.md` in the same pull request.
- Keep service functions pure: input dict/schema → output dict/schema.
