# Team Modules

Six members work on **separate files** and share data through `backend/app/schemas/` and `docs/api_contract.md`. Prefer feature branches named `memberN/short-topic`.

**Integration rule:** Member 1 orchestrates. Members 2–5 each return the common module JSON. Member 5’s risk engine produces overall score and `top_reasons`. Member 6 renders the final analysis JSON. Do not change the working `GET /api/health` contract.

```
Member 6 (UI)
     |
     |  health + later analyze JSON
     v
Member 1 (API, Gmail OAuth, parser, orchestration)
     |
     +--> Member 2  nlp_analyzer.py
     +--> Member 3  header_analyzer.py
     +--> Member 4  url_analyzer.py, ip_analyzer.py, geolocation.py
     +--> Member 5  threat_intelligence.py --> risk_engine.py
```

---

## Member 1 — Backend + Gmail Integration + API Orchestration

**Owns**

- `backend/app/main.py`
- `backend/app/api/`
- `backend/app/core/`
- `backend/app/database/` (SQLite later)
- `backend/app/services/email_parser.py`
- `backend/requirements.txt`
- Gmail OAuth routes, mock development mode, and Gmail fetch helpers

**Responsibilities**

- Keep FastAPI, CORS, and **`GET /api/health`** working unchanged
- Google OAuth 2.0 for Gmail (never collect Gmail passwords)
- Fetch recent mail / selected message after OAuth
- Manual analysis path: accept pasted raw email for demos
- Email parser: normalize Gmail or raw input; never execute attachments
- Call analyzers in parallel (conceptually), then the risk engine
- Return the **final analysis response** in `docs/api_contract.md`
- Environment and secrets (`.env`); never commit OAuth credentials
- Thin database interface (SQLite now-plan, PostgreSQL later)

---

## Member 2 — AI/NLP Detection Engine

**Owns**

- `backend/app/services/nlp_analyzer.py`
- NLP-related schemas

**Module id:** `nlp`  
**Risk weight:** 25%

**Responsibilities**

- Phishing language, urgency, credential-theft, social engineering, impersonation
- Rule-based first; keep hooks for later spaCy or Hugging Face
- Do not train a heavy ML model in early phases
- Return the common module envelope (`risk_score`, `risk_level`, `indicators`, `details`, `errors`)

---

## Member 3 — Email Header Forensics

**Owns**

- `backend/app/services/header_analyzer.py`
- Header-related schemas

**Module id:** `header`  
**Risk weight:** 25%

**Responsibilities**

- From, Return-Path, Reply-To, Received, Message-ID
- SPF, DKIM, DMARC **when those headers exist**
- Spoofing and identity-mismatch indicators
- Return the common module envelope

---

## Member 4 — URL + IP + Geolocation Analysis

**Owns**

- `backend/app/services/url_analyzer.py`
- `backend/app/services/ip_analyzer.py`
- `backend/app/services/geolocation.py`
- Related schemas

**Module ids:** `url` (20% weight) and `geolocation` (10% weight, includes IP extraction)

**Responsibilities**

- Extract URLs; suspicious / lookalike / IP-based URLs; keyword checks
- **Never automatically visit** URLs; analyze strings only
- Extract public IPs from Received headers; pick earliest reliable public sending node
- Approximate geolocation: country, city, ISP/ASN, lat/long when available
- Label results as **approximate network intelligence**, not attacker identity
- Return two module envelopes: `url` and `geolocation`

---

## Member 5 — Threat Intelligence + Risk Scoring Engine

**Owns**

- `backend/app/services/threat_intelligence.py`
- `backend/app/services/risk_engine.py`
- Related schemas

**Module id:** `threat_intelligence` (20% weight) plus overall score

**Responsibilities**

- Correlate domains, IPs, and URLs against local MVP intel
- Consume other modules’ envelopes **only** as JSON/schema input
- Weighted score:

  - NLP 25% + Header 25% + URL 20% + Threat intel 20% + IP/geolocation 10%
- Map 0–30 / 31–60 / 61–100 → `SAFE` / `SUSPICIOUS` / `HIGH_RISK`
- Fill `overall` and `top_reasons` for the final API object
- Keep scoring explainable

---

## Member 6 — Frontend UI + Dashboard + Results Visualization

**Owns**

- `frontend/`
- Future report download UI

**Responsibilities**

- Keep the current homepage and health **CONNECTED** / **OFFLINE** behavior working
- Later: Gmail connect UX, mailbox/email select, manual paste mode
- Results: score, classification, module evidence, `top_reasons`, disclaimer
- Later: Recharts, Leaflet + OpenStreetMap, forensic report download
- Consume only documented JSON (`GET /api/health` now; final analysis object later)
- Never embed OAuth client secrets in frontend source

---

## Conflict avoidance

- Do not edit another member’s owned files without agreement
- Schema or endpoint changes require an update to `docs/api_contract.md` in the same pull request
- Keep service functions: documented input → common module envelope
- Do not break, delete, or rename the existing health endpoint
- Keep OAuth credentials server-side and retain mock mode for credential-free demonstrations

## Security (all members)

- OAuth 2.0 for Gmail; no Gmail passwords
- No automatic URL visits
- Geolocation is approximate; analysis does not prove attacker identity
- Secrets stay out of GitHub
