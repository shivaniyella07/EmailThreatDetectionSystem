# System Architecture

## Purpose

**EmailThreatDetectionSystem** is a defensive cybersecurity platform:

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**

It helps an analyst:

1. Connect Gmail with Google OAuth 2.0 (planned; not implemented yet)
2. Fetch recent messages or pick one email
3. Run a multi-engine analysis pipeline
4. Receive an explainable threat score from 0–100
5. See a classification of `SAFE`, `SUSPICIOUS`, or `HIGH_RISK`
6. Review forensic evidence in the dashboard and in a downloadable report

The product analyzes email **text and metadata only**. It never executes attachments and never automatically opens or visits URLs.

**Current code (working foundation):** FastAPI `GET /api/health` and a React dashboard that shows backend **CONNECTED** / **OFFLINE**. Gmail OAuth, fetch, and analysis engines are **planned** and must not replace that health endpoint.

## Primary user workflow (Gmail)

```
User
  -> Connect Gmail (Google OAuth 2.0)
  -> Fetch recent emails or select one email
  -> Send selected email to the analysis pipeline
  -> Parallel security engines analyze the message
  -> Risk Engine produces score 0-100
  -> Classification: SAFE / SUSPICIOUS / HIGH_RISK
  -> Dashboard shows explainable forensic evidence
```

Gmail access uses **OAuth 2.0 only**. The platform never collects or stores Gmail passwords. OAuth client secrets stay in local `.env` files and are never committed to GitHub.

## Manual analysis mode (hackathon backup)

If OAuth is unavailable in a demo, the analyst pastes a raw email (`.eml` / headers + body) into the UI. The same parser and analysis pipeline run. This is a backup path, not a second product.

```
Manual paste of raw email
        |
        v
   Email Parser  ---- same pipeline as Gmail ---->  Results UI
```

## High-level system layout

```
+------------------+          JSON / HTTP           +------------------+
| React + Vite     |  <-------------------------->  | FastAPI (Py 3.12)|
| Dashboard        |                                | API + orchestrator|
+------------------+                                +--------+---------+
                                                               |
                    +------------------------------------------+
                    |  core/        settings, OAuth config later
                    |  api/         health (live) + future routes
                    |  schemas/     shared JSON contracts
                    |  services/    independent analysis modules
                    |  database/    SQLite later; unused for now
                    +------------------------------------------+
                               |
                               v
                    Google Gmail API (planned, OAuth 2.0)
```

## Analysis pipeline

```
Gmail API  or  Manual raw email
              |
              v
        Email Parser
         (Member 1)
              |
              +------------------+------------------+------------------+------------------+
              |                  |                  |                  |                  |
              v                  v                  v                  v                  v
       NLP Analyzer      Header Forensics     URL Analyzer     IP + Geolocation    Threat Intel
        (Member 2)         (Member 3)          (Member 4)         (Member 4)        (Member 5)
              |                  |                  |                  |                  |
              +------------------+------------------+------------------+------------------+
                                              |
                                              v
                                        Risk Engine
                                         (Member 5)
                                              |
                                              v
                                   Final score 0-100
                          SAFE / SUSPICIOUS / HIGH_RISK
                                              |
                                              v
                         Frontend results + forensic report (Member 6)
```

Modules run **independently** after parsing. They communicate only through documented JSON (see `docs/api_contract.md`). Sibling services must not import each other’s internals. That keeps Git merge conflicts low for a 6-person team.

### 1. Email Parser (Member 1)

Normalizes Gmail payload or pasted raw email into a shared structure (headers, body text, extracted fields). Never executes attachments.

### 2. NLP Analyzer (Member 2)

Rule-based first (architecture ready for later spaCy / Hugging Face):

- phishing language
- urgency detection
- credential-theft indicators
- social engineering
- impersonation language

### 3. Header Forensics Analyzer (Member 3)

- From, Return-Path, Reply-To
- Received headers
- Message-ID
- SPF, DKIM, DMARC when present
- spoofing / identity mismatch indicators

### 4. URL Analyzer (Member 4)

- extract URLs
- suspicious / lookalike domains
- IP-based URLs
- suspicious keywords in URL strings
- **never automatically visit** URLs; analyze as text only

### 5. IP and Geolocation Analyzer (Member 4)

- public IPs from Received headers
- earliest reliable public sending node
- approximate country, city, ISP/ASN, lat/long when available
- results are **approximate network intelligence**, not proof of attacker identity

### 6. Threat Intelligence (Member 5)

- correlate domains, IPs, and URLs
- known suspicious indicators
- local / static intel for the hackathon MVP (no paid APIs required)

### 7. Risk Engine (Member 5)

Combines module scores into one explainable 0–100 result and `top_reasons` for the UI.

| Module | Weight |
| ------ | ------ |
| NLP analysis | 25% |
| Header analysis | 25% |
| URL analysis | 20% |
| Threat intelligence | 20% |
| IP / geolocation | 10% |

Score bands (same for modules and overall):

| Score | `risk_level` / `classification` |
| ----- | ------------------------------- |
| 0–30 | `SAFE` |
| 31–60 | `SUSPICIOUS` |
| 61–100 | `HIGH_RISK` |

### 8. Frontend (Member 6)

Analyst dashboard: Gmail connect (later), mailbox / email select, manual paste, health indicator, score, classification, module evidence, map/charts later, forensic report download.

## Integration workflow (how the team plugs in)

1. Member 1 owns orchestration: parse → call each analyzer → pass results to the risk engine → return the **final analysis JSON**.
2. Members 2–5 implement only their service files and matching Pydantic schemas.
3. Each analyzer returns the **common module envelope** in `docs/api_contract.md`.
4. Schema changes are written into `docs/api_contract.md` in the same pull request.
5. Member 6 consumes only the final analysis JSON (plus live `GET /api/health`).
6. Do not change `GET /api/health`. It is the working connectivity contract.

## Data stores

| Stage | Store |
| ----- | ----- |
| Current foundation | None required |
| Hackathon MVP | SQLite behind a thin database interface |
| Later | PostgreSQL using the same interface |

Do not store Gmail passwords. If tokens are stored later, keep them server-side and secret; never commit them.

## Security principles

- Gmail access: **Google OAuth 2.0 only**
- Never collect or store Gmail passwords
- Never execute attachments
- Never automatically open or visit suspicious URLs
- IP geolocation is **approximate network intelligence**
- Analysis is **risk assessment**, not proof of attacker identity
- Secrets and OAuth credentials: `.env` only; never GitHub
- Do not expose API keys or OAuth secrets to the frontend

## Related docs

- [api_contract.md](api_contract.md) — implemented and planned JSON contracts
- [team_modules.md](team_modules.md) — file ownership per member
