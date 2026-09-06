# System Architecture (Phase 1)

## Purpose

This platform is a **defensive** cybersecurity tool. It analyzes suspicious emails as text and metadata. It never executes attachments and never automatically opens or visits URLs.

## High-level layout

```
Browser (React + Vite)
        |
        |  JSON over HTTP
        v
FastAPI backend (Python 3.12)
        |
        +-- api/          HTTP routes
        +-- schemas/      Pydantic JSON contracts
        +-- services/     Independent analysis modules
        +-- database/     Persistence (SQLite later; unused in Phase 1)
        +-- core/         Settings and shared config
```

## Design for six developers

Each analysis module lives in its own file under `backend/app/services/`. Modules must not import implementation details from sibling modules. They exchange data through **Pydantic schemas** (Python) and **JSON** (API / frontend).

This reduces merge conflicts: members work on different files and agree on field names in `docs/api_contract.md` before changing shared schemas.

## Request flow (future analysis endpoint)

Phase 1 only implements `GET /api/health`. Later phases will follow this pipeline:

1. **Email parser** — parse raw email text; never run attachments.
2. **NLP analyzer** — social engineering signals (rule-based first).
3. **Header analyzer** — Received chain, SPF/DKIM/DMARC when present, spoofing clues.
4. **URL analyzer** — extract URLs; inspect strings only.
5. **IP analyzer** — originating IPs from Received headers.
6. **Geolocation** — approximate origin intelligence (not proof of identity).
7. **Threat intelligence** — correlate indicators.
8. **Risk engine** — explainable score 0–100 and class SAFE / SUSPICIOUS / HIGH RISK.
9. **API** — return a single JSON report to the dashboard.

## Data stores

| Phase | Store |
| ----- | ----- |
| Phase 1 | None |
| MVP | SQLite behind a thin database interface |
| Later | PostgreSQL using the same interface |

## Frontend

The React app is a cybersecurity analyst dashboard. Phase 1 shows project context, module placeholders, and live backend connectivity via `/api/health`.

Maps (Leaflet + OpenStreetMap) and charts (Recharts) will be added when IP geolocation and scoring exist. Do not treat geolocation as legal attribution.

## Security rules

- Secrets stay in `.env` (see `backend/.env.example`). Never commit `.env`.
- Do not expose API keys to the frontend.
- Label geolocation and attribution as **approximate intelligence**.
