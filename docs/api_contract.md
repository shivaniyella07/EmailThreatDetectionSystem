# API Contract

All responses are JSON. Shared Python models live in `backend/app/schemas/`.

Change this document **before** changing request/response fields so frontend and backend stay aligned.

## Base URL (local)

- Backend: `http://127.0.0.1:8000`
- Interactive docs: `http://127.0.0.1:8000/docs`

The Vite app may call `/api/...` through a development proxy, or call the backend origin directly.

---

## Implemented now (do not change)

### GET `/`

Liveness helper for browsers hitting the API root.

**Response**

```json
{
  "service": "EmailThreatDetectionSystem",
  "message": "API is running. See /api/health and /docs."
}
```

### GET `/api/health`

Used by the dashboard to show **CONNECTED** or **OFFLINE**. **Do not rename, remove, or change this response.**

**Response `200`**

```json
{
  "status": "healthy",
  "service": "EmailThreatDetectionSystem"
}
```

| Field | Type | Meaning |
| ----- | ---- | ------- |
| `status` | string | `"healthy"` when the API process is up |
| `service` | string | Constant service name |

The frontend treats any successful parse of this body as **CONNECTED**. Network errors, timeouts, or non-OK HTTP status are **OFFLINE**.

---

## Gmail endpoints (implemented; Member 1)

Gmail access is prepared for Google OAuth 2.0 only. Gmail passwords are never accepted. The default development configuration uses a deterministic mock mailbox, so no Google credentials are needed to run the application.

### GET `/api/gmail/auth`

Starts the connection flow by returning an authorization URL. In mock mode the URL points to the local callback; with configured OAuth credentials it points to Google's read-only authorization flow.

```json
{
  "mode": "mock",
  "authorization_url": "http://127.0.0.1:8000/api/gmail/callback?mode=mock",
  "message": "Mock Gmail authorization is ready; no Google credentials are required."
}
```

### GET `/api/gmail/callback`

Handles the OAuth callback (`code` or `error`). Mock mode marks the in-memory demo mailbox connected. Real token exchange remains intentionally disabled until secure server-side token storage is designed; codes and tokens are never returned in JSON.

### GET `/api/gmail/emails`

Lists recent email metadata. In development it returns sanitized mock messages.

```json
{
  "mode": "mock",
  "emails": [
    {"id": "demo-team-update", "from": "Project Team <team@example.test>", "subject": "Weekly project update", "date": "Sun, 07 Sep 2026 09:00:00 +0000", "snippet": "Hi team..."}
  ]
}
```

### POST `/api/gmail/analyze/{email_id}`

Fetches the selected Gmail/mock message, normalizes it through the shared email parser, and calls the same analysis orchestration used by the manual route. The response follows the final analysis response below.
### Manual analysis (hackathon backup)

Conceptual: `POST` raw email text/headers. Same analysis pipeline and **same final response shape** as Gmail-selected mail.

### Analysis

Conceptual: `POST /api/analyze` (name TBD) accepts either:

- a Gmail message id (authenticated session), or
- raw email content (manual mode)

and returns the **final analysis object** below.

---

## Common module response (all analyzers)

Every analysis module returns this envelope. `module` is one of: `nlp`, `header`, `url`, `geolocation`, `threat_intelligence`.

```json
{
  "module": "module_name",
  "risk_score": 0,
  "risk_level": "SAFE",
  "indicators": [],
  "details": {},
  "errors": []
}
```

| Field | Type | Meaning |
| ----- | ---- | ------- |
| `module` | string | Module id (`nlp`, `header`, `url`, `geolocation`, `threat_intelligence`) |
| `risk_score` | number | Integer 0–100 |
| `risk_level` | string | `SAFE` \| `SUSPICIOUS` \| `HIGH_RISK` from the score bands |
| `indicators` | array | Short, human-readable findings (strings or small objects) |
| `details` | object | Module-specific forensic fields |
| `errors` | array | Non-fatal issues (missing headers, lookup skipped, etc.) |

Score bands for **module** `risk_level` and **overall** `classification`:

| Score | Level |
| ----- | ----- |
| 0–30 | `SAFE` |
| 31–60 | `SUSPICIOUS` |
| 61–100 | `HIGH_RISK` |

If a module cannot run, it still returns the envelope: `risk_score` 0 or omitted-as-0, `errors` populated, and the risk engine decides how to weight missing input.

### Suggested `details` (not required until implementation)

**nlp**

- phishing / urgency / credential-theft / social-engineering / impersonation flags

**header**

- From, Return-Path, Reply-To, Message-ID
- Received chain summary
- SPF / DKIM / DMARC when present
- spoofing indicators

**url**

- extracted URLs
- suspicious, lookalike, IP-based, keyword matches
- never include a “visited URL” or live-fetch result

**geolocation**

- public IPs, chosen sending node
- country, city, ISP/ASN, latitude, longitude when available
- always treat as approximate intelligence

**threat_intelligence**

- matched domains, IPs, URLs
- local intel hits for MVP

---

## Final analysis response (orchestration → frontend)

Member 1 assembles this object after the Risk Engine runs. Member 6 should design the results UI around this shape.

```json
{
  "analysis_id": "unique_analysis_id",

  "email": {
    "id": "email_id",
    "from": "sender@example.com",
    "subject": "Email subject"
  },

  "overall": {
    "risk_score": 85,
    "classification": "HIGH_RISK",
    "confidence": "HIGH"
  },

  "analyses": {
    "nlp": {},
    "header": {},
    "url": {},
    "geolocation": {},
    "threat_intelligence": {}
  },

  "top_reasons": [],

  "disclaimer": "Analysis provides security intelligence and risk assessment; it does not prove attacker identity."
}
```

| Field | Meaning |
| ----- | ------- |
| `analysis_id` | Unique id for this run |
| `email` | Identity of the analyzed message (Gmail id or manual placeholder) |
| `overall.risk_score` | Weighted 0–100 |
| `overall.classification` | `SAFE` \| `SUSPICIOUS` \| `HIGH_RISK` |
| `overall.confidence` | e.g. `LOW` \| `MEDIUM` \| `HIGH` (how complete the inputs were) |
| `analyses.*` | Each value is a **common module response** |
| `top_reasons` | Short strings explaining the score (from the risk engine) |
| `disclaimer` | Required on every report; geolocation is not attacker identity |

`analyses.geolocation` covers IP extraction plus geolocation (Member 4). There is no separate top-level `ip` object in the final payload.

---

## Risk engine formula (contract)

Weights (must sum to 100%):

| Input | Weight | Source module id |
| ----- | ------ | ---------------- |
| NLP | 25% | `nlp` |
| Header | 25% | `header` |
| URL | 20% | `url` |
| Threat intelligence | 20% | `threat_intelligence` |
| IP / geolocation | 10% | `geolocation` |

```
overall.risk_score =
    0.25 * nlp.risk_score
  + 0.25 * header.risk_score
  + 0.20 * url.risk_score
  + 0.20 * threat_intelligence.risk_score
  + 0.10 * geolocation.risk_score
```

Round to an integer 0–100, then apply the same 0–30 / 31–60 / 61–100 bands to `overall.classification`.

`top_reasons` should be explainable (which indicators drove the score), not a black box.

---

## Security notes for API implementers

- Do not put OAuth secrets or API keys in responses
- Do not return Gmail refresh tokens to the browser unless a later, reviewed design requires a narrow session cookie
- Never include fetched HTML from live URL visits (URL analysis is text-only)
- Always include the identity-disclaimer string on analysis results
