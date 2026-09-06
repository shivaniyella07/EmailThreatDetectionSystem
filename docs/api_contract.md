# API Contract (Phase 1)

All responses are JSON. Shared Python models live in `backend/app/schemas/`.

Change this document **before** changing request/response fields so frontend and backend stay aligned.

## Base URL (local)

- Backend: `http://127.0.0.1:8000`
- Interactive docs: `http://127.0.0.1:8000/docs`

The Vite app may call `/api/...` through a development proxy, or call the backend origin directly.

---

## GET `/`

Liveness helper for browsers hitting the API root.

**Response**

```json
{
  "service": "EmailThreatDetectionSystem",
  "message": "API is running. See /api/health and /docs."
}
```

---

## GET `/api/health`

Used by the dashboard to show **CONNECTED** or **OFFLINE**.

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

## Planned (not implemented in Phase 1)

A future `POST /api/analyze` will accept raw email text and return a forensic report object. Do not invent extra endpoints until the team agrees on the schema.

Draft report fields (subject to change):

- `score` (0–100)
- `classification` (`SAFE` | `SUSPICIOUS` | `HIGH_RISK`)
- `nlp`, `headers`, `urls`, `ips`, `geolocation`, `threat_intel`
- `explanations` (human-readable reasons for the score)
- `disclaimer` for approximate geolocation
