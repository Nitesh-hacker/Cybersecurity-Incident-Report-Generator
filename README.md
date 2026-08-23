# Cybersecurity Incident Report Generator

Generate standardized, tamper-evident cybersecurity incident reports (Markdown + PDF) from investigation data, through a web form or a JSON API.

This project takes the messy output of a SOC/IR investigation — timeline notes, IOCs, containment steps — and turns it into a consistent, professional report every time, so analysts spend less time formatting and more time investigating.

## Features

- **Web form UI** for entering incident data by hand
- **JSON API** (`/api/generate`, `/api/generate_pdf`) for pulling data from a SIEM, ticketing system, or IR playbook automation
- **Standardized structure** — every report has the same sections: incident metadata, scope, description, timeline, IOCs, impact, containment/eradication/recovery, root cause, recommendations
- **Two output formats**: Markdown (for version control / email / wikis) and PDF (for distribution)
- **Integrity hash** (SHA-256) stamped on every report so recipients can verify it hasn't been altered after generation

## Project Structure

```
incident-report-generator/
├── app.py                  # Flask web app (routes, security headers, rate limiting)
├── models.py                # IncidentReport data model + field constraints
├── security.py               # Input validation, sanitization, hashing, audit logging, rate limiter
├── report_generator.py       # Builds reports, renders Markdown + PDF
├── templates/
│   └── index.html            # Web form UI
├── tests/
│   └── test_report_generator.py   # 31 automated tests
├── reports/
│   └── sample_report.pdf / .md    # Example generated report
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Optional but recommended: set a persistent secret key
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

python3 app.py
```

Then open **http://127.0.0.1:5000**.

By default the app runs with `debug=False` and binds only to localhost. Set `FLASK_DEBUG=1` only in local development — never in anything resembling production, since Flask's debugger allows arbitrary code execution if exposed.

## Using the API directly

```bash
curl -X POST http://127.0.0.1:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
        "incident_id": "INC-2026-0142",
        "title": "Phishing-driven credential compromise",
        "severity": "High",
        "status": "Contained",
        "classification": "TLP:AMBER",
        "reported_by": "SOC Analyst",
        "report_author": "IR Lead",
        "date_reported": "2026-08-18",
        "date_occurred": "2026-08-17",
        "affected_systems": "corp-vpn-01",
        "description": "Employee credentials phished and used to access VPN.",
        "timeline": [{"timestamp": "2026-08-17 09:38", "description": "Anomalous VPN login detected"}],
        "indicators_of_compromise": ["185.220.101.44"],
        "impact_assessment": "One account compromised, no lateral movement.",
        "containment_actions": "Account disabled, session terminated.",
        "recommendations": "Deploy phishing-resistant MFA."
      }'
```

`/api/generate` returns JSON with the rendered Markdown and integrity hash. `/api/generate_pdf` returns the PDF file directly.

A full example is in `reports/sample_report.pdf`.

## Security Features Implemented

| Feature | Where | Why |
|---|---|---|
| **Allow-list field validation** | `security.py: validate_incident_data()` | Severity, status, and classification are checked against fixed enums rather than accepted as free text — malformed or malicious values are rejected outright, not coerced. |
| **Input sanitization / HTML-escaping** | `security.py: sanitize_text()` | Every free-text field (title, description, timeline entries, IOCs, etc.) is HTML-escaped and stripped of control characters before it's stored or rendered, preventing stored XSS even though Flask/Jinja2 already autoescapes on output. |
| **Restricted incident ID charset** | `security.py` | `incident_id` must match `^[A-Za-z0-9\-_]+$`, closing off injection attempts via a field that's used in filenames and URLs. |
| **Field length limits** | `models.py: FIELD_LIMITS`, `security.py` | Every field has a max length, capping payload size and guarding against pathological input used for resource-exhaustion attacks. |
| **Request body size cap** | `app.py: MAX_CONTENT_LENGTH` | Flask rejects any request body over 512 KB before it's even parsed. |
| **Rate limiting** | `security.py: RateLimiter`, wired into `app.py` | Sliding-window limiter (default 20 requests/min per client) on report-generation endpoints, mitigating abuse/DoS. |
| **Security response headers** | `app.py: set_security_headers()` | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` set on every response. |
| **No hardcoded secrets** | `app.py` | `SECRET_KEY` is read from the environment; if unset, a random per-process key is generated rather than shipping a default. |
| **Report integrity hashing** | `security.py: compute_integrity_hash()` / `verify_integrity_hash()` | Every generated report is stamped with a SHA-256 hash of its own content, computed with a constant-time comparison function for verification, so tampering after generation is detectable. |
| **Fail-closed error handling** | `app.py` error handlers | Internal errors return a generic message to the client; details go only to the server-side audit log, never to the HTTP response. |
| **Audit logging** | `security.py: audit_log()` | Report generation, validation failures, and rate-limit hits are logged to `audit.log`, deliberately excluding raw free-text content from the log line. |
| **Debug mode disabled by default** | `app.py` | Flask's interactive debugger (which permits arbitrary code execution) is off unless explicitly enabled via `FLASK_DEBUG=1`, and is never intended for production use. |
| **No unsafe deserialization / eval** | throughout | Input is parsed as strict JSON via Flask's built-in parser only; nowhere in the codebase is `eval`, `exec`, `pickle`, or `yaml.load` used on user input. |

## Testing

```bash
pip install pytest
pytest tests/ -v
```

Current result: **31/31 tests passing**, covering:
- Field validation (required fields, enums, date format, ID charset, length limits, malformed list fields)
- Sanitization / XSS & injection resistance
- Markdown and PDF report generation
- Integrity hash generation and tamper detection
- Rate limiter behavior
- Flask API endpoints (success, validation errors, non-JSON rejection, security headers, PDF response)

See `test_results.txt` for the last full run output.

## Deploying it live

This project ships ready to deploy: a `Dockerfile`, `Procfile` (Heroku-style),
`render.yaml` (Render.com one-click blueprint), and `fly.toml` (Fly.io) are all
included. See **`DEPLOYMENT.md`** for step-by-step instructions — the fastest
path is Render.com's free tier, which takes about 5 minutes from a GitHub repo
to a live HTTPS URL.

## Known Limitations (MVP scope)

- No authentication/authorization layer yet — intended to sit behind an organization's existing SSO/reverse proxy in a real deployment.
- Reports are generated per-request and not persisted to a database; the in-memory cache in `app.py` is for demo purposes only.
- Rate limiting is in-process and per-instance; a multi-instance deployment would need a shared store (e.g., Redis) instead.

## License

Provided as-is for demonstration/educational purposes.
