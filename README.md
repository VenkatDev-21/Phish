# PhishGuard

PhishGuard is a self-hostable phishing triage console. It combines three analyses in one
interface — a machine-learning URL check, static file triage, and pasted-email security
review — and records every scan in a searchable SQLite history with a SOC-style dashboard.

It runs either as a local Flask app or as a small hosted deployment: the app on
[Render](https://render.com) and a static marketing/demo front end on
[Vercel](https://vercel.com) that calls the same public JSON API.

> **Important:** this is an educational detector, not a production security product.
> Model output and scanner results can be wrong. URLs are never opened, files are never
> executed, and email checks are heuristics. A "legitimate" or "no detections" result is
> not proof of safety.

---

## Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Run it locally](#run-it-locally)
- [Configuration](#configuration)
- [Pages](#pages)
- [Public JSON API](#public-json-api)
- [Optional integrations](#optional-integrations)
- [Tests](#tests)
- [Project layout](#project-layout)
- [Deployment](#deployment)
- [Security model](#security-model)

---

## What it does

| Analysis | Entry point | Result |
|---|---|---|
| URL scan | `/` and `POST /api/v1/scan/url` | Phishing probability plus the 11 structural features the model used |
| File scan | `/files` | SHA-256, signature/magic checks, optional ClamAV + consented cloud lookups |
| Email scan | `/email` | Header/intent/attachment findings, link extraction, SPF/DKIM/DMARC claims |
| Authentication review | `/authentication` | Reported auth-header verdicts, plus per-source history tabs |
| Dashboard | `/dashboard` | Cross-source counts, trends, top indicators, live health |
| History | `/history` | One filterable, paginated timeline with CSV export |

Everything is deterministic and offline by default: no URL fetches, no telemetry, no
phoning home. Only two things ever leave the machine, and both are opt-in:
public DNS lookups for SPF/DMARC/MX, and per-scan consented attachment submission to
VirusTotal/OPSWAT when you configure those keys.

## Architecture

```
                     ┌───────────────────────────────┐
     GitHub  ───────▶│  Render: gunicorn + Flask     │
                     │  SQLite · uploads · ML model  │
                     │  /api/v1/scan/url  · /healthz │
                     └──────────────▲────────────────┘
                                    │ JSON over HTTPS
                     ┌──────────────┴────────────────┐
     Vercel  ───────▶│  Static front end + proxy fn  │
                     │  /  ·  /api/scan  ·  /api/health │
                     └───────────────────────────────┘
```

The full Flask app is too large for a Vercel Python function (numpy + scipy + pandas +
scikit-learn exceed the bundle limit), so the hosted split is deliberate: Render runs the
real application, Vercel serves a fast static page and proxies a single endpoint so the
browser never needs CORS and the Render host name stays server-side.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the step-by-step, and
[SECURITY.md](SECURITY.md) for the threat model.

## Run it locally

Requires Python 3.11+ (the pinned toolchain is 3.13).

```powershell
cd "C:\Users\VasuDev\OneDrive\Desktop\PhishGuard"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env        # optional, needed only for integrations
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000**. The server binds `127.0.0.1` in development, so it is not
reachable from other machines. Press `Ctrl+C` to stop it.

Change the port without editing code:

```powershell
$env:PORT = "5056"; .\.venv\Scripts\python.exe app.py
Remove-Item Env:PORT                # back to 5000 in this shell
```

On Linux or macOS the same steps work with `python3 -m venv .venv` and
`./.venv/bin/python app.py`.

## Configuration

All runtime settings come from environment variables (a local `.env` is loaded
automatically). Nothing else needs to be edited to change a deployment.

| Variable | Default (local) | Default (production) | Purpose |
|---|---|---|---|
| `FLASK_SECRET_KEY` | ephemeral random | **required** | Session + CSRF signing. Startup fails outside development if missing or shorter than 16 characters. |
| `PHISHGUARD_ENV` | `development` | `production` | Selects safe defaults and enables `Secure` cookies. |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | `0.0.0.0` / `$PORT` | Bind address. |
| `PHISHGUARD_DATA_DIR` | project folder | `/tmp/phishguard` | Root for the SQLite DB and temporary uploads. Point at a mounted disk to keep history. |
| `MAX_UPLOAD_BYTES` | `5368709120` (5 GiB) | `104857600` (100 MiB) | File-scan ceiling. |
| `MAX_EMAIL_REQUEST_BYTES` | `67108864` (64 MiB) | same | Pasted-email request ceiling. |
| `PHISHGUARD_ACCESS_CODE` | empty (gate off) | empty (gate off) | When set, `/dashboard`, `/history`, `/authentication`, `/api/dashboard/*` require this passcode. Scanners stay public. |
| `PHISHGUARD_ALLOWED_ORIGINS` | `*` | `*` | Comma-separated origins allowed on `/api/v1`; set your front-end domain to tighten CORS. |
| `PHISHGUARD_RATE_LIMIT` | `1` | `1` | `0` disables the in-process limiter (not recommended when hosted). |
| `PHISHGUARD_EXTERNAL_SUBMISSIONS` | `1` | `1` | `0` refuses third-party file uploads even when a user ticks consent. |
| `PHISHGUARD_BEHIND_PROXY` | auto | `1` | Trust `X-Forwarded-*` from the platform proxy. |

`vt`, `OPSWAT`, `CLAMSCAN_PATH` and `CLAMAV_DATABASE_DIR` are covered under
[optional integrations](#optional-integrations).

## Pages

| Route | Notes |
|---|---|
| `/` | URL scanner, model confidence, feature breakdown |
| `/files` | File upload with hashing, signatures, scanner readiness |
| `/email` | Paste or upload `.eml`/`.txt`/`.html`; links, headers, attachments |
| `/authentication` | SPF/DKIM/DMARC claims with separate email/file/URL history tabs |
| `/dashboard` | Range selector (15m → 30d or custom), auto-refresh every minute |
| `/history` | Unified timeline, filters, CSV export (max 1,000 rows) |
| `/api` | On-page API documentation with a copy-ready cURL sample |
| `/unlock`, `/lock` | Passcode gate for history, only active when `PHISHGUARD_ACCESS_CODE` is set |
| `/healthz`, `/api/v1/health` | Liveness/readiness probes used by Render |

Branded 404/429/500 pages replace framework defaults, and every response carries a strict
CSP, `nosniff`, `DENY` framing, and a no-referrer policy.

## Public JSON API

`POST /api/v1/scan/url`

```bash
curl -X POST https://YOUR-APP.onrender.com/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://secure-account-verify.example/login"}'
```

```json
{
  "scan_id": 12,
  "scanned_at": "2026-11-20 12:34:20",
  "url": "http://secure-account-verify.example/login",
  "result": "PHISHING",
  "risk_level": "High",
  "probability": 100.0,
  "features": { "https": 0, "has_at_symbol": 0, "hyphen_count": 2, "...": "..." },
  "engine": "phishguard-url-random-forest",
  "disclaimer": "Structural model output only. The URL was never opened and no reputation service was queried."
}
```

- `201` report created, `400` validation error, `429` rate limited (`Retry-After` header
  plus `retry_after` in the body), `500` unexpected failure.
- Default limit: 60 requests per 5 minutes per client address.
- CORS is enabled on `/api/v1/*` (`PHISHGUARD_ALLOWED_ORIGINS` to restrict).
- `GET /api/v1/health` advertises capabilities and the active limits;
  `GET /healthz` returns `200`/`503` with database and model state.

Read-only dashboard endpoints live under `/api/dashboard/`: `summary`, `activity`,
`threat-distribution`, `recent-events` (+ `.csv`), `email-statistics`, `url-statistics`,
`file-statistics`, `authentication-statistics`, `threat-intelligence`, `incidents`,
`top-indicators`, `system-health`, and `search`. They accept
`range=all|15m|1h|24h|7d|30d` or `range=custom&start=…&end=…`.

## Optional integrations

**ClamAV** (local, recommended): install from [clamav.net](https://www.clamav.net/downloads),
run `freshclam`, then set `CLAMSCAN_PATH` and `CLAMAV_DATABASE_DIR`. The scanner page shows
whether the executable and signature database were found.

**VirusTotal / OPSWAT** (cloud, opt-in): set `VT_API_KEY`, `OPSWAT_API_KEY` and optionally
`OPSWAT_MAX_UPLOAD_BYTES` in `.env` or the platform dashboard. Files are only uploaded when
the per-scan consent checkbox is ticked, and `PHISHGUARD_EXTERNAL_SUBMISSIONS=0` disables
the path entirely. Never submit confidential or regulated samples.

Wrap local paths containing spaces in quotes:

```dotenv
CLAMSCAN_PATH="C:\Program Files\ClamAV\clamscan.exe"
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

60 tests cover the scanners, dashboard APIs, CSRF enforcement, security headers, the
passcode gate, rate limiting, the public API contract, CORS preflight, and health probes.
The limiter is bypassed while `TESTING` is set unless a test opts in with
`RATE_LIMIT_IN_TESTS`, so suites stay fast and deterministic.

## Project layout

```text
app.py                        Flask routes, scans, dashboard APIs, public API v1
runtime_config.py             Environment resolution and production guards
security.py                   Security headers, CORS, passcode gate, rate limiter
wsgi.py                       Gunicorn entry point
email_security.py             Email parsing, risk indicators, report shaping
email_auth.py                 Reported auth-header analysis, optional DNS lookups
email_attachment_analysis.py  Bounded static attachment inspection
file_analysis.py              Signatures, local ClamAV, consented provider submissions
feature_extraction.py         URL feature extraction
models/phishing_model.pkl     Pre-trained URL model used by the app
templates/, static/           Jinja pages and browser assets
web/                          Vercel static front end + /api proxy functions
tests/                        unittest suite
render.yaml, Procfile         Render blueprint
```

## Deployment

- **Render** runs `wsgi:app` under gunicorn using the committed `render.yaml`
  (Blueprint) or the manual settings in [DEPLOYMENT.md](DEPLOYMENT.md).
- **Vercel** serves `web/` as a static site and proxies `POST /api/scan` to Render via
  `PHISHGUARD_APP_URL`.

Both services deploy from the same GitHub repository on every push to `main`. Full
instructions, environment variables, and troubleshooting are in
[DEPLOYMENT.md](DEPLOYMENT.md).

## Security model

Implemented controls: mandatory stable secret key outside development, strict CSP and
header set on every response, HttpOnly + SameSite session cookies with `Secure` in
production, CSRF tokens on all state-changing form posts, timing-safe passcode comparison,
sliding-window rate limits per client and rule, ProxyFix only when explicitly trusted,
sanitized `robots.txt`, no `noindex` leakage, and no secrets in the repository
(`.env` is ignored, `.env.example` holds placeholders only).

Known limits: the rate limiter is per-process (two gunicorn workers = two budgets), the
passcode gate is a shared secret rather than per-user accounts, SQLite on a free Render
instance is ephemeral unless you attach a disk, and scan results are heuristic. See
[SECURITY.md](SECURITY.md).

## Training-data note

Raw dataset CSVs are not part of this repository (size and licensing). The app ships a
trained model in `models/` and does not need the datasets at runtime.
