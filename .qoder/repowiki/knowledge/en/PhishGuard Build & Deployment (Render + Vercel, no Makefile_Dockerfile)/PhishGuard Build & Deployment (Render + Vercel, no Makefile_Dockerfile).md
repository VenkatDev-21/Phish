---
kind: build_system
name: PhishGuard Build & Deployment (Render + Vercel, no Makefile/Dockerfile)
category: build_system
scope:
    - '**'
source_files:
    - requirements.txt
    - .python-version
    - Procfile
    - render.yaml
    - DEPLOYMENT.md
    - web/package.json
    - web/vercel.json
    - wsgi.py
---

## What system/approach is used

PhishGuard has **no Makefile, Dockerfile, or CI pipeline** in this repository. Build and deployment are delegated entirely to two platform-as-a-service providers:

- **Render** hosts the Flask backend (Python/gunicorn). The service is declared declaratively in `render.yaml` (Blueprint) and can also be configured manually.
- **Vercel** hosts the static frontend under `web/`, including two serverless functions (`api/scan.js`, `api/health.js`) that proxy requests to Render.

The only local build tooling is `pip` for Python dependencies and `vercel` CLI for the frontend; there is no shared build script, no cross-compilation, and no release automation beyond Git push → platform auto-deploy.

## Key files and packages

| File | Role |
|---|---|
| `requirements.txt` | Pinned Python dependency manifest (Flask 3.1.3, gunicorn 23.0.0, scikit-learn 1.9.1, pandas 3.0.6, etc.) — all versions pinned with `==`. |
| `.python-version` | Declares the CPython version used by the project (read by tools like pyenv). |
| `Procfile` | Heroku-style process declaration: `web: gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 --access-logfile - wsgi:app`. |
| `render.yaml` | Render Blueprint defining the web service, build/start commands, health check path `/healthz`, environment variables, and `autoDeploy: true`. |
| `DEPLOYMENT.md` | Authoritative step-by-step guide covering GitHub → Render → Vercel order, env vars, disk persistence, rollback, and post-deploy checks. |
| `web/package.json` | Node package declaring `engines.node >= 20`, scripts `dev` (`vercel dev`) and `deploy` (`vercel deploy --prod`). No runtime dependencies listed. |
| `web/vercel.json` | Vercel config: `framework: null`, `buildCommand: null`, function timeouts of 15s, security headers (CSP, X-Frame-Options DENY, Referrer-Policy, Permissions-Policy), cache rules for CSS/JS vs API routes. |
| `wsgi.py` | WSGI entry point consumed by both Procfile and Render's start command. |

## Architecture and conventions

- **Two-platform split**: Backend lives at the repo root (Python/Flask); frontend lives in `web/` (static HTML/CSS/JS plus Node serverless functions). There is no monorepo bundler — each side deploys independently.
- **Declarative Render deployment**: `render.yaml` is the single source of truth for the backend service. It pins `PYTHON_VERSION=3.13.7`, sets `PHISHGUARD_ENV=production`, generates `FLASK_SECRET_KEY`, and defines `PHISHGUARD_DATA_DIR=/tmp/phishguard` (ephemeral on free tier).
- **No build step for either side**: Render runs `pip install -r requirements.txt`; Vercel serves `web/` as-is with `buildCommand: null`. The ML model (`models/phishing_model.pkl`) is shipped in-tree and loaded at runtime.
- **Environment-driven configuration**: All secrets and tuning knobs flow through environment variables (`FLASK_SECRET_KEY`, `PHISHGUARD_ACCESS_CODE`, `PHISHGUARD_ALLOWED_ORIGINS`, `MAX_UPLOAD_BYTES`, `FILE_SCAN_WORKERS`, `PHISHGUARD_RATE_LIMIT`, `PHISHGUARD_APP_URL`). Secrets are never committed; `.env.example` is the template.
- **Health endpoints**: Both platforms use a health check — Render probes `/healthz` (and `/api/v1/health` per docs); Vercel exposes `/api/health` via a serverless function.
- **Auto-deploy on `main`**: Render's `branch: main` and `autoDeploy: true` mean pushes to main trigger builds automatically. Vercel is wired to the same GitHub repo.
- **Rollback strategy**: Documented in `DEPLOYMENT.md` — Render Rollback button, Vercel Deployments → Promote, and code-level rollback via `git revert HEAD ; git push`.

## Conventions and constraints

- **Dependency pinning**: Every line in `requirements.txt` uses `==` (e.g. `Flask==3.1.3`, `gunicorn==23.0.0`, `scikit-learn==1.9.1`). This is enforced by the file itself — there is no `Pipfile.lock` or `poetry.lock` to override it.
- **Python version pinning**: `.python-version` and `render.yaml`'s `PYTHON_VERSION=3.13.7` must agree; mismatch causes build failures on Render.
- **Gunicorn invocation is duplicated but identical**: `Procfile` and `render.yaml` both specify `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 --access-logfile - wsgi:app`. Any change needs to be kept in sync across both files.
- **Frontend has zero build step**: `web/vercel.json` sets `buildCommand: null` and `framework: null`; `web/package.json` declares no dependencies. Static assets and serverless functions are served directly.
- **Vercel function timeout**: Both `api/scan.js` and `api/health.js` are capped at `maxDuration: 15` seconds in `web/vercel.json`. Long-running scans must complete within this window or the function will terminate.
- **Security headers are centralized in `web/vercel.json`**: CSP (`default-src 'self'`, `script-src 'self'`, `object-src 'none'`), `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy` disabling camera/microphone/geolocation/payment are applied to all routes.
- **Cache policy separation**: API routes get `Cache-Control: no-store`; static assets (`/styles.css`, `/app.js`) get `public, max-age=3600, must-revalidate`.
- **Deployment order is enforced by documentation**: `DEPLOYMENT.md` states "Deploy in that order: GitHub → Render → Vercel" because the Vercel proxy depends on the Render URL being live.
- **Ephemeral filesystem caveat**: Free Render instances lose SQLite data on restart; `DEPLOYMENT.md` documents attaching a disk at `/var/data` and setting `PHISHGUARD_DATA_DIR=/var/data` as the fix.
- **No CI lint/test/build gate**: There is no GitHub Actions workflow, no `Make test`, and no pre-commit hook in the repo. Tests under `tests/` exist but are not invoked by any build script.