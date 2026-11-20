# Deploying PhishGuard

Three moving parts, one repository:

| Piece | Platform | What it is |
|---|---|---|
| Source of truth | GitHub | The `main` branch both platforms watch |
| Application | Render | gunicorn + Flask + SQLite + the ML model |
| Front end | Vercel | Static page in `web/` plus a `/api/scan` proxy to Render |

Deploy in that order: **GitHub → Render → Vercel**. The Vercel functions need the Render
URL, and Render needs the repository.

---

## 0. Before the first push

1. Confirm the placeholder-only template is what you commit. `.env` is ignored by Git;
   `.env.example` must contain no real keys.
2. Generate a session key you can reuse:

   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Rotate any API key that was ever stored in a tracked file.** If a VirusTotal or
   OPSWAT key was previously committed or shared, revoke it in the vendor console, create a
   new one, and keep it only in `.env` locally and in Render's environment variables.

## 1. Publish to GitHub

Install Git for Windows first if `git --version` fails:
<https://git-scm.com/download/win> (accept the default options).

```powershell
cd "C:\Users\VasuDev\OneDrive\Desktop\PhishGuard"
git init -b main
git add .
git status --short          # inspect: no .env, no .venv, no phishguard.db
git commit -m "Harden PhishGuard for hosted deployment"
git remote add origin https://github.com/YOUR-USERNAME/PhishGuard.git
git push -u origin main
```

Create the empty repository on GitHub first (**New repository**, no README, no `.gitignore`,
no license — this project already has them). Authenticate in the browser prompt or with a
personal access token; never paste a token into the remote URL.

Later pushes are just `git add . ; git commit -m "..." ; git push`.

## 2. Deploy the app to Render

### Option A — Blueprint (recommended)

`render.yaml` is committed and describes the whole service.

1. Open <https://dashboard.render.com/blueprints> → **New Blueprint Instance**.
2. Connect GitHub and pick the `PhishGuard` repository.
3. Render reads `render.yaml` and shows the service `phishguard`. Review it, then
   **Apply**. `FLASK_SECRET_KEY` is generated automatically.
4. When prompted, fill the two `sync: false` values:
   - `PHISHGUARD_ACCESS_CODE` — a passcode you choose, or leave empty for a fully public
     history. Setting it is strongly recommended on a public URL.
   - `PHISHGUARD_ALLOWED_ORIGINS` — your future Vercel domain, for example
     `https://phishguard.vercel.app`. Use `*` while you experiment, tighten it afterwards.
5. Wait for the build. The health check hits `/healthz`; a green service means
   `status: ok` and `database: ok`.

### Option B — Manual web service

If you prefer clicking through **New → Web Service**:

| Setting | Value |
|---|---|
| Language / runtime | Python 3 |
| Root directory | repository root (leave empty) |
| Build command | `pip install --upgrade pip && pip install -r requirements.txt` |
| Start command | `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 --access-logfile - wsgi:app` |
| Health check path | `/healthz` |

Environment variables:

| Key | Value |
|---|---|
| `PYTHON_VERSION` | `3.13.7` |
| `PHISHGUARD_ENV` | `production` |
| `FLASK_SECRET_KEY` | the 64-character hex string from step 0 |
| `PHISHGUARD_DATA_DIR` | `/tmp/phishguard` (or your disk mount path) |
| `PHISHGUARD_ACCESS_CODE` | your passcode, or empty |
| `PHISHGUARD_ALLOWED_ORIGINS` | `https://YOUR-PROJECT.vercel.app` |
| `MAX_UPLOAD_BYTES` | `52428800` |
| `FILE_SCAN_WORKERS` | `2` |
| `PHISHGUARD_RATE_LIMIT` | `1` |

Note the resulting URL, for example `https://phishguard.onrender.com`. Verify it:

```powershell
Invoke-RestMethod https://phishguard.onrender.com/healthz
Invoke-RestMethod https://phishguard.onrender.com/api/v1/health
```

### Persisting history on Render

Free instances have an ephemeral filesystem: the SQLite file and the passcode-protected
history disappear on every deploy or restart. Pick one:

- **Accept it** — history is per-session demo data. Fine for a portfolio link.
- **Attach a disk** — add a Render disk (paid) mounted at `/var/data`, then set
  `PHISHGUARD_DATA_DIR=/var/data`. The database lands in `/var/data/phishguard.db`.
- **Use an external database** — requires a code change; SQLite is the only supported store
  today.

Free services also sleep after ~15 minutes of inactivity. The first request afterwards
takes 30–50 seconds to wake; the Vercel proxy returns a readable `504` message if it times
out before the app wakes.

## 3. Deploy the front end to Vercel

The front end lives in `web/` and is a static site plus two Node functions
(`api/scan.js`, `api/health.js`). No build step.

1. Open <https://vercel.com/new> and import the same GitHub repository.
2. Configure the project:

   | Setting | Value |
   |---|---|
   | Framework preset | Other / None |
   | Root directory | `web` |
   | Build command | *(empty)* |
   | Output directory | *(empty — static files are served as-is)* |
   | Install command | *(empty)* |

3. Add one environment variable, then deploy:

   | Key | Value |
   |---|---|
   | `PHISHGUARD_APP_URL` | `https://phishguard.onrender.com` (no trailing slash) |

4. Deploy, then open the assigned domain. The demo form should return a live report.

Environment variable changes require a **Redeploy** to take effect.

### Wiring the two together

- Set `PHISHGUARD_ALLOWED_ORIGINS` on Render to your Vercel domain. Because the browser
  only calls the same-origin `/api/scan` proxy, CORS is not strictly needed — but tightening
  the list keeps direct API use under your control.
- Update the Vercel domain in `web/app.js` only if you change the Render URL; it reads the
  console links from `data-app-path`, so the base host is configurable per environment.

For the CLI path instead of the dashboard:

```powershell
npm install -g vercel
vercel login
cd web
vercel --prod
vercel env add PHISHGUARD_APP_URL production
vercel --prod
```

## 4. Post-deploy checklist

```powershell
# Render
Invoke-RestMethod https://YOUR-APP.onrender.com/healthz
Invoke-WebRequest  https://YOUR-APP.onrender.com/ -UseBasicParsing | Select-Object StatusCode
$body = @{ url = "http://secure-account-verify.example/login" } | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri https://YOUR-APP.onrender.com/api/v1/scan/url `
  -ContentType application/json -Body $body

# Vercel
Invoke-RestMethod https://YOUR-PROJECT.vercel.app/api/health
```

Then in the browser:

1. `/` returns a verdict for a suspicious URL.
2. Security headers are present (`Content-Security-Policy`, `X-Frame-Options: DENY`).
3. With a passcode set, `/dashboard` redirects to `/unlock`; a wrong code is rejected and a
   correct one opens the console. `/email` and `/files` stay reachable either way.
4. `/api` renders the documentation page and the copy button works.
5. Upload a small file on `/files` and confirm the report renders.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Build fails with `No module named ...` | dependency not listed in `requirements.txt` | add it, commit, push |
| `ConfigurationError: FLASK_SECRET_KEY` at boot | production without a stable key | set `FLASK_SECRET_KEY` on Render |
| `/healthz` returns `503` | database or model could not load | check logs for `database`/`model` detail; usually a bad `PHISHGUARD_DATA_DIR` |
| Vercel shows `503 PHISHGUARD_APP_URL is not set` | env var missing | add it, redeploy |
| Vercel shows `504 … may still be waking up` | Render free instance asleep | retry once after ~40 seconds |
| Session or CSRF errors across workers | secret key changed between restarts | keep `FLASK_SECRET_KEY` fixed |
| Uploads rejected at ~4.5 MB | platform body limit | lower `MAX_UPLOAD_BYTES`; Render caps request bodies well below 100 MiB |
| History empty after a deploy | ephemeral filesystem | attach a disk and set `PHISHGUARD_DATA_DIR` |

## Rollback

Render and Vercel both keep previous deploys: use **Rollback** on the Render service page or
**Deployments → Promote** on Vercel. To roll back the code itself:

```powershell
git revert HEAD ; git push
```
