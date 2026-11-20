---
kind: dependency_management
name: Dual Python/Node Dependency Management via Flat Requirements and Vercel Scripts
category: dependency_management
scope:
    - '**'
source_files:
    - requirements.txt
    - web/package.json
    - Procfile
    - render.yaml
    - .python-version
    - .gitignore
---

## Approach

PhishGuard uses two independent, flat dependency declarations with no lockfiles:

- **Python**: `requirements.txt` pinned to exact versions (e.g. `Flask==3.1.3`, `scikit-learn==1.9.1`, `numpy==2.5.3`). Installation is performed by both local tooling and CI/deploy pipelines via `pip install -r requirements.txt`.
- **Node.js (Vercel landing page)**: `web/package.json` declares only metadata and scripts; there are no runtime dependencies listed in `dependencies`. The project relies on Node built-ins plus the `vercel` CLI (`dev` / `deploy` scripts) and a `node` engine constraint of `>=20`.

There is no `Pipfile`, `pyproject.toml`, `poetry.lock`, `Pipenv`, `uv.lock`, or any private PyPI registry configuration. There is no `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`; `web/node_modules/` is gitignored (`.gitignore` line 23).

## Key Files

- `requirements.txt` — canonical Python dependency manifest, all packages pinned with `==`.
- `web/package.json` — Node-side manifest for the Vercel landing page; declares `engines.node >= 20` and `vercel` CLI scripts.
- `Procfile` — Heroku-style process definition running `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 --access-logfile - wsgi:app`.
- `render.yaml` — Render.com deployment config that runs `pip install --upgrade pip && pip install -r requirements.txt` as its build step and sets `PYTHON_VERSION=3.13.7`.
- `.python-version` — pyenv-compatible Python version pin (used locally).
- `.gitignore` — excludes `__pycache__/`, `.venv/`, and `web/node_modules/`.

## Architecture & Conventions

- **Flat pins over ranges**: Every Python package in `requirements.txt` uses an exact `==` pin rather than `>=`, `~=`, or bare names. This makes builds reproducible at install time but requires manual updates when bumping libraries.
- **No lockfile generation**: Neither `pip freeze` nor `pip-tools`/`pip-compile` is used; `requirements.txt` is the single source of truth. Similarly, the Node side has no lockfile — dependency resolution happens at deploy time on Vercel's Node 20+ environment.
- **Runtime pinned via platform configs**: Python interpreter version is pinned through both `.python-version` (local pyenv) and `render.yaml` env var `PYTHON_VERSION=3.13.7`; Node version is constrained via `engines.node >= 20` in `web/package.json`.
- **Deployment-driven installs**: Dependencies are installed inside the deployment pipeline (`render.yaml` `buildCommand`) and at runtime via gunicorn (declared in both `Procfile` and `render.yaml` `startCommand`).
- **No vendoring**: No `vendor/`, no vendored wheels, no private index URLs (`--index-url`, `--extra-index-url`, `PIP_INDEX_URL`, `PIP_TRUSTED_HOST`) appear anywhere in the repo.

## Observed Constraints

- All Python third-party packages are pinned to exact versions in `requirements.txt` (verified across all 34 entries).
- The Node side declares zero runtime dependencies in `web/package.json`; only dev-time tooling (`vercel`) is referenced via scripts.
- `web/node_modules/` is excluded from version control (`.gitignore`), so Node dependencies are resolved on each Vercel deploy.
- The Python runtime is pinned to 3.13.7 by `render.yaml`'s `envVars.PYTHON_VERSION` and by `.python-version`.
- The Node runtime must be Node ≥ 20 per `web/package.json` `engines.node`.
- Gunicorn is the production WSGI server, configured identically in `Procfile` and `render.yaml` (`--workers 2 --threads 4 --timeout 120`).

No private registries, proxy configurations, or dependency-update automation (Dependabot, Renovate, etc.) were found.