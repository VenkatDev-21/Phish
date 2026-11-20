---
kind: configuration_system
name: Environment-Driven Runtime Configuration via `runtime_config.RuntimeSettings`
category: configuration_system
scope:
    - '**'
source_files:
    - runtime_config.py
    - .env.example
    - app.py
    - wsgi.py
---

## What system/approach is used

PhishGuard uses a single, import-time configuration layer built on Python's `os.environ` plus the third-party `python-dotenv` library. There is no YAML/JSON/TOML config file format and no Flask `Config.from_envfile`; instead, `runtime_config.py` defines typed helpers (`_flag`, `_integer`, `_origins`) that parse environment variables into an immutable `dataclass` snapshot called `RuntimeSettings`. The module loads `.env` at import time and exposes a module-level `SETTINGS` instance consumed by `app.py`.

## Key files and packages

- `runtime_config.py` — sole configuration loader; defines `load_settings()`, `RuntimeSettings`, and the `ConfigurationError` exception.
- `.env.example` — template of all supported environment variables (copy to `.env` for local dev).
- `app.py` — consumes `SETTINGS` and pushes values onto `Flask.config`.
- `wsgi.py` — production WSGI entry point; relies on `app.py`'s top-level imports (and thus `runtime_config`) to initialize settings before gunicorn starts workers.
- `Procfile` / `render.yaml` / `vercel.json` — deployment manifests that set the runtime environment variables consumed by the loader.

## Architecture and conventions

1. **Single source of truth.** All hosting-specific defaults live in `runtime_config.py`; `app.py` never reads `os.environ` directly for application behavior. It only imports `PROJECT_DIR` and `SETTINGS` from that module.

2. **Immutable dataclass snapshot.** `RuntimeSettings` is declared with `@dataclass(frozen=True)`, so once loaded it cannot be mutated at runtime. New configuration knobs are added as fields on this class rather than ad-hoc globals.

3. **Typed parsers.** Boolean flags go through `_flag(name, default)` which accepts any case-insensitive value in `{"1", "true", "yes", "on"}` as truthy and `{"0", "false", "no", "off", ""}` as falsy; integers go through `_integer(name, default)` which raises `ConfigurationError` on non-numeric input. Origins are parsed from a comma-separated string with trailing slashes stripped and duplicates removed.

4. **Environment detection.** `_environment()` resolves `PHISHGUARD_ENV` explicitly; otherwise it infers `production` when `RENDER` or `RENDER_EXTERNAL_HOSTNAME` or `VERCEL` is present, and `development` when `FLASK_DEBUG=1`; everything else falls back to `development`. `is_production` is derived as `environment not in DEVELOPMENT_ENVIRONMENTS` where `DEVELOPMENT_ENVIRONMENTS = {"development", "dev", "local", "test", "testing"}`.

5. **Secret-key policy.** `_secret_key(environment)` enforces a minimum length of 16 characters for `FLASK_SECRET_KEY`. In development environments it generates an ephemeral key via `secrets.token_hex(32)` and sets `secret_key_is_ephemeral=True`; outside development it raises `ConfigurationError` if the variable is missing or too short. This is the only place session/CSRF signing material is produced.

6. **Data directory policy.** `_data_directory()` returns `$PHISHGUARD_DATA_DIR` (expanded via `Path.expanduser()`) when set, otherwise the project root. Database path is always `data_dir / "phishguard.db"` and uploads go under `data_dir / "uploads"`.

7. **Upload ceilings differ by environment.** Local default is `LOCAL_MAX_UPLOAD_BYTES = 5 * 1024**3` (5 GiB); hosted default is `HOSTED_MAX_UPLOAD_BYTES = 100 * 1024**2` (100 MiB). Both must be positive integers.

8. **Flask config bridge.** `app.py` calls `app.config.update(...)` with every field from `SETTINGS` (e.g. `SECRET_KEY`, `DATABASE`, `UPLOAD_DIR`, `MAX_UPLOAD_BYTES`, `PORT`, `ENVIRONMENT`, `IS_PRODUCTION`, `ACCESS_CODE`, `ALLOWED_ORIGINS`, `RATE_LIMIT_ENABLED`, `EXTERNAL_SUBMISSIONS_ENABLED`). It also derives `MAX_CONTENT_LENGTH` from the larger of upload/email limits and hardens session cookies (`HTTPONLY`, `SAMESITE=Lax`, `SECURE=is_production`).

9. **Feature-flag style toggles.** `PHISHGUARD_RATE_LIMIT` and `PHISHGUARD_EXTERNAL_SUBMISSIONS` are boolean flags that gate the in-process rate limiter and third-party scanner submissions respectively; both default to enabled.

10. **Access gate.** `PHISHGUARD_ACCESS_CODE` is a shared passcode for `/dashboard`, `/history`, `/authentication` and their APIs. When empty the gate is disabled; when present `access_gate_enabled` becomes true and routes require unlocking via `/unlock`.

11. **CORS origins.** `PHISHGUARD_ALLOWED_ORIGINS` is a comma-separated list of hostnames with trailing slashes stripped; if unset the default is `("*",)`.

## Conventions and constraints

- **All configuration comes from environment variables** (plus `.env` via `dotenv.load_dotenv(PROJECT_DIR / ".env")` at import time). No other config file formats are read by the application.
- **Boolean flags use the canonical truthy/falsy sets**: `1/true/yes/on` → True; `0/false/no/off/empty` → False; anything else falls back to the provided default.
- **Integer configuration values raise `ConfigurationError`** when they cannot be parsed or are non-positive (enforced by `_integer` and the explicit `<= 0` checks around `MAX_UPLOAD_BYTES` and `MAX_EMAIL_REQUEST_BYTES`).
- **Port must be between 1 and 65535** — enforced by `load_settings` after parsing `PORT`.
- **`FLASK_SECRET_KEY` is mandatory outside development environments** — `_secret_key` raises `ConfigurationError` if it is absent or shorter than 16 characters when `environment` is not in `DEVELOPMENT_ENVIRONMENTS`.
- **Development vs production host binding**: host defaults to `127.0.0.1` in development and `0.0.0.0` in production unless `HOST` is explicitly set.
- **Behind-proxy mode defaults to True in production** via `PHISHGUARD_BEHIND_PROXY`, allowing reverse proxies (Render/Vercel) to supply correct client IPs.
- **The `.env.example` template documents every supported variable** and instructs users to copy it to `.env` (which is gitignored); real keys must not be committed.
- **New configuration knobs should be added as fields on `RuntimeSettings`** and wired into `app.config.update(...)` in `app.py`, following the existing pattern rather than being accessed directly from `os.environ`.