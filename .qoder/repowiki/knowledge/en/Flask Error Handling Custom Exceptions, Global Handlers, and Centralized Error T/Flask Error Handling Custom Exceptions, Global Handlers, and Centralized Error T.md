---
kind: error_handling
name: 'Flask Error Handling: Custom Exceptions, Global Handlers, and Centralized Error Templates'
category: error_handling
scope:
    - '**'
source_files:
    - app.py
    - runtime_config.py
    - security.py
    - templates/error.html
    - email_security.py
    - email_attachment_analysis.py
    - email_auth.py
    - soc_dashboard.py
---

## Approach

PhishGuard uses a layered Flask error-handling strategy built on three pillars:

1. **Custom exception classes** for domain-specific validation failures.
2. **Flask `@app.errorhandler` decorators** for global HTTP-level responses (404, 500, `RequestEntityTooLarge`).
3. **A shared Jinja2 template** (`templates/error.html`) that renders all user-facing errors with a consistent dark-console UI.

There is no centralized error-class hierarchy beyond the small set of custom exceptions; most I/O and DNS failures are caught inline with `try/except` blocks and logged via `app.logger.exception`.

## Key Files and Packages

- `runtime_config.py` — defines `ConfigurationError(RuntimeError)` and raises it during environment-variable validation at import time.
- `security.py` — defines `RateRule.__post_init__` raising `ValueError`, plus the shared `rate_limited_response(429)` helper used by rate-limiting code paths.
- `app.py` — defines `UrlValidationError(ValueError)`, registers the three global error handlers, and contains route-level `try/except ValueError` blocks for email/file input validation.
- `email_security.py` / `email_attachment_analysis.py` — raise `TypeError` / `ValueError` for malformed inputs (e.g. non-bytes email data, empty uploads).
- `soc_dashboard.py` — exports `DashboardQueryError`, caught in `_dashboard_api` and returned as JSON `400`.
- `templates/error.html` — single error page rendering `error_code`, `error_title`, `error_message`, and optional `retry_after`.

## Architecture and Conventions

### Custom exception types

| Exception | Base class | Where raised | Meaning |
|---|---|---|---|
| `ConfigurationError` | `RuntimeError` | `runtime_config.py` | Invalid or missing environment variable at startup |
| `UrlValidationError` | `ValueError` | `app.py::normalize_url` | Client-supplied URL fails validation |
| `DashboardQueryError` | (from `soc_dashboard.py`) | Dashboard query layer | Bad dashboard query parameters |

Domain-layer functions raise these specific exceptions so routes can distinguish them from unexpected bugs. For example, `predict()` catches `UrlValidationError` and returns the form with an `error` message (HTTP 400), while unhandled exceptions bubble to the global 500 handler.

### Global error handlers

Three handlers are registered in `app.py`:

- `@app.errorhandler(RequestEntityTooLarge)` — distinguishes `/files` vs `/email` vs other routes and returns either JSON or the appropriate scan form with the error pre-filled.
- `@app.errorhandler(404)` — returns `jsonify(error="Not found.")` for `/api/*` requests, otherwise renders `error.html` with title "Page not found".
- `@app.errorhandler(500)` — logs the full exception via `app.logger.error`, then returns JSON for API routes or `error.html` with title "Something went wrong" for HTML routes.

The pattern is uniform across handlers: branch on `request.path.startswith("/api/")` to choose between a JSON body and a rendered template.

### Rate limiting as an error path

Rate-limited requests return 429 through two channels:

- `_rate_limit_blocked()` in `app.py` renders `error.html` for HTML requests or calls `security.rate_limited_response()` (which sets `Retry-After`) for JSON requests.
- The access-code gate in `security._enforce_access()` returns 401 JSON when a protected endpoint is hit without a valid session.

### Inline exception handling

Most I/O-bound operations use `try/except` around the risky call and log via `app.logger.exception(...)` before returning a user-friendly response:

- File upload streaming catches `OSError` and returns 507 with a disk-space hint.
- Asynchronous file analysis (`_process_file`) wraps the whole analysis in `try/except Exception`, marks the scan `failed`, and still deletes the temp file in `finally`.
- Email parsing catches `ValueError` and re-renders the email form with the error message.
- DNS lookups in `email_auth.py` catch `dns.resolver.NXDOMAIN`, `NoAnswer`, and `DNSException` individually.
- SQLite connections go through `_connection()`, a context manager that commits on success, rolls back on any exception, and always closes the connection.

### Template convention

All user-facing errors render through `templates/error.html`, which expects four variables: `error_code`, `error_title`, `error_message`, and optionally `retry_after`. The template shows a banner reading `REQUEST NOT COMPLETED · {{ error_code }}` and provides action links back to the scanners. This centralizes the error UI rather than scattering per-route error templates.

### Startup-time failures

`runtime_config.load_settings()` raises `ConfigurationError` for invalid env vars (e.g. `FLASK_SECRET_KEY` too short, `PORT` out of range, negative `MAX_UPLOAD_BYTES`). Because `SETTINGS = load_settings()` runs at module import, a bad configuration kills the process before any request is served — there is no runtime fallback.

## Conventions and Constraints

- **Client validation errors** (bad URLs, expired CSRF tokens, oversized payloads) are represented as `ValueError` subclasses or plain `ValueError`s and converted to HTTP 400 responses with a human-readable message.
- **Server-side failures** bubble up to the global 500 handler, which never leaks the raw exception text to clients — only the logger receives the details.
- **API vs HTML branching** is done uniformly by checking `request.path.startswith("/api/")` inside error handlers and templates, ensuring JSON consumers get JSON and browsers get HTML.
- **Rate limits** consistently return 429 with a `Retry-After` header (via `rate_limited_response`) and a message indicating how long to wait.
- **Access-gated endpoints** return 401 JSON with an `unlock_url` pointing to the passcode entry page.
- **Database transactions** are wrapped in `_connection()` which enforces commit-on-success / rollback-on-failure semantics.
- **File cleanup** is placed in `finally` blocks so temporary uploads are removed even when analysis fails.
- No `panic`/`recover` equivalent exists (Python has no such construct); instead, broad `except Exception` blocks are used sparingly (only in async file analysis) to mark scans failed rather than crash the worker.