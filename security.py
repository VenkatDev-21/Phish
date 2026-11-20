"""Request hardening shared by every route.

Three concerns live here so they cannot be forgotten on a new endpoint:

* response headers (CSP, framing, referrer, HSTS, no-store on private pages),
* a small in-process rate limiter for expensive scans,
* the optional shared-passcode gate in front of stored scan history.

The limiter is intentionally in-process. It is enough to blunt accidental
loops and casual abuse on a single instance; a multi-instance deployment
should put a real limiter (for example a Cloudflare rule or Redis) in front.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass

from flask import Flask, jsonify, redirect, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from runtime_config import RuntimeSettings


PROTECTED_PREFIXES = ("/dashboard", "/history", "/authentication", "/api/dashboard")
PRIVATE_PREFIXES = PROTECTED_PREFIXES + ("/email/", "/files/", "/urls/")
ACCESS_SESSION_KEY = "phishguard_access_granted"
UNLOCK_ENDPOINT = "unlock"

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    )
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


@dataclass(frozen=True)
class RateRule:
    """``limit`` requests allowed per ``window_seconds`` for one client."""

    limit: int
    window_seconds: int
    scope: str = ""

    def __post_init__(self) -> None:
        if self.limit <= 0 or self.window_seconds <= 0:
            raise ValueError("Rate limits need a positive limit and window.")


class RateLimiter:
    """Sliding-window limiter keyed by client address and rule name."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}

    def retry_after(self, client: str, rule: RateRule, name: str) -> int:
        """Return 0 when the request is allowed, else seconds until retry."""

        now = time.monotonic()
        bucket_key = f"{name}:{rule.scope}:{client}"
        window = rule.window_seconds
        with self._lock:
            events = self._events.setdefault(bucket_key, deque())
            while events and now - events[0] >= window:
                events.popleft()
            if len(events) >= rule.limit:
                return max(1, int(round(window - (now - events[0]))))
            events.append(now)
            if not events:
                self._events.pop(bucket_key, None)
        return 0

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


LIMITER = RateLimiter()


def client_address() -> str:
    """Best-effort client identity for rate limiting."""

    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.remote_addr or "unknown"


def is_private_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in PRIVATE_PREFIXES
    )


def access_required(path: str) -> bool:
    """True when ``path`` must sit behind the shared passcode."""

    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in PROTECTED_PREFIXES
    )


def access_granted() -> bool:
    """True when the gate is disabled or this session already unlocked it."""

    if not session.get(ACCESS_SESSION_KEY):
        return False
    return True


def grant_access(submitted: str) -> bool:
    expected = _access_code()
    if not expected or not submitted:
        return False
    if not secrets.compare_digest(submitted.strip(), expected):
        return False
    session[ACCESS_SESSION_KEY] = True
    return True


def revoke_access() -> None:
    session.pop(ACCESS_SESSION_KEY, None)


def _access_code() -> str:
    from flask import current_app

    return str(current_app.config.get("ACCESS_CODE", "") or "")


def safe_next(target: str | None) -> str | None:
    """Return ``target`` only when it is a local, single-slash path."""

    if not target:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    best = request.accept_mimetypes.best
    return best == "application/json" and (
        request.accept_mimetypes[best]
        > request.accept_mimetypes["text/html"]
    )


def _enforce_access():
    from flask import current_app

    if not current_app.config.get("ACCESS_CODE"):
        return None
    if not access_required(request.path):
        return None
    if request.endpoint in {UNLOCK_ENDPOINT, "static"}:
        return None
    if access_granted():
        return None

    if _wants_json():
        return (
            jsonify(
                error="This deployment protects saved scan history with an access code.",
                unlock_url=url_for(UNLOCK_ENDPOINT, next=request.full_path),
            ),
            401,
        )
    return redirect(url_for(UNLOCK_ENDPOINT, next=request.full_path))


def _add_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)

    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    if is_private_path(request.path):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")

    # The public JSON API is consumed by the static Vercel front-end.
    if request.path.startswith("/api/v1"):
        allowed = _cors_origin()
        if allowed:
            response.headers["Access-Control-Allow-Origin"] = allowed
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
            response.headers["Vary"] = "Origin"
    return response


def _cors_origin() -> str | None:
    from flask import current_app

    origins = current_app.config.get("ALLOWED_ORIGINS") or ()
    origin = request.headers.get("Origin")
    if "*" in origins:
        return "*"
    if origin and origin.rstrip("/") in origins:
        return origin
    return None


def _cors_preflight():
    if request.method != "OPTIONS" or not request.path.startswith("/api/v1"):
        return None
    from flask import current_app

    return current_app.response_class(status=204)


def configure_security(app: Flask, settings: RuntimeSettings) -> None:
    """Attach proxy trust, the access gate and response headers."""

    if settings.behind_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.before_request(_cors_preflight)
    app.before_request(_enforce_access)
    app.after_request(_add_security_headers)


def rate_limited_response(retry_after: int, message: str):
    """Standard 429 body with a ``Retry-After`` header."""

    response = jsonify(error=message, retry_after=retry_after)
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response
