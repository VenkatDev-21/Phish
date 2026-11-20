"""Environment-driven runtime configuration resolved once at start-up.

Everything hosting-specific lives here so ``app.py`` can stay focused on
routes. Local development keeps the historical defaults (SQLite inside the
project folder, 127.0.0.1, 5 GiB uploads). A hosted deployment switches on
stricter defaults: a data directory outside the source tree, a much smaller
upload ceiling and a mandatory stable secret key.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off", ""}
DEVELOPMENT_ENVIRONMENTS = {"development", "dev", "local", "test", "testing"}

LOCAL_MAX_UPLOAD_BYTES = 5 * 1024**3
HOSTED_MAX_UPLOAD_BYTES = 100 * 1024**2
DEFAULT_EMAIL_REQUEST_BYTES = 64 * 1024 * 1024
MINIMUM_SECRET_LENGTH = 16


class ConfigurationError(RuntimeError):
    """Raised when an environment variable cannot be used safely."""


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in TRUTHY:
        return True
    if value in FALSY:
        return False
    return default


def _integer(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}.") from error


def _origins() -> tuple[str, ...]:
    raw = os.environ.get("PHISHGUARD_ALLOWED_ORIGINS", "")
    origins = []
    for item in raw.split(","):
        origin = item.strip().rstrip("/")
        if origin and origin not in origins:
            origins.append(origin)
    return tuple(origins)


def _environment() -> str:
    explicit = os.environ.get("PHISHGUARD_ENV", "").strip().lower()
    if explicit:
        return explicit
    if _flag("RENDER") or os.environ.get("RENDER_EXTERNAL_HOSTNAME"):
        return "production"
    if os.environ.get("VERCEL"):
        return "production"
    if os.environ.get("FLASK_DEBUG", "").strip() == "1":
        return "development"
    return "development"


def _data_directory() -> Path:
    configured = os.environ.get("PHISHGUARD_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return PROJECT_DIR


def _secret_key(environment: str) -> tuple[str, bool]:
    configured = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if len(configured) >= MINIMUM_SECRET_LENGTH:
        return configured, False
    if configured:
        raise ConfigurationError(
            "FLASK_SECRET_KEY is too short. Use at least "
            f"{MINIMUM_SECRET_LENGTH} characters, for example the output of "
            "`python -c \"import secrets; print(secrets.token_hex(32))\"`."
        )
    if environment in DEVELOPMENT_ENVIRONMENTS:
        return secrets.token_hex(32), True
    raise ConfigurationError(
        "FLASK_SECRET_KEY must be set before running PhishGuard outside local "
        "development. Generate one with "
        "`python -c \"import secrets; print(secrets.token_hex(32))\"` and add it "
        "as an environment variable. Without a stable key, session cookies and "
        "CSRF tokens break as soon as more than one worker or dyno is running."
    )


@dataclass(frozen=True)
class RuntimeSettings:
    """Immutable snapshot of the resolved configuration."""

    environment: str
    is_production: bool
    behind_proxy: bool
    secret_key: str
    secret_key_is_ephemeral: bool
    data_dir: Path
    database_path: Path
    upload_dir: Path
    max_upload_bytes: int
    max_email_request_bytes: int
    port: int
    host: str
    access_code: str
    allowed_origins: tuple[str, ...]
    rate_limit_enabled: bool
    external_submissions_enabled: bool

    @property
    def access_gate_enabled(self) -> bool:
        return bool(self.access_code)

    @property
    def public_api_enabled(self) -> bool:
        return True


def load_settings() -> RuntimeSettings:
    environment = _environment()
    is_production = environment not in DEVELOPMENT_ENVIRONMENTS
    data_dir = _data_directory()
    secret_key, secret_key_is_ephemeral = _secret_key(environment)

    default_upload = HOSTED_MAX_UPLOAD_BYTES if is_production else LOCAL_MAX_UPLOAD_BYTES
    max_upload_bytes = _integer("MAX_UPLOAD_BYTES", default_upload)
    if max_upload_bytes <= 0:
        raise ConfigurationError("MAX_UPLOAD_BYTES must be a positive integer.")

    max_email_request_bytes = _integer(
        "MAX_EMAIL_REQUEST_BYTES", DEFAULT_EMAIL_REQUEST_BYTES
    )
    if max_email_request_bytes <= 0:
        raise ConfigurationError("MAX_EMAIL_REQUEST_BYTES must be a positive integer.")

    port = _integer("PORT", 5000)
    if not 1 <= port <= 65535:
        raise ConfigurationError("PORT must be an integer between 1 and 65535.")

    behind_proxy = _flag("PHISHGUARD_BEHIND_PROXY", default=is_production)
    host = os.environ.get("HOST", "").strip() or (
        "0.0.0.0" if is_production else "127.0.0.1"
    )

    return RuntimeSettings(
        environment=environment,
        is_production=is_production,
        behind_proxy=behind_proxy,
        secret_key=secret_key,
        secret_key_is_ephemeral=secret_key_is_ephemeral,
        data_dir=data_dir,
        database_path=data_dir / "phishguard.db",
        upload_dir=data_dir / "uploads",
        max_upload_bytes=max_upload_bytes,
        max_email_request_bytes=max_email_request_bytes,
        port=port,
        host=host,
        access_code=os.environ.get("PHISHGUARD_ACCESS_CODE", "").strip(),
        allowed_origins=_origins() or ("*",),
        rate_limit_enabled=_flag("PHISHGUARD_RATE_LIMIT", default=True),
        external_submissions_enabled=_flag(
            "PHISHGUARD_EXTERNAL_SUBMISSIONS", default=True
        ),
    )


SETTINGS = load_settings()
