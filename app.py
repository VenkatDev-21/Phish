import hashlib
import csv
import io
import json
import os
import secrets
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from feature_extraction import extract_features
from runtime_config import PROJECT_DIR, SETTINGS
from security import (
    LIMITER,
    RateRule,
    client_address,
    configure_security,
    grant_access,
    rate_limited_response,
    revoke_access,
    safe_next,
)
from email_security import (
    MAX_EMAIL_ATTACHMENTS,
    MAX_EMAIL_CHARACTERS,
    MAX_EMAIL_UPLOAD_BYTES,
    analyze_email,
    parse_email_upload,
)
from email_attachment_analysis import MAX_ATTACHMENT_BYTES
from file_analysis import (
    analyze_file,
    get_scanner_configuration,
    summarize_file_verdict,
)
from soc_dashboard import (
    DashboardQueryError,
    INCIDENT_STATUSES,
    get_activity,
    get_authentication_statistics,
    get_email_statistics,
    get_file_statistics,
    get_incidents,
    get_recent_events,
    get_search_results,
    get_summary,
    get_threat_distribution,
    get_threat_intelligence,
    get_top_indicators,
    get_url_statistics,
    parse_date_range,
    register_sql_functions,
    sync_incidents,
)


DATABASE = SETTINGS.database_path
APP_STARTED_MONOTONIC = time.monotonic()
CHUNK_SIZE = 1024 * 1024
MAX_EMAIL_REQUEST_BYTES = SETTINGS.max_email_request_bytes
MAX_URL_LENGTH = 4096

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SETTINGS.secret_key,
    DATABASE=str(SETTINGS.database_path),
    UPLOAD_DIR=str(SETTINGS.upload_dir),
    MAX_UPLOAD_BYTES=SETTINGS.max_upload_bytes,
    PORT=SETTINGS.port,
    ENVIRONMENT=SETTINGS.environment,
    IS_PRODUCTION=SETTINGS.is_production,
    ACCESS_CODE=SETTINGS.access_code,
    ALLOWED_ORIGINS=SETTINGS.allowed_origins,
    RATE_LIMIT_ENABLED=SETTINGS.rate_limit_enabled,
    EXTERNAL_SUBMISSIONS_ENABLED=SETTINGS.external_submissions_enabled,
)
app.config["MAX_CONTENT_LENGTH"] = max(
    app.config["MAX_UPLOAD_BYTES"], MAX_EMAIL_REQUEST_BYTES
) + 2 * 1024**2
app.config["MAX_FORM_MEMORY_SIZE"] = 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = SETTINGS.is_production

configure_security(app, SETTINGS)

RATE_RULES = {
    "url_scan": RateRule(limit=40, window_seconds=300, scope="scan"),
    "file_upload": RateRule(limit=12, window_seconds=3600, scope="upload"),
    "email_analysis": RateRule(limit=25, window_seconds=1800, scope="email"),
    "dashboard": RateRule(limit=600, window_seconds=300, scope="dashboard"),
    "public_api": RateRule(limit=60, window_seconds=300, scope="api"),
    "unlock": RateRule(limit=6, window_seconds=900, scope="unlock"),
}

file_scan_executor = ThreadPoolExecutor(
    max_workers=max(1, int(os.environ.get("FILE_SCAN_WORKERS", "2"))),
    thread_name_prefix="file-scan",
)


def _connect():
    connection = sqlite3.connect(app.config["DATABASE"], timeout=30)
    connection.row_factory = sqlite3.Row
    register_sql_functions(connection)
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    interrupted_scans = []
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                probability REAL NOT NULL,
                risk_level TEXT NOT NULL,
                scan_time TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_scans (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                file_type TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                results_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_scans (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                results_json TEXT NOT NULL,
                scan_time TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_incidents (
                id TEXT PRIMARY KEY,
                source_type TEXT NOT NULL
                    CHECK (source_type IN ('url', 'file', 'email')),
                source_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
                entity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New'
                    CHECK (status IN (
                        'New', 'Investigating', 'Contained', 'Resolved',
                        'False Positive'
                    )),
                assigned_analyst TEXT NOT NULL DEFAULT '',
                first_detected TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                UNIQUE (source_type, source_id)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_scan_time ON scans(scan_time)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_result_time "
            "ON scans(result, scan_time)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_scans_created_at "
            "ON file_scans(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_scans_sha256 "
            "ON file_scans(sha256)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_scans_status_time "
            "ON file_scans(status, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_scans_scan_time "
            "ON email_scans(scan_time)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_scans_risk_time "
            "ON email_scans(risk_score, scan_time)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_incidents_time "
            "ON security_incidents(first_detected)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_incidents_severity "
            "ON security_incidents(severity, status, first_detected)"
        )
        interrupted_scans = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM file_scans WHERE status IN ('queued', 'scanning')"
            ).fetchall()
        ]
        conn.execute("""
            UPDATE file_scans
            SET status = 'failed',
                message = 'The server restarted before this analysis finished. Please resubmit the file.',
                updated_at = ?
            WHERE status IN ('queued', 'scanning')
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
    for scan_id in interrupted_scans:
        stale_file = Path(app.config["UPLOAD_DIR"]) / f"{scan_id}.upload"
        try:
            stale_file.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove interrupted upload %s", scan_id)


init_db()


def _csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _csrf_is_valid(value):
    expected = session.get("_csrf_token", "")
    return bool(value and expected and secrets.compare_digest(value, expected))


def _rate_limit_blocked(name, *, as_json=False, message=None):
    """Return a ready-made 429 response, or ``None`` when allowed."""

    if not app.config.get("RATE_LIMIT_ENABLED", True):
        return None
    if app.config.get("TESTING") and not app.config.get("RATE_LIMIT_IN_TESTS"):
        return None
    retry_after = LIMITER.retry_after(client_address(), RATE_RULES[name], name)
    if not retry_after:
        return None
    detail = message or (
        f"Too many requests. Try again in {retry_after} seconds."
    )
    if as_json:
        return rate_limited_response(retry_after, detail)
    return render_template(
        "error.html",
        error_code=429,
        error_title="Slow down for a moment",
        error_message=detail,
        retry_after=retry_after,
    ), 429


class UrlValidationError(ValueError):
    """Raised when a submitted URL cannot be scored safely."""


def normalize_url(raw_value):
    """Validate a submitted URL without ever resolving or fetching it."""

    url = (raw_value or "").strip()
    if not url:
        raise UrlValidationError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise UrlValidationError(
            f"URLs must be {MAX_URL_LENGTH:,} characters or fewer."
        )
    if any(character.isspace() for character in url):
        raise UrlValidationError("Remove spaces from the URL before scanning.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UrlValidationError(
            "Enter a valid URL starting with http:// or https://"
        )
    return url


def classify_url(url):
    """Score one URL; shared by the HTML form and the public JSON API."""

    features = extract_features(url)
    frame = pd.DataFrame([features])
    prediction = model.predict(frame)[0]
    probabilities = model.predict_proba(frame)[0]
    class_names = list(model.classes_)
    phishing_index = class_names.index("phishing") if "phishing" in class_names else 1
    probability = round(float(probabilities[phishing_index] * 100), 2)

    if str(prediction).lower() == "phishing" or prediction == 1:
        result, risk_level = "PHISHING", "High"
    else:
        result, risk_level = "LEGITIMATE", "Low"

    return {
        "url": url,
        "result": result,
        "risk_level": risk_level,
        "probability": probability,
        "features": features,
    }


def save_scan(url, result, probability, risk_level):
    with _connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (url, result, probability, risk_level, scan_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            url,
            result,
            probability,
            risk_level,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        return cursor.lastrowid


def _save_file_scan(scan_id, status, message, results=None, file_type=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connection() as conn:
        conn.execute("""
            UPDATE file_scans
            SET status = ?, message = ?, results_json = ?, updated_at = ?,
                file_type = COALESCE(?, file_type)
            WHERE id = ?
        """, (
            status,
            message,
            json.dumps(results or {}),
            now,
            file_type,
            scan_id,
        ))


def _process_file(scan_id, file_path, filename, file_size, sha256, consent):
    try:
        _save_file_scan(scan_id, "scanning", "Local and selected provider checks are running.")
        results = analyze_file(
            file_path, filename, file_size, sha256, consent
        )
        results["sha256"] = sha256
        _save_file_scan(
            scan_id,
            "complete",
            "Analysis steps finished.",
            results,
            results.get("file_type"),
        )
    except Exception:
        app.logger.exception("File analysis failed for scan %s", scan_id)
        _save_file_scan(
            scan_id,
            "failed",
            "Analysis failed unexpectedly. Check the server log for details.",
        )
    finally:
        try:
            Path(file_path).unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove temporary file for scan %s", scan_id)


def _scan_record(scan_id):
    with _connection() as conn:
        return conn.execute(
            "SELECT * FROM file_scans WHERE id = ?", (scan_id,)
        ).fetchone()


def _file_scan_view(scan):
    values = dict(scan)
    values["results"] = json.loads(values.pop("results_json") or "{}")
    values["results"]["verdict"] = summarize_file_verdict(
        values["results"].get("engines", [])
    )
    return values


@app.route("/")
def home():
    return render_template("index.html", csrf_token=_csrf_token())


@app.route("/predict", methods=["POST"])
def predict():
    limited = _rate_limit_blocked(
        "url_scan",
        message="Too many URL analyses from this address. Wait a moment and try again.",
    )
    if limited:
        return limited

    if not _csrf_is_valid(request.form.get("csrf_token")):
        return render_template(
            "result.html",
            error="The form expired. Reload the page and try again.",
        ), 400

    try:
        url = normalize_url(request.form.get("url", ""))
    except UrlValidationError as error:
        return render_template("result.html", error=str(error)), 400

    report = classify_url(url)
    save_scan(url, report["result"], report["probability"], report["risk_level"])
    return render_template("result.html", **report)


@app.route("/urls/<int:scan_id>")
def url_scan_result(scan_id):
    with _connection() as conn:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if scan is None:
        return render_template(
            "result.html",
            error="URL analysis was not found.",
        ), 404
    return render_template(
        "result.html",
        url=scan["url"],
        result=scan["result"],
        risk_level=scan["risk_level"],
        probability=scan["probability"],
        features=extract_features(scan["url"]),
        scanned_at=scan["scan_time"],
    )


@app.route("/api/v1/scan/url", methods=["POST"])
def api_scan_url():
    limited = _rate_limit_blocked(
        "public_api",
        as_json=True,
        message="Too many API scans from this address. Wait a moment and try again.",
    )
    if limited:
        return limited

    payload = request.get_json(silent=True)
    if payload is None and request.form:
        payload = request.form.to_dict()
    if payload is None:
        return jsonify(
            error='Send a JSON body such as {"url": "https://example.com"}.'
        ), 400
    if not isinstance(payload, dict):
        return jsonify(error='Send a JSON object with a "url" field.'), 400

    try:
        url = normalize_url(payload.get("url", ""))
    except UrlValidationError as error:
        return jsonify(error=str(error)), 400

    report = classify_url(url)
    scan_id = save_scan(
        url, report["result"], report["probability"], report["risk_level"]
    )
    return jsonify(
        scan_id=scan_id,
        scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        engine="phishguard-url-random-forest",
        disclaimer=(
            "Structural model output only. The URL was never opened and no "
            "reputation service was queried."
        ),
        **report,
    ), 201


@app.route("/healthz")
def healthz():
    """Small probe used by Render and any external uptime monitor."""

    database_state = "ok"
    try:
        with _connection() as conn:
            conn.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        app.logger.exception("Health check could not read the database")
        database_state = "error"

    model_state = "loaded" if globals().get("model") is not None else "unavailable"
    healthy = database_state == "ok" and model_state == "loaded"
    return jsonify(
        status="ok" if healthy else "degraded",
        environment=app.config["ENVIRONMENT"],
        database=database_state,
        model=model_state,
        uptime_seconds=int(time.monotonic() - APP_STARTED_MONOTONIC),
    ), (200 if healthy else 503)


@app.route("/api/v1/health")
def api_health():
    return jsonify(
        status="ok",
        service="phishguard",
        environment=app.config["ENVIRONMENT"],
        capabilities={
            "url_scan": {"endpoint": "/api/v1/scan/url", "method": "POST"},
            "url_features": list(extract_features("https://example.com/").keys()),
        },
        limits={
            "max_url_length": MAX_URL_LENGTH,
            "max_upload_bytes": app.config["MAX_UPLOAD_BYTES"],
            "max_email_request_bytes": MAX_EMAIL_REQUEST_BYTES,
            "public_api": {
                "requests": RATE_RULES["public_api"].limit,
                "window_seconds": RATE_RULES["public_api"].window_seconds,
            },
        },
        history_gate=bool(app.config.get("ACCESS_CODE")),
    )


@app.route("/api")
def api_docs():
    return render_template(
        "api_docs.html",
        features=list(extract_features("https://example.com/").keys()),
        api_rule=RATE_RULES["public_api"],
        max_upload_bytes=app.config["MAX_UPLOAD_BYTES"],
        max_url_length=MAX_URL_LENGTH,
        csrf_token=_csrf_token(),
    )


@app.route("/robots.txt")
def robots_txt():
    disallowed = (
        "/dashboard",
        "/history",
        "/authentication",
        "/api/",
        "/email/",
        "/files/",
        "/urls/",
        "/unlock",
    )
    body = "\n".join(
        ["User-agent: *", "Allow: /", *(f"Disallow: {path}" for path in disallowed), ""]
    )
    return app.response_class(body, mimetype="text/plain")


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if not app.config.get("ACCESS_CODE"):
        return redirect(url_for("dashboard"))

    target = safe_next(request.values.get("next"))
    error = None
    if request.method == "POST":
        limited = _rate_limit_blocked(
            "unlock", message="Too many access-code attempts. Try again later."
        )
        if limited:
            return limited
        if not _csrf_is_valid(request.form.get("csrf_token")):
            error = "The form expired. Reload the page and try again."
        elif grant_access(request.form.get("access_code", "")):
            return redirect(target or url_for("dashboard"))
        else:
            app.logger.warning(
                "Rejected access-code attempt from %s", client_address()
            )
            error = "That access code is not valid."

    return render_template(
        "unlock.html",
        csrf_token=_csrf_token(),
        error=error,
        next=target or "",
    ), (400 if error else 200)


@app.route("/lock", methods=["POST"])
def lock():
    if _csrf_is_valid(request.form.get("csrf_token")):
        revoke_access()
    return redirect(url_for("home"))


@app.route("/files")
def file_scanner():
    return render_template(
        "file_scan.html",
        csrf_token=_csrf_token(),
        scanner_configuration=get_scanner_configuration(),
        max_upload_bytes=app.config["MAX_UPLOAD_BYTES"],
        max_upload_label=f"{app.config['MAX_UPLOAD_BYTES'] / 1024**3:g} GiB",
    )


@app.route("/files/scan", methods=["POST"])
def upload_file():
    limited = _rate_limit_blocked(
        "file_upload",
        as_json=True,
        message="Too many file uploads from this address. Try again later.",
    )
    if limited:
        return limited

    if not _csrf_is_valid(request.headers.get("X-CSRF-Token")):
        return jsonify(error="The form expired. Reload the page and try again."), 400

    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify(error="Choose a file to analyze."), 400

    filename = secure_filename(upload.filename)[:180] or "uploaded-file"
    scan_id = uuid.uuid4().hex
    upload_dir = Path(app.config["UPLOAD_DIR"])
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        app.logger.exception("Could not create file upload directory")
        return jsonify(error="The upload directory is unavailable."), 507
    file_path = upload_dir / f"{scan_id}.upload"
    digest = hashlib.sha256()
    file_size = 0

    try:
        with file_path.open("xb") as destination:
            while True:
                chunk = upload.stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > app.config["MAX_UPLOAD_BYTES"]:
                    destination.close()
                    file_path.unlink(missing_ok=True)
                    return jsonify(
                        error=f"The file exceeds the {app.config['MAX_UPLOAD_BYTES'] / 1024**3:g} GiB upload limit."
                    ), 413
                digest.update(chunk)
                destination.write(chunk)
    except OSError:
        app.logger.exception("Could not store uploaded file")
        file_path.unlink(missing_ok=True)
        return jsonify(error="The upload could not be stored. Check available disk space."), 507

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sha256 = digest.hexdigest()
    try:
        with _connection() as conn:
            conn.execute("""
                INSERT INTO file_scans
                (id, filename, file_size, sha256, file_type, status, message,
                 results_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'queued', 'Queued for analysis.', '{}', ?, ?)
            """, (
                scan_id,
                filename,
                file_size,
                sha256,
                "Pending identification",
                now,
                now,
            ))
        file_scan_executor.submit(
            _process_file,
            scan_id,
            str(file_path),
            filename,
            file_size,
            sha256,
            request.form.get("external_consent") == "on"
            and app.config["EXTERNAL_SUBMISSIONS_ENABLED"],
        )
    except Exception:
        app.logger.exception("Could not queue file analysis %s", scan_id)
        file_path.unlink(missing_ok=True)
        with _connection() as conn:
            conn.execute("DELETE FROM file_scans WHERE id = ?", (scan_id,))
        return jsonify(error="The analysis could not be queued. Please try again."), 503

    return jsonify(url=url_for("file_scan_result", scan_id=scan_id)), 202


@app.route("/files/<scan_id>")
def file_scan_result(scan_id):
    scan = _scan_record(scan_id)
    if scan is None:
        return render_template("result.html", error="File analysis was not found."), 404
    return render_template("file_result.html", scan=_file_scan_view(scan))


@app.route("/api/files/<scan_id>")
def file_scan_status(scan_id):
    scan = _scan_record(scan_id)
    if scan is None:
        return jsonify(error="File analysis was not found."), 404
    values = _file_scan_view(scan)
    return jsonify({
        "status": values["status"],
        "message": values["message"],
        "updated_at": values["updated_at"],
        "results": values["results"],
    })


def _email_scan_record(scan_id):
    with _connection() as conn:
        return conn.execute(
            "SELECT * FROM email_scans WHERE id = ?", (scan_id,)
        ).fetchone()


@app.route("/email")
def email_scanner():
    return render_template(
        "email_scan.html",
        csrf_token=_csrf_token(),
        max_email_characters=MAX_EMAIL_CHARACTERS,
        max_email_upload_bytes=MAX_EMAIL_UPLOAD_BYTES,
        max_attachment_bytes=MAX_ATTACHMENT_BYTES,
        max_email_request_bytes=MAX_EMAIL_REQUEST_BYTES,
    )


@app.route("/email/analyze", methods=["POST"])
def analyze_pasted_email():
    request.max_content_length = MAX_EMAIL_REQUEST_BYTES
    limited = _rate_limit_blocked(
        "email_analysis",
        message="Too many email analyses from this address. Try again later.",
    )
    if limited:
        return limited
    if request.content_length and request.content_length > MAX_EMAIL_REQUEST_BYTES:
        return render_template(
            "email_scan.html",
            csrf_token=_csrf_token(),
            max_email_characters=MAX_EMAIL_CHARACTERS,
            max_email_upload_bytes=MAX_EMAIL_UPLOAD_BYTES,
            max_attachment_bytes=MAX_ATTACHMENT_BYTES,
            max_email_request_bytes=MAX_EMAIL_REQUEST_BYTES,
            error=(
                f"Email requests must be {MAX_EMAIL_REQUEST_BYTES // (1024 * 1024)} MiB "
                "or smaller."
            ),
        ), 413

    if not _csrf_is_valid(request.form.get("csrf_token")):
        return render_template(
            "email_scan.html",
            csrf_token=_csrf_token(),
            max_email_characters=MAX_EMAIL_CHARACTERS,
            max_email_upload_bytes=MAX_EMAIL_UPLOAD_BYTES,
            max_attachment_bytes=MAX_ATTACHMENT_BYTES,
            max_email_request_bytes=MAX_EMAIL_REQUEST_BYTES,
            error="The form expired. Reload the page and try again.",
        ), 400

    text = request.form.get("email_content", "")
    uploaded_email = request.files.get("email_file")
    parsed_message = None
    separate_attachments = []
    try:
        if uploaded_email and uploaded_email.filename:
            email_bytes = uploaded_email.stream.read(MAX_EMAIL_UPLOAD_BYTES + 1)
            if len(email_bytes) > MAX_EMAIL_UPLOAD_BYTES:
                raise ValueError(
                    f"Email files must be {MAX_EMAIL_UPLOAD_BYTES // (1024 * 1024)} MiB or smaller."
                )
            parsed_message = parse_email_upload(
                uploaded_email.filename, email_bytes
            )
            text = ""

        upload_files = [
            item for item in request.files.getlist("attachments")
            if item and item.filename
        ]
        if len(upload_files) > MAX_EMAIL_ATTACHMENTS:
            raise ValueError(
                f"Upload no more than {MAX_EMAIL_ATTACHMENTS} separate attachments."
            )
        for attachment in upload_files:
            data = attachment.stream.read(MAX_ATTACHMENT_BYTES + 1)
            if len(data) > MAX_ATTACHMENT_BYTES:
                raise ValueError(
                    f"Each separate attachment must be {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MiB or smaller."
                )
            separate_attachments.append({
                "filename": secure_filename(attachment.filename) or "attachment",
                "data": data,
                "mime_type": attachment.mimetype,
            })

        results = analyze_email(
            text,
            url_model=model,
            dns_lookup=request.form.get("dns_lookup") == "on",
            attachments=separate_attachments,
            parsed_message=parsed_message,
            external_consent=request.form.get("external_consent") == "on"
            and app.config["EXTERNAL_SUBMISSIONS_ENABLED"],
        )
    except ValueError as error:
        with _connection() as conn:
            recent_scans = conn.execute("""
                SELECT id, subject, sender, risk_score, risk_level, scan_time
                FROM email_scans ORDER BY scan_time DESC LIMIT 8
            """).fetchall()
        return render_template(
            "email_scan.html",
            csrf_token=_csrf_token(),
            recent_scans=recent_scans,
            max_email_characters=MAX_EMAIL_CHARACTERS,
            max_email_upload_bytes=MAX_EMAIL_UPLOAD_BYTES,
            max_attachment_bytes=MAX_ATTACHMENT_BYTES,
            max_email_request_bytes=MAX_EMAIL_REQUEST_BYTES,
            error=str(error),
        ), 400

    scan_id = uuid.uuid4().hex
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connection() as conn:
        conn.execute("""
            INSERT INTO email_scans
            (id, subject, sender, risk_score, risk_level, results_json, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            results["subject"],
            results["sender"],
            results["risk_score"],
            results["risk_level"],
            json.dumps(results),
            scan_time,
        ))
    return redirect(url_for("email_scan_result", scan_id=scan_id))


@app.route("/email/<scan_id>")
def email_scan_result(scan_id):
    scan = _email_scan_record(scan_id)
    if scan is None:
        return render_template(
            "email_result.html",
            error="Email analysis was not found.",
        ), 404
    return render_template(
        "email_result.html",
        scan_id=scan["id"],
        scan_time=scan["scan_time"],
        results=json.loads(scan["results_json"]),
    )


@app.route("/email/<scan_id>/export.json")
def export_email_scan(scan_id):
    scan = _email_scan_record(scan_id)
    if scan is None:
        return jsonify(error="Email analysis was not found."), 404
    response = jsonify({
        "scan_id": scan["id"],
        "scan_time": scan["scan_time"],
        "results": json.loads(scan["results_json"]),
    })
    response.headers["Content-Disposition"] = (
        f'attachment; filename="phishguard-email-{scan_id}.json"'
    )
    return response


@app.route("/api/email/health")
def email_health():
    return jsonify({
        "status": "available",
        "inputs": ["paste", ".eml", ".txt", ".html", ".htm"],
        "separate_attachment_limit": MAX_EMAIL_ATTACHMENTS,
        "attachment_size_limit_bytes": MAX_ATTACHMENT_BYTES,
        "dns_lookup": "optional per analysis",
        "external_submission": "explicit per-analysis consent required",
    })


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", csrf_token=_csrf_token())


@app.route("/authentication")
def authentication_analysis():
    return render_template(
        "authentication_analysis.html", csrf_token=_csrf_token()
    )


def _dashboard_api(handler, sync=False):
    limited = _rate_limit_blocked(
        "dashboard",
        as_json=True,
        message="Too many dashboard requests. Wait a moment and try again.",
    )
    if limited:
        return limited
    try:
        date_range = parse_date_range(request.args)
        with _connection() as conn:
            if sync:
                sync_incidents(conn)
            return jsonify(handler(conn, date_range))
    except DashboardQueryError as error:
        return jsonify(error=str(error)), 400
    except sqlite3.Error:
        app.logger.exception("Dashboard query failed")
        return jsonify(error="Dashboard data could not be read."), 503


@app.route("/api/dashboard/summary")
def dashboard_summary_api():
    return _dashboard_api(get_summary, sync=True)


@app.route("/api/dashboard/activity")
def dashboard_activity_api():
    return _dashboard_api(
        lambda conn, date_range: get_activity(
            conn, date_range, request.args.get("bucket", "1h")
        )
    )


@app.route("/api/dashboard/threat-distribution")
def dashboard_threat_distribution_api():
    return _dashboard_api(get_threat_distribution)


@app.route("/api/dashboard/recent-events")
def dashboard_recent_events_api():
    return _dashboard_api(
        lambda conn, date_range: get_recent_events(
            conn,
            date_range,
            search=request.args.get("q", ""),
            severity=request.args.get("severity", "all"),
            event_type=request.args.get("event_type", "all"),
            source_type=request.args.get("source", "all"),
            page=request.args.get("page", 1),
            page_size=request.args.get("page_size", 25),
            sort=request.args.get("sort", "desc"),
        ),
        sync=True,
    )


@app.route("/api/dashboard/recent-events.csv")
def dashboard_recent_events_csv():
    try:
        date_range = parse_date_range(request.args)
        with _connection() as conn:
            sync_incidents(conn)
            data = get_recent_events(
                conn,
                date_range,
                search=request.args.get("q", ""),
                severity=request.args.get("severity", "all"),
                event_type=request.args.get("event_type", "all"),
                source_type=request.args.get("source", "all"),
                page=1,
                page_size=1000,
                sort=request.args.get("sort", "desc"),
            )
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow([
            "Timestamp", "Event ID", "Event Type", "Source Type", "Source",
            "Category", "Risk Score", "Severity", "Detection Engine", "Status",
            "Investigation URL",
        ])
        for event in data["events"]:
            writer.writerow([
                event["timestamp"],
                event["event_id"],
                event["event_type"],
                event["source_type"],
                event["source"],
                event["category"],
                event["risk_score"],
                event["severity"],
                event["engine"],
                event["status"],
                event["investigation_url"],
            ])
        return app.response_class(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="phishguard-events.csv"',
                "X-Total-Events": str(data["total"]),
                "X-Export-Truncated": str(data["total"] > len(data["events"])).lower(),
            },
        )
    except DashboardQueryError as error:
        return jsonify(error=str(error)), 400
    except sqlite3.Error:
        app.logger.exception("Dashboard event export failed")
        return jsonify(error="Dashboard event data could not be read."), 503


@app.route("/api/dashboard/email-statistics")
def dashboard_email_statistics_api():
    return _dashboard_api(
        lambda conn, date_range: get_email_statistics(
            conn,
            date_range,
            page=request.args.get("page", 1),
            page_size=request.args.get("page_size", 10),
            search=request.args.get("q", ""),
        )
    )


@app.route("/api/dashboard/url-statistics")
def dashboard_url_statistics_api():
    return _dashboard_api(
        lambda conn, date_range: get_url_statistics(
            conn,
            date_range,
            page=request.args.get("page", 1),
            page_size=request.args.get("page_size", 10),
        )
    )


@app.route("/api/dashboard/file-statistics")
def dashboard_file_statistics_api():
    return _dashboard_api(
        lambda conn, date_range: get_file_statistics(
            conn,
            date_range,
            page=request.args.get("page", 1),
            page_size=request.args.get("page_size", 10),
        )
    )


@app.route("/api/dashboard/authentication-statistics")
def dashboard_authentication_statistics_api():
    return _dashboard_api(get_authentication_statistics)


@app.route("/api/dashboard/threat-intelligence")
def dashboard_threat_intelligence_api():
    return _dashboard_api(
        lambda conn, date_range: get_threat_intelligence(
            conn, date_range, get_scanner_configuration()
        )
    )


@app.route("/api/dashboard/incidents")
def dashboard_incidents_api():
    return _dashboard_api(
        lambda conn, date_range: get_incidents(
            conn,
            date_range,
            status=request.args.get("status", "all"),
            page=request.args.get("page", 1),
            page_size=request.args.get("page_size", 25),
        ),
        sync=True,
    )


@app.route("/api/dashboard/incidents/<incident_id>", methods=["PATCH"])
def update_security_incident(incident_id):
    if not _csrf_is_valid(request.headers.get("X-CSRF-Token")):
        return jsonify(error="The form expired. Reload the page and try again."), 400
    values = request.get_json(silent=True)
    if not isinstance(values, dict):
        return jsonify(error="Provide a JSON object with incident updates."), 400
    status = values.get("status")
    analyst = values.get("assigned_analyst")
    if status is not None and status not in INCIDENT_STATUSES:
        return jsonify(error="Unknown incident status."), 400
    if analyst is not None:
        if not isinstance(analyst, str) or len(analyst.strip()) > 80:
            return jsonify(error="Analyst names must be 80 characters or fewer."), 400
        analyst = analyst.strip()
    if status is None and analyst is None:
        return jsonify(error="No incident fields were provided."), 400

    try:
        with _connection() as conn:
            incident = conn.execute(
                "SELECT * FROM security_incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if incident is None:
                return jsonify(error="Security incident was not found."), 404
            conn.execute("""
                UPDATE security_incidents
                SET status = COALESCE(?, status),
                    assigned_analyst = COALESCE(?, assigned_analyst),
                    last_updated = ?
                WHERE id = ?
            """, (
                status,
                analyst,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                incident_id,
            ))
            updated = conn.execute(
                "SELECT * FROM security_incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
        return jsonify(dict(updated))
    except sqlite3.Error:
        app.logger.exception("Could not update security incident %s", incident_id)
        return jsonify(error="The incident could not be updated."), 503


@app.route("/api/dashboard/system-health")
def dashboard_system_health_api():
    def health(conn, date_range):
        conn.execute("SELECT 1").fetchone()
        configuration = get_scanner_configuration()
        model_ready = bool(globals().get("model")) and (
            PROJECT_DIR / "models" / "phishing_model.pkl"
        ).is_file()
        latest = conn.execute("""
            SELECT MAX(scan_time) FROM (
                SELECT scan_time FROM scans
                UNION ALL
                SELECT created_at AS scan_time FROM file_scans
                UNION ALL
                SELECT scan_time FROM email_scans
            )
            WHERE scan_time >= ? AND scan_time < ?
        """, (date_range["start"], date_range["end"])).fetchone()[0]
        failed = conn.execute("""
            SELECT COUNT(*) FROM file_scans
            WHERE status = 'failed' AND created_at >= ? AND created_at < ?
        """, (date_range["start"], date_range["end"])).fetchone()[0]
        pending = conn.execute("""
            SELECT COUNT(*) FROM file_scans
            WHERE status IN ('queued', 'scanning')
              AND created_at >= ? AND created_at < ?
        """, (date_range["start"], date_range["end"])).fetchone()[0]
        integrations = {
            entry["provider"]: entry["configured"]
            for entry in configuration
        }
        services = [
            {"name": "Flask application", "status": "operational"},
            {"name": "SQLite database", "status": "operational"},
            {
                "name": "URL model",
                "status": "operational" if model_ready else "unavailable",
            },
            {"name": "Email parser", "status": "operational"},
            {"name": "Public DNS", "status": "available · not live-tested"},
            {
                "name": "ClamAV",
                "status": "configured" if integrations.get("ClamAV") else "not configured",
            },
            {
                "name": "VirusTotal",
                "status": (
                    "configured · connectivity not tested"
                    if integrations.get("VirusTotal")
                    else "not configured"
                ),
            },
            {
                "name": "OPSWAT MetaDefender",
                "status": (
                    "configured · connectivity not tested"
                    if integrations.get("OPSWAT MetaDefender")
                    else "not configured"
                ),
            },
        ]
        return {
            "range": {"start": date_range["start"], "end": date_range["end"]},
            "services": services,
            "last_scan": latest,
            "failed_scans": int(failed),
            "pending_scans": int(pending),
            "uptime_seconds": int(time.monotonic() - APP_STARTED_MONOTONIC),
            "note": (
                "Provider credentials and DNS support are not live-connectivity "
                "checks. The local app has no user-account system."
            ),
        }

    return _dashboard_api(health)


@app.route("/api/dashboard/top-indicators")
def dashboard_top_indicators_api():
    return _dashboard_api(get_top_indicators)


@app.route("/api/dashboard/search")
def dashboard_search_api():
    return _dashboard_api(
        lambda conn, date_range: get_search_results(
            conn,
            date_range,
            request.args.get("q", ""),
            limit=request.args.get("limit", 30),
        ),
        sync=True,
    )


@app.route("/history")
def history():
    return render_template("history.html", csrf_token=_csrf_token())


@app.errorhandler(RequestEntityTooLarge)
def handle_large_request(_error):
    _ = _error
    message = (
        f"The request exceeds the {app.config['MAX_UPLOAD_BYTES'] / 1024**3:g} GiB upload limit."
    )
    if request.path.startswith("/files"):
        return jsonify(error=message), 413
    if request.path.startswith("/email"):
        message = (
            f"Email requests must be {MAX_EMAIL_REQUEST_BYTES // (1024 * 1024)} MiB "
            "or smaller."
        )
        with _connection() as conn:
            recent_scans = conn.execute("""
                SELECT id, subject, sender, risk_score, risk_level, scan_time
                FROM email_scans ORDER BY scan_time DESC LIMIT 8
            """).fetchall()
        return render_template(
            "email_scan.html",
            csrf_token=_csrf_token(),
            recent_scans=recent_scans,
            max_email_characters=MAX_EMAIL_CHARACTERS,
            max_email_upload_bytes=MAX_EMAIL_UPLOAD_BYTES,
            max_attachment_bytes=MAX_ATTACHMENT_BYTES,
            max_email_request_bytes=MAX_EMAIL_REQUEST_BYTES,
            error=message,
        ), 413
    return render_template("result.html", error=message), 413


@app.errorhandler(404)
def handle_not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found."), 404
    return render_template(
        "error.html",
        error_code=404,
        error_title="Page not found",
        error_message=(
            "That page does not exist. Check the address, or start again from "
            "the URL scanner."
        ),
    ), 404


@app.errorhandler(500)
def handle_server_error(error):
    app.logger.error("Unhandled error on %s: %s", request.path, error)
    if request.path.startswith("/api/"):
        return jsonify(error="The server could not complete the request."), 500
    return render_template(
        "error.html",
        error_code=500,
        error_title="Something went wrong",
        error_message=(
            "The request could not be completed. Try again, and check the "
            "server log if the problem continues."
        ),
    ), 500


model = joblib.load(PROJECT_DIR / "models" / "phishing_model.pkl")

if SETTINGS.secret_key_is_ephemeral:
    app.logger.warning(
        "FLASK_SECRET_KEY is not set; using a temporary key for local "
        "development. Sessions reset whenever the process restarts."
    )
if SETTINGS.access_gate_enabled:
    app.logger.info("Saved scan history is protected by an access code.")


if __name__ == "__main__":
    print("PhishGuard database initialized.")
    print(
        f"Environment: {app.config['ENVIRONMENT']} · "
        f"data directory: {SETTINGS.data_dir}"
    )
    if SETTINGS.is_production:
        print(
            "Use `gunicorn --bind 0.0.0.0:$PORT app:app` for production; "
            "the Flask development server is not suitable for hosting."
        )
    app.run(debug=False, host=SETTINGS.host, port=app.config["PORT"])
