import json
import ipaddress
import re
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse


class DashboardQueryError(ValueError):
    pass


DATE_RANGES = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
INCIDENT_STATUSES = (
    "New",
    "Investigating",
    "Contained",
    "Resolved",
    "False Positive",
)
URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "lnkd.in",
    "rb.gy",
    "t.co",
    "tinyurl.com",
    "ow.ly",
    "shorturl.at",
}


EVENTS_CTE = """
WITH events AS (
    SELECT
        'url:' || id AS event_id,
        'url' AS source_type,
        CAST(id AS TEXT) AS source_id,
        CASE WHEN result = 'PHISHING'
             THEN 'MALICIOUS_URL_DETECTED'
             ELSE 'URL_ANALYSIS_COMPLETED' END AS event_type,
        url AS source,
        CASE WHEN result = 'PHISHING'
             THEN 'Phishing URL' ELSE 'URL analysis' END AS category,
        probability AS risk_score,
        CASE WHEN result = 'PHISHING' THEN 'High' ELSE 'Low' END AS severity,
        'PhishGuard Random Forest' AS engine,
        result AS status,
        scan_time AS timestamp,
        '/urls/' || id AS investigation_url,
        url AS searchable,
        CASE WHEN result = 'PHISHING' THEN 'phishing' ELSE 'legitimate' END
            AS url_classification,
        NULL AS file_classification,
        NULL AS email_classification
    FROM scans

    UNION ALL

    SELECT
        'file:' || f.id AS event_id,
        'file' AS source_type,
        f.id AS source_id,
        CASE
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 'MALICIOUS_FILE_DETECTED'
            WHEN f.status = 'complete' THEN 'FILE_SCAN_COMPLETED'
            WHEN f.status = 'failed' THEN 'FILE_SCAN_FAILED'
            ELSE 'FILE_SCAN_PENDING'
        END AS event_type,
        f.filename AS source,
        CASE
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 'Malware'
            ELSE 'File scan'
        END AS category,
        CASE
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 100
            ELSE 0
        END AS risk_score,
        CASE
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 'Critical'
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
            ) THEN 'Low'
            ELSE 'Informational'
        END AS severity,
        COALESCE((
            SELECT group_concat(json_extract(e.value, '$.provider'), ', ')
            FROM json_each(
                CASE WHEN json_valid(f.results_json)
                     THEN f.results_json ELSE '{}' END,
                '$.engines'
            ) AS e
            WHERE json_extract(e.value, '$.status') = 'complete'
        ), 'No scanner completed') AS engine,
        CASE
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 'Potential threat detected'
            WHEN f.status = 'complete' AND EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
            ) THEN 'No detections by completed scanners'
            WHEN f.status = 'complete' THEN 'Unable to determine'
            ELSE f.status
        END AS status,
        f.created_at AS timestamp,
        '/files/' || f.id AS investigation_url,
        f.filename || ' ' || f.sha256 || ' ' || f.file_type AS searchable,
        NULL AS url_classification,
        CASE
            WHEN f.status != 'complete' THEN 'pending'
            WHEN EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
                  AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
            ) THEN 'malicious'
            WHEN EXISTS (
                SELECT 1
                FROM json_each(
                    CASE WHEN json_valid(f.results_json)
                         THEN f.results_json ELSE '{}' END,
                    '$.engines'
                ) AS e
                WHERE json_extract(e.value, '$.status') = 'complete'
            ) THEN 'clean'
            ELSE 'unknown'
        END AS file_classification,
        NULL AS email_classification
    FROM file_scans AS f

    UNION ALL

    SELECT
        'email:' || e.id AS event_id,
        'email' AS source_type,
        e.id AS source_id,
        CASE
            WHEN e.risk_score >= 75 THEN 'PHISHING_EMAIL_DETECTED'
            WHEN e.risk_score >= 50 THEN 'SUSPICIOUS_EMAIL_DETECTED'
            ELSE 'EMAIL_ANALYZED'
        END AS event_type,
        COALESCE(json_extract(e.results_json, '$.sender'), e.sender) AS source,
        COALESCE(
            json_extract(e.results_json, '$.findings[0].title'),
            'Email heuristic analysis'
        ) AS category,
        e.risk_score AS risk_score,
        CASE
            WHEN e.risk_score >= 75 THEN 'Critical'
            WHEN e.risk_score >= 50 THEN 'High'
            WHEN e.risk_score >= 25 THEN 'Medium'
            ELSE 'Low'
        END AS severity,
        'Email heuristics / URL model' AS engine,
        COALESCE(
            json_extract(e.results_json, '$.verdict'),
            e.risk_level
        ) AS status,
        e.scan_time AS timestamp,
        '/email/' || e.id AS investigation_url,
        e.sender || ' ' ||
        COALESCE(json_extract(e.results_json, '$.sender_address'), '') || ' ' ||
        COALESCE(json_extract(e.results_json, '$.sender_domain'), '') || ' ' ||
        COALESCE(json_extract(e.results_json, '$.to'), '') || ' ' ||
        COALESCE(json_extract(e.results_json, '$.cc'), '') || ' ' ||
        COALESCE(json_extract(e.results_json, '$.bcc'), '') || ' ' ||
        COALESCE(json_extract(e.results_json, '$.subject'), e.subject) || ' ' ||
        COALESCE(json_extract(e.results_json, '$.links'), '') AS searchable,
        NULL AS url_classification,
        NULL AS file_classification,
        CASE
            WHEN e.risk_score >= 75 THEN 'phishing'
            WHEN e.risk_score >= 25 THEN 'suspicious'
            ELSE 'inconclusive'
        END AS email_classification
    FROM email_scans AS e
)
"""


def register_sql_functions(connection):
    def host(value):
        try:
            return (urlparse(value or "").hostname or "").lower().rstrip(".")
        except ValueError:
            return ""

    def is_ip(value):
        try:
            ipaddress.ip_address(host(value))
            return 1
        except ValueError:
            return 0

    connection.create_function("soc_url_host", 1, host, deterministic=True)
    connection.create_function("soc_url_is_ip", 1, is_ip, deterministic=True)
    connection.create_function(
        "soc_url_is_shortener",
        1,
        lambda value: int(host(value) in URL_SHORTENERS),
        deterministic=True,
    )


def parse_date_range(args, now=None):
    now = now or datetime.now().replace(microsecond=0)
    selected = args.get("range", "24h")
    if selected == "all":
        start = datetime(1970, 1, 1)
        end = now
    elif selected == "custom":
        try:
            start = datetime.fromisoformat(args.get("start", ""))
            end = datetime.fromisoformat(args.get("end", ""))
        except ValueError as error:
            raise DashboardQueryError(
                "Custom ranges require valid start and end dates."
            ) from error
        if start.tzinfo or end.tzinfo:
            raise DashboardQueryError(
                "Use local date and time values without a timezone offset."
            )
        if start >= end:
            raise DashboardQueryError("The start date must be earlier than the end date.")
    elif selected in DATE_RANGES:
        end = now
        start = end - DATE_RANGES[selected]
    else:
        raise DashboardQueryError(
            "Choose one of all, 15m, 1h, 24h, 7d, 30d, or custom."
        )

    return {
        "key": selected,
        "start": start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": end.strftime("%Y-%m-%d %H:%M:%S"),
        "start_datetime": start,
        "end_datetime": end,
        "duration": end - start,
    }


def _range_where():
    return "timestamp >= ? AND timestamp < ?"


def _event_period_metrics(connection, start, end):
    rows = connection.execute(
        EVENTS_CTE + """
        SELECT
            COUNT(*) AS events,
            SUM(CASE WHEN source_type = 'email' THEN 1 ELSE 0 END) AS emails,
            SUM(CASE WHEN source_type = 'file' THEN 1 ELSE 0 END) AS files,
            SUM(CASE WHEN source_type = 'url' THEN 1 ELSE 0 END) AS urls,
            SUM(CASE WHEN email_classification = 'phishing' THEN 1 ELSE 0 END)
                AS phishing_emails,
            SUM(CASE WHEN file_classification = 'malicious' THEN 1 ELSE 0 END)
                AS malicious_files,
            SUM(CASE WHEN url_classification = 'phishing' THEN 1 ELSE 0 END)
                AS malicious_urls,
            SUM(CASE WHEN severity IN ('Critical', 'High') THEN 1 ELSE 0 END)
                AS high_risk_events,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END)
                AS critical_events,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END)
                AS medium_risk_events,
            SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END)
                AS low_risk_events,
            SUM(CASE WHEN url_classification = 'legitimate'
                       OR file_classification = 'clean'
                     THEN 1 ELSE 0 END) AS no_detection_items
        FROM events
        WHERE """ + _range_where(),
        (start, end),
    ).fetchone()
    metrics = {key: int(rows[key] or 0) for key in rows.keys()}
    metrics["critical_incidents"] = connection.execute("""
        SELECT COUNT(*)
        FROM security_incidents
        WHERE first_detected >= ? AND first_detected < ?
          AND severity = 'Critical'
          AND status NOT IN ('Resolved', 'False Positive')
    """, (start, end)).fetchone()[0]
    metrics["critical_incidents"] = int(metrics["critical_incidents"] or 0)
    return metrics


def get_summary(connection, date_range):
    start = date_range["start"]
    end = date_range["end"]
    current = _event_period_metrics(connection, start, end)
    duration = date_range["duration"]
    previous = _event_period_metrics(
        connection,
        (date_range["start_datetime"] - duration).strftime("%Y-%m-%d %H:%M:%S"),
        start,
    )
    labels = (
        ("emails", "Emails analyzed"),
        ("files", "Files scanned"),
        ("urls", "URLs analyzed"),
        ("events", "Security events"),
        ("phishing_emails", "Phishing-risk emails"),
        ("malicious_files", "Malicious files"),
        ("malicious_urls", "Phishing URLs"),
        ("critical_incidents", "Open critical incidents"),
        ("high_risk_events", "High-risk events"),
        ("medium_risk_events", "Medium-risk events"),
        ("low_risk_events", "Low-risk events"),
        ("no_detection_items", "No-detection items"),
    )
    cards = []
    for key, label in labels:
        before = previous[key]
        now = current[key]
        change = (
            round(((now - before) / before) * 100, 1)
            if before
            else (0.0 if now == 0 else None)
        )
        cards.append({
            "key": key,
            "label": label,
            "value": now,
            "previous_value": before,
            "change_percent": change,
        })
    return {
        "range": {
            "key": date_range["key"],
            "start": start,
            "end": end,
        },
        "kpis": cards,
    }


def get_activity(connection, date_range, bucket):
    bucket_minutes = {"5m": 5, "15m": 15, "1h": 60, "1d": 1440}
    if bucket not in bucket_minutes:
        raise DashboardQueryError("Choose a 5m, 15m, 1h, or 1d activity bucket.")
    minutes = bucket_minutes[bucket]
    if minutes < 60:
        bucket_sql = (
            "strftime('%Y-%m-%d %H:', timestamp) || "
            f"printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / {minutes}) * {minutes}) || ':00'"
        )
    elif minutes == 60:
        bucket_sql = "strftime('%Y-%m-%d %H:00:00', timestamp)"
    else:
        bucket_sql = "strftime('%Y-%m-%d 00:00:00', timestamp)"

    rows = connection.execute(
        EVENTS_CTE + f"""
        SELECT
            {bucket_sql} AS bucket,
            SUM(CASE WHEN source_type = 'email' THEN 1 ELSE 0 END) AS emails,
            SUM(CASE WHEN event_type = 'PHISHING_EMAIL_DETECTED'
                     THEN 1 ELSE 0 END) AS phishing_emails,
            SUM(CASE WHEN source_type = 'file' THEN 1 ELSE 0 END) AS files,
            SUM(CASE WHEN file_classification = 'malicious'
                     THEN 1 ELSE 0 END) AS malicious_files,
            SUM(CASE WHEN source_type = 'url' THEN 1 ELSE 0 END) AS urls,
            SUM(CASE WHEN url_classification = 'phishing'
                     THEN 1 ELSE 0 END) AS malicious_urls
        FROM events
        WHERE {_range_where()}
        GROUP BY bucket
        ORDER BY bucket
        """,
        (date_range["start"], date_range["end"]),
    ).fetchall()
    series_keys = (
        "emails",
        "phishing_emails",
        "files",
        "malicious_files",
        "urls",
        "malicious_urls",
    )
    points = [
        {
            "timestamp": row["bucket"],
            **{key: int(row[key] or 0) for key in series_keys},
        }
        for row in rows
        if row["bucket"]
    ]
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "bucket": bucket,
        "series": list(series_keys),
        "points": points,
    }


def get_recent_events(
    connection,
    date_range,
    search="",
    severity="all",
    event_type="all",
    source_type="all",
    page=1,
    page_size=25,
    sort="desc",
):
    try:
        page = int(page)
        page_size = int(page_size)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Page and page size must be integers.") from error
    if page < 1:
        raise DashboardQueryError("Page must be 1 or greater.")
    if not 1 <= page_size <= 1000:
        raise DashboardQueryError("Page size must be between 1 and 1000.")
    if severity not in {
        "all", "Critical", "High", "Medium", "Low", "Informational"
    }:
        raise DashboardQueryError("Unknown severity filter.")
    if source_type not in {"all", "email", "file", "url"}:
        raise DashboardQueryError("Unknown source filter.")
    if sort not in {"asc", "desc"}:
        raise DashboardQueryError("Sort must be asc or desc.")
    if len(search) > 200:
        raise DashboardQueryError("Search text must be 200 characters or fewer.")

    conditions = [_range_where()]
    values = [date_range["start"], date_range["end"]]
    if severity != "all":
        conditions.append("severity = ?")
        values.append(severity)
    if event_type != "all":
        conditions.append("event_type = ?")
        values.append(event_type[:80])
    if source_type != "all":
        conditions.append("source_type = ?")
        values.append(source_type)
    if search:
        escaped = search.strip().lower().replace("\\", "\\\\")
        escaped = escaped.replace("%", "\\%").replace("_", "\\_")
        conditions.append("lower(searchable) LIKE ? ESCAPE '\\'")
        values.append(f"%{escaped}%")
    where = " AND ".join(conditions)
    total = connection.execute(
        EVENTS_CTE + f"SELECT COUNT(*) FROM events WHERE {where}",
        values,
    ).fetchone()[0]
    rows = connection.execute(
        EVENTS_CTE + f"""
        SELECT event_id, source_type, source_id, event_type, source, category,
               risk_score, severity, engine, status, timestamp,
               investigation_url
        FROM events
        WHERE {where}
        ORDER BY timestamp {sort.upper()}, event_id {sort.upper()}
        LIMIT ? OFFSET ?
        """,
        values + [page_size, (page - 1) * page_size],
    ).fetchall()
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "events": [dict(row) for row in rows],
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "pages": (int(total) + page_size - 1) // page_size,
    }


def _authentication_distribution(connection, date_range):
    raw_statuses = connection.execute("""
        SELECT method, status, COUNT(*) AS total
        FROM (
            SELECT 'spf' AS method,
                   COALESCE(json_extract(results_json, '$.authentication.spf'),
                            'unknown') AS status
            FROM email_scans
            WHERE scan_time >= ? AND scan_time < ?
            UNION ALL
            SELECT 'dkim',
                   COALESCE(json_extract(results_json, '$.authentication.dkim'),
                            'unknown')
            FROM email_scans
            WHERE scan_time >= ? AND scan_time < ?
            UNION ALL
            SELECT 'dmarc',
                   COALESCE(json_extract(results_json, '$.authentication.dmarc'),
                            'unknown')
            FROM email_scans
            WHERE scan_time >= ? AND scan_time < ?
        ) AS auth
        GROUP BY method, status
    """, (
        date_range["start"], date_range["end"],
        date_range["start"], date_range["end"],
        date_range["start"], date_range["end"],
    )).fetchall()
    methods = {
        method: {"pass": 0, "fail": 0, "none": 0, "unknown": 0}
        for method in ("spf", "dkim", "dmarc")
    }
    for row in raw_statuses:
        value = row["status"].strip().lower()
        if "fail" in value or "softfail" in value or "permerror" in value:
            normalized = "fail"
        elif "pass" in value:
            normalized = "pass"
        elif value == "none":
            normalized = "none"
        else:
            normalized = "unknown"
        methods[row["method"]][normalized] += int(row["total"])
    for values in methods.values():
        denominator = values["pass"] + values["fail"]
        values["pass_percentage"] = (
            round(values["pass"] / denominator * 100, 1)
            if denominator
            else None
        )

    alignment_failures = connection.execute("""
        SELECT COUNT(*)
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ?
          AND json_extract(
              results_json,
              '$.authentication_details.dmarc.reported_alignment'
          ) = 'reported pass without a matching aligned mechanism'
    """, (date_range["start"], date_range["end"])).fetchone()[0]
    dns_lookups = connection.execute("""
        SELECT COUNT(*)
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ?
          AND json_extract(results_json, '$.dns.checked') = 1
    """, (date_range["start"], date_range["end"])).fetchone()[0]
    return {
        "methods": methods,
        "alignment_failures": int(alignment_failures),
        "dns_lookups": int(dns_lookups),
        "source_note": (
            "SPF/DKIM/DMARC statuses are reported email-header claims. "
            "DNS records are shown separately and do not authenticate a message."
        ),
    }


def get_threat_distribution(connection, date_range):
    severity_rows = connection.execute(
        EVENTS_CTE + """
        SELECT severity, COUNT(*) AS total
        FROM events
        WHERE """ + _range_where() + """
        GROUP BY severity
        """,
        (date_range["start"], date_range["end"]),
    ).fetchall()
    category_rows = connection.execute(
        EVENTS_CTE + """
        SELECT category, COUNT(*) AS total
        FROM events
        WHERE """ + _range_where() + """
        GROUP BY category
        ORDER BY total DESC, category
        LIMIT 12
        """,
        (date_range["start"], date_range["end"]),
    ).fetchall()
    file_rows = connection.execute(
        EVENTS_CTE + """
        SELECT file_classification AS classification, COUNT(*) AS total
        FROM events
        WHERE source_type = 'file' AND """ + _range_where() + """
        GROUP BY file_classification
        """,
        (date_range["start"], date_range["end"]),
    ).fetchall()
    url_rows = connection.execute(
        EVENTS_CTE + """
        SELECT url_classification AS classification, COUNT(*) AS total
        FROM events
        WHERE source_type = 'url' AND """ + _range_where() + """
        GROUP BY url_classification
        """,
        (date_range["start"], date_range["end"]),
    ).fetchall()
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "severity": {row["severity"]: int(row["total"]) for row in severity_rows},
        "categories": [
            {"label": row["category"], "value": int(row["total"])}
            for row in category_rows
        ],
        "files": {
            row["classification"]: int(row["total"]) for row in file_rows
        },
        "urls": {
            row["classification"]: int(row["total"]) for row in url_rows
        },
        "authentication": _authentication_distribution(connection, date_range),
    }


def get_email_statistics(connection, date_range, page=1, page_size=10, search=""):
    start, end = date_range["start"], date_range["end"]
    row = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN risk_score >= 75 THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN risk_score >= 25 AND risk_score < 75
                     THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN risk_score < 25 THEN 1 ELSE 0 END) AS low_signal,
            SUM(CASE WHEN lower(COALESCE(
                json_extract(results_json, '$.authentication.spf'), ''
            )) LIKE '%fail%' THEN 1 ELSE 0 END) AS spf_failures,
            SUM(CASE WHEN lower(COALESCE(
                json_extract(results_json, '$.authentication.dkim'), ''
            )) LIKE '%fail%' THEN 1 ELSE 0 END) AS dkim_failures,
            SUM(CASE WHEN lower(COALESCE(
                json_extract(results_json, '$.authentication.dmarc'), ''
            )) LIKE '%fail%' THEN 1 ELSE 0 END) AS dmarc_failures,
            SUM(CASE WHEN EXISTS (
                SELECT 1 FROM json_each(
                    CASE WHEN json_valid(email_scans.results_json)
                         THEN email_scans.results_json ELSE '{}' END,
                    '$.findings'
                ) AS finding
                WHERE lower(json_extract(finding.value, '$.title'))
                      LIKE '%brand name%'
                   OR lower(json_extract(finding.value, '$.title'))
                      LIKE '%spoof%'
            ) THEN 1 ELSE 0 END) AS sender_spoofing,
            SUM(CASE WHEN EXISTS (
                SELECT 1 FROM json_each(
                    CASE WHEN json_valid(email_scans.results_json)
                         THEN email_scans.results_json ELSE '{}' END,
                    '$.findings'
                ) AS finding
                WHERE json_extract(finding.value, '$.title')
                      = 'Reply-To domain differs from From'
            ) THEN 1 ELSE 0 END) AS reply_to_mismatches,
            SUM(COALESCE(json_array_length(results_json, '$.links'), 0))
                AS url_count,
            SUM(COALESCE(json_array_length(results_json, '$.attachments'), 0))
                AS attachment_count,
            COUNT(DISTINCT json_extract(results_json, '$.sender_domain'))
                AS distinct_domains,
            SUM(CASE WHEN EXISTS (
                SELECT 1 FROM json_each(
                    CASE WHEN json_valid(email_scans.results_json)
                         THEN email_scans.results_json ELSE '{}' END,
                    '$.findings'
                ) AS finding
                WHERE lower(json_extract(finding.value, '$.title'))
                      LIKE '%credential%'
                   OR lower(json_extract(finding.value, '$.title'))
                      LIKE '%password%'
            ) THEN 1 ELSE 0 END) AS credential_indicators
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ?
    """, (start, end)).fetchone()
    if len(search) > 200:
        raise DashboardQueryError("Email search text must be 200 characters or fewer.")
    try:
        page, page_size = int(page), int(page_size)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Page and page size must be integers.") from error
    if page < 1 or not 1 <= page_size <= 100:
        raise DashboardQueryError("Invalid email page or page size.")
    records_where = "scan_time >= ? AND scan_time < ?"
    records_values = [start, end]
    if search.strip():
        escaped = search.strip().lower()
        escaped = escaped.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        records_where += """
            AND lower(id || ' ' || sender || ' ' || subject || ' ' || results_json)
                LIKE ? ESCAPE '\\'
        """
        records_values.append(f"%{escaped}%")
    records_total = connection.execute(
        f"SELECT COUNT(*) FROM email_scans WHERE {records_where}",
        records_values,
    ).fetchone()[0]
    records = connection.execute(f"""
        SELECT id, subject, sender, risk_score, risk_level, results_json, scan_time
        FROM email_scans
        WHERE {records_where}
        ORDER BY scan_time DESC, id
        LIMIT ? OFFSET ?
    """, records_values + [page_size, (page - 1) * page_size]).fetchall()
    email_rows = []
    for record in records:
        try:
            results = json.loads(record["results_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            results = {}
        authentication = results.get("authentication") or {}
        email_rows.append({
            "id": record["id"],
            "subject": results.get("subject") or record["subject"],
            "sender": results.get("sender") or record["sender"],
            "recipient": results.get("to") or "(not included)",
            "domain": results.get("sender_domain") or "(not available)",
            "spf": authentication.get("spf") or "unknown",
            "dkim": authentication.get("dkim") or "unknown",
            "dmarc": authentication.get("dmarc") or "unknown",
            "attachment_count": len(results.get("attachments") or []),
            "url_count": len(results.get("links") or []),
            "risk_score": int(record["risk_score"]),
            "verdict": results.get("verdict") or record["risk_level"],
            "timestamp": record["scan_time"],
            "investigation_url": f"/email/{record['id']}",
        })
    return {
        "range": {"start": start, "end": end},
        **{key: int(row[key] or 0) for key in row.keys()},
        "records": email_rows,
        "records_total": int(records_total),
        "page": page,
        "page_size": page_size,
        "classification_note": (
            "Low-signal email checks are inconclusive, not confirmed safe."
        ),
    }


def get_url_statistics(connection, date_range, page=1, page_size=10):
    start, end = date_range["start"], date_range["end"]
    row = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN result = 'PHISHING' THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN result = 'LEGITIMATE' THEN 1 ELSE 0 END) AS legitimate,
            SUM(CASE WHEN soc_url_is_ip(url) = 1 THEN 1 ELSE 0 END)
                AS ip_based,
            SUM(CASE WHEN lower(soc_url_host(url)) LIKE '%xn--%'
                     THEN 1 ELSE 0 END) AS punycode,
            SUM(CASE WHEN soc_url_is_shortener(url) = 1 THEN 1 ELSE 0 END)
                AS shortened,
            AVG(probability) AS average_phishing_probability
        FROM scans
        WHERE scan_time >= ? AND scan_time < ?
    """, (start, end)).fetchone()
    try:
        page, page_size = int(page), int(page_size)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Page and page size must be integers.") from error
    if page < 1 or not 1 <= page_size <= 100:
        raise DashboardQueryError("Invalid URL page or page size.")
    records = connection.execute("""
        SELECT id, url, result, probability, risk_level, scan_time
        FROM scans
        WHERE scan_time >= ? AND scan_time < ?
        ORDER BY scan_time DESC, id DESC
        LIMIT ? OFFSET ?
    """, (start, end, page_size, (page - 1) * page_size)).fetchall()
    total = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE scan_time >= ? AND scan_time < ?",
        (start, end),
    ).fetchone()[0]
    return {
        "range": {"start": start, "end": end},
        **{
            key: (
                round(row[key], 2)
                if key == "average_phishing_probability" and row[key] is not None
                else (int(row[key] or 0) if key != "average_phishing_probability" else None)
            )
            for key in row.keys()
        },
        "redirects": None,
        "redirects_note": "URLs are not opened; redirect chains are not checked.",
        "model": "Included Random Forest structural URL model",
        "records": [
            {
                "id": record["id"],
                "url": record["url"],
                "host": register_url_host(record["url"]),
                "result": record["result"],
                "probability": record["probability"],
                "risk_level": record["risk_level"],
                "timestamp": record["scan_time"],
                "investigation_url": f"/urls/{record['id']}",
            }
            for record in records
        ],
        "total": int(total),
        "page": page,
        "page_size": page_size,
    }


def register_url_host(value):
    try:
        return (urlparse(value or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def get_file_statistics(connection, date_range, page=1, page_size=10):
    start, end = date_range["start"], date_range["end"]
    rows = connection.execute(
        EVENTS_CTE + """
        SELECT file_classification, COUNT(*) AS total
        FROM events
        WHERE source_type = 'file' AND """ + _range_where() + """
        GROUP BY file_classification
        """,
        (start, end),
    ).fetchall()
    states = {row["file_classification"]: int(row["total"]) for row in rows}
    totals = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status IN ('queued', 'scanning') THEN 1 ELSE 0 END)
                AS pending,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN lower(file_type) LIKE '%executable%'
                     THEN 1 ELSE 0 END) AS executable_types,
            SUM(CASE WHEN lower(file_type) LIKE '%archive%'
                     THEN 1 ELSE 0 END) AS archive_types
        FROM file_scans
        WHERE created_at >= ? AND created_at < ?
    """, (start, end)).fetchone()
    try:
        page, page_size = int(page), int(page_size)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Page and page size must be integers.") from error
    if page < 1 or not 1 <= page_size <= 100:
        raise DashboardQueryError("Invalid file page or page size.")
    records = connection.execute("""
        SELECT id, filename, file_size, sha256, file_type, status, message,
               results_json, created_at
        FROM file_scans
        WHERE created_at >= ? AND created_at < ?
        ORDER BY created_at DESC, id
        LIMIT ? OFFSET ?
    """, (start, end, page_size, (page - 1) * page_size)).fetchall()
    file_rows = []
    for record in records:
        try:
            results = json.loads(record["results_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            results = {}
        file_rows.append({
            "id": record["id"],
            "filename": record["filename"],
            "file_size": int(record["file_size"]),
            "sha256": record["sha256"],
            "file_type": results.get("file_type") or record["file_type"],
            "status": record["status"],
            "engines": results.get("engines") or [],
            "timestamp": record["created_at"],
            "investigation_url": f"/files/{record['id']}",
        })
    return {
        "range": {"start": start, "end": end},
        **{key: int(totals[key] or 0) for key in totals.keys()},
        "classification": {
            "malicious": states.get("malicious", 0),
            "clean": states.get("clean", 0),
            "unknown": states.get("unknown", 0),
            "pending": states.get("pending", 0),
        },
        "records": file_rows,
        "macro_enabled_documents": None,
        "mime_mismatches": None,
        "double_extension_detections": None,
        "unavailable_note": (
            "Standalone file scans do not currently record macro, MIME-mismatch, "
            "or double-extension analysis."
        ),
    }


def get_authentication_statistics(connection, date_range):
    values = _authentication_distribution(connection, date_range)
    values["range"] = {"start": date_range["start"], "end": date_range["end"]}
    return values


def get_threat_intelligence(connection, date_range, provider_configuration):
    rows = connection.execute("""
        SELECT
            json_extract(engine.value, '$.provider') AS provider,
            json_extract(engine.value, '$.status') AS status,
            CAST(json_extract(engine.value, '$.detections') AS INTEGER) AS detections,
            file_scans.updated_at AS checked_at
        FROM file_scans,
             json_each(
                 CASE WHEN json_valid(file_scans.results_json)
                      THEN file_scans.results_json ELSE '{}' END,
                 '$.engines'
             ) AS engine
        WHERE file_scans.updated_at >= ? AND file_scans.updated_at < ?
          AND json_extract(engine.value, '$.provider') IN
              ('VirusTotal', 'OPSWAT MetaDefender')
    """, (date_range["start"], date_range["end"])).fetchall()
    providers = {
        name: {
            "recorded_results": 0,
            "completed": 0,
            "detections": 0,
            "pending": 0,
            "failed": 0,
            "last_check": None,
        }
        for name in ("VirusTotal", "OPSWAT MetaDefender")
    }
    for row in rows:
        value = providers[row["provider"]]
        status = row["status"] or "unknown"
        if status not in {"not_shared", "not_configured", "skipped"}:
            value["recorded_results"] += 1
        if status == "complete":
            value["completed"] += 1
            value["detections"] += int(row["detections"] or 0)
        elif status == "submitted":
            value["pending"] += 1
        elif status == "error":
            value["failed"] += 1
        checked_at = row["checked_at"]
        if status not in {"not_shared", "not_configured"} and (
            value["last_check"] is None or checked_at > value["last_check"]
        ):
            value["last_check"] = checked_at

    configuration = {item["provider"]: item for item in provider_configuration}
    for provider, values in providers.items():
        configured = configuration.get(provider, {}).get("configured", False)
        values["configuration"] = "configured" if configured else "not configured"
        values["connectivity"] = "not tested by dashboard"
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "providers": providers,
        "pending_file_scans": connection.execute("""
            SELECT COUNT(*) FROM file_scans
            WHERE status IN ('queued', 'scanning')
              AND created_at >= ? AND created_at < ?
        """, (date_range["start"], date_range["end"])).fetchone()[0],
        "note": (
            "Provider credentials indicate configuration only. No live provider "
            "connectivity or quota check was made."
        ),
    }


def get_top_indicators(connection, date_range):
    start, end = date_range["start"], date_range["end"]
    sender_domains = connection.execute("""
        SELECT json_extract(results_json, '$.sender_domain') AS indicator,
               COUNT(*) AS total
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ?
          AND risk_score >= 25
          AND json_extract(results_json, '$.sender_domain') IS NOT NULL
          AND json_extract(results_json, '$.sender_domain') != '(not available)'
        GROUP BY indicator
        ORDER BY total DESC, indicator
        LIMIT 5
    """, (start, end)).fetchall()
    suspicious_urls = connection.execute("""
        SELECT soc_url_host(url) AS indicator, COUNT(*) AS total
        FROM scans
        WHERE scan_time >= ? AND scan_time < ? AND result = 'PHISHING'
        GROUP BY indicator
        ORDER BY total DESC, indicator
        LIMIT 5
    """, (start, end)).fetchall()
    file_hashes = connection.execute("""
        SELECT f.sha256 AS indicator, COUNT(*) AS total
        FROM file_scans AS f
        WHERE f.created_at >= ? AND f.created_at < ?
          AND EXISTS (
              SELECT 1
              FROM json_each(
                  CASE WHEN json_valid(f.results_json)
                       THEN f.results_json ELSE '{}' END,
                  '$.engines'
              ) AS e
              WHERE json_extract(e.value, '$.status') = 'complete'
                AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
          )
        GROUP BY f.sha256
        ORDER BY total DESC, indicator
        LIMIT 5
    """, (start, end)).fetchall()
    phishing_subjects = connection.execute("""
        SELECT COALESCE(json_extract(results_json, '$.subject'), subject)
                   AS indicator,
               COUNT(*) AS total
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ? AND risk_score >= 75
        GROUP BY indicator
        ORDER BY total DESC, indicator
        LIMIT 5
    """, (start, end)).fetchall()
    categories = connection.execute("""
        SELECT json_extract(finding.value, '$.title') AS indicator,
               COUNT(*) AS total
        FROM email_scans AS e,
             json_each(
                 CASE WHEN json_valid(e.results_json)
                      THEN e.results_json ELSE '{}' END,
                 '$.findings'
             ) AS finding
        WHERE e.scan_time >= ? AND e.scan_time < ?
        GROUP BY indicator
        ORDER BY total DESC, indicator
        LIMIT 8
    """, (start, end)).fetchall()

    def values(rows):
        return [
            {"label": row["indicator"], "count": int(row["total"])}
            for row in rows
        ]

    return {
        "range": {"start": start, "end": end},
        "sender_domains": values(sender_domains),
        "suspicious_urls": values(suspicious_urls),
        "file_hashes": values(file_hashes),
        "phishing_subjects": values(phishing_subjects),
        "categories": values(categories),
    }


def sync_incidents(connection):
    candidates = []
    candidates.extend(
        {
            "source_type": "url",
            "source_id": str(row["id"]),
            "title": "Phishing URL model detection",
            "description": (
                f"The URL model flagged this address with "
                f"{row['probability']:.2f}% phishing probability."
            ),
            "category": "Phishing URL",
            "severity": "High",
            "entity": row["url"],
            "timestamp": row["scan_time"],
        }
        for row in connection.execute("""
            SELECT id, url, probability, scan_time
            FROM scans WHERE result = 'PHISHING'
        """)
    )
    candidates.extend(
        {
            "source_type": "email",
            "source_id": row["id"],
            "title": "High-risk email analysis",
            "description": (
                f"Email analysis produced a heuristic risk score of "
                f"{row['risk_score']}/100. Review the report before treating it "
                "as a confirmed phishing incident."
            ),
            "category": "Phishing email",
            "severity": "Critical" if row["risk_score"] >= 75 else "High",
            "entity": row["sender"],
            "timestamp": row["scan_time"],
        }
        for row in connection.execute("""
            SELECT id, sender, risk_score, scan_time
            FROM email_scans WHERE risk_score >= 50
        """)
    )
    candidates.extend(
        {
            "source_type": "file",
            "source_id": row["id"],
            "title": "Malware detected in file scan",
            "description": (
                f"A configured scanner reported {row['detections']} detection(s). "
                "Review the stored engine results."
            ),
            "category": "Malware",
            "severity": "Critical",
            "entity": row["filename"],
            "timestamp": row["created_at"],
        }
        for row in connection.execute("""
            SELECT f.id, f.filename, f.created_at,
                   (SELECT SUM(CAST(json_extract(e.value, '$.detections') AS INTEGER))
                    FROM json_each(
                        CASE WHEN json_valid(f.results_json)
                             THEN f.results_json ELSE '{}' END,
                        '$.engines'
                    ) AS e
                    WHERE json_extract(e.value, '$.status') = 'complete'
                   ) AS detections
            FROM file_scans AS f
            WHERE f.status = 'complete'
              AND EXISTS (
                  SELECT 1
                  FROM json_each(
                      CASE WHEN json_valid(f.results_json)
                           THEN f.results_json ELSE '{}' END,
                      '$.engines'
                  ) AS e
                  WHERE json_extract(e.value, '$.status') = 'complete'
                    AND CAST(json_extract(e.value, '$.detections') AS INTEGER) > 0
              )
        """)
    )
    for candidate in candidates:
        connection.execute("""
            INSERT OR IGNORE INTO security_incidents
            (id, source_type, source_id, title, description, category,
             severity, entity, status, assigned_analyst, first_detected,
             last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New', '', ?, ?)
        """, (
            uuid.uuid4().hex,
            candidate["source_type"],
            candidate["source_id"],
            candidate["title"],
            candidate["description"],
            candidate["category"],
            candidate["severity"],
            candidate["entity"],
            candidate["timestamp"],
            candidate["timestamp"],
        ))


def get_incidents(connection, date_range, status="all", page=1, page_size=25):
    try:
        page, page_size = int(page), int(page_size)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Page and page size must be integers.") from error
    if page < 1 or not 1 <= page_size <= 100:
        raise DashboardQueryError("Invalid incident page or page size.")
    if status != "all" and status not in INCIDENT_STATUSES:
        raise DashboardQueryError("Unknown incident status.")
    conditions = ["first_detected >= ?", "first_detected < ?"]
    values = [date_range["start"], date_range["end"]]
    if status != "all":
        conditions.append("status = ?")
        values.append(status)
    where = " AND ".join(conditions)
    total = connection.execute(
        f"SELECT COUNT(*) FROM security_incidents WHERE {where}", values
    ).fetchone()[0]
    rows = connection.execute(
        f"""
        SELECT id, source_type, source_id, title, description, category,
               severity, entity, status, assigned_analyst, first_detected,
               last_updated
        FROM security_incidents
        WHERE {where}
        ORDER BY first_detected DESC, id
        LIMIT ? OFFSET ?
        """,
        values + [page_size, (page - 1) * page_size],
    ).fetchall()
    incidents = []
    for row in rows:
        incident = dict(row)
        investigation_routes = {
            "url": "urls",
            "file": "files",
            "email": "email",
        }
        incident["investigation_url"] = (
            f"/{investigation_routes[incident['source_type']]}/"
            f"{incident['source_id']}"
        )
        incidents.append(incident)
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "incidents": incidents,
        "statuses": list(INCIDENT_STATUSES),
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "pages": (int(total) + page_size - 1) // page_size,
    }


def get_search_results(connection, date_range, query, limit=30):
    query = query.strip()
    if len(query) < 2:
        raise DashboardQueryError("Enter at least 2 characters to search.")
    if len(query) > 200:
        raise DashboardQueryError("Search text must be 200 characters or fewer.")
    try:
        limit = int(limit)
    except (TypeError, ValueError) as error:
        raise DashboardQueryError("Search result limit must be an integer.") from error
    if not 1 <= limit <= 100:
        raise DashboardQueryError("Search result limit must be between 1 and 100.")
    escaped = query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    rows = connection.execute("""
        SELECT 'url:' || id AS id, 'URL scan' AS kind,
               url AS label, result AS detail, scan_time AS timestamp,
               '/urls/' || id AS url
        FROM scans
        WHERE scan_time >= ? AND scan_time < ? AND lower(url) LIKE ? ESCAPE '\\'
        UNION ALL
        SELECT 'file:' || id, 'File scan', filename,
               sha256 || ' · ' || status, created_at, '/files/' || id
        FROM file_scans
        WHERE created_at >= ? AND created_at < ?
          AND (lower(filename) LIKE ? ESCAPE '\\'
               OR lower(sha256) LIKE ? ESCAPE '\\')
        UNION ALL
        SELECT 'email:' || id, 'Email scan',
               COALESCE(json_extract(results_json, '$.subject'), subject),
               sender || ' · ' || risk_level, scan_time, '/email/' || id
        FROM email_scans
        WHERE scan_time >= ? AND scan_time < ?
          AND lower(
              sender || ' ' || subject || ' ' ||
              COALESCE(json_extract(results_json, '$.sender_domain'), '') || ' ' ||
              COALESCE(json_extract(results_json, '$.to'), '') || ' ' ||
              COALESCE(json_extract(results_json, '$.cc'), '') || ' ' ||
              COALESCE(json_extract(results_json, '$.bcc'), '') || ' ' ||
              COALESCE(json_extract(results_json, '$.links'), '')
          ) LIKE ? ESCAPE '\\'
        UNION ALL
        SELECT 'incident:' || id, 'Security incident', title,
               category || ' · ' || status, first_detected,
               CASE
                   WHEN source_type = 'url' THEN '/urls/' || source_id
                   WHEN source_type = 'file' THEN '/files/' || source_id
                   ELSE '/email/' || source_id
               END
        FROM security_incidents
        WHERE first_detected >= ? AND first_detected < ?
          AND lower(
              id || ' ' || title || ' ' || description || ' ' || category ||
              ' ' || entity || ' ' || source_id
          ) LIKE ? ESCAPE '\\'
        ORDER BY timestamp DESC
        LIMIT ?
    """, (
        date_range["start"], date_range["end"], pattern,
        date_range["start"], date_range["end"], pattern, pattern,
        date_range["start"], date_range["end"], pattern,
        date_range["start"], date_range["end"], pattern,
        limit,
    )).fetchall()
    return {
        "range": {"start": date_range["start"], "end": date_range["end"]},
        "query": query,
        "results": [dict(row) for row in rows],
        "limit": limit,
    }
