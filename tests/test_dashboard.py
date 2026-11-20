import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import app as web_app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        web_app.app.config.update(
            TESTING=True,
            DATABASE=str(Path(self.temp_dir.name) / "dashboard-test.db"),
            UPLOAD_DIR=str(Path(self.temp_dir.name) / "uploads"),
        )
        web_app.init_db()
        self.client = web_app.app.test_client()
        self.client.get("/dashboard")
        with self.client.session_transaction() as current_session:
            self.csrf_token = current_session["_csrf_token"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dashboard_pages_and_apis_render_with_no_scan_records(self):
        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(b"Threat intelligence", dashboard.data)
        self.assertNotIn(b"Security incidents", dashboard.data)
        self.assertNotIn(b"Settings &amp; health", dashboard.data)
        self.assertNotIn(b"data-system-health", dashboard.data)
        self.assertNotIn(b"data-provider-results", dashboard.data)
        self.assertNotIn(b"data-incident-rows", dashboard.data)
        self.assertIn(b"<span>Authentication</span>", dashboard.data)
        self.assertIn(b"TOP THREAT INDICATORS", dashboard.data)
        self.assertIn(b"data-email-rows", dashboard.data)
        self.assertNotIn(b"data-auth-methods", dashboard.data)
        self.assertIn(b'href="/authentication"', dashboard.data)
        self.assertNotIn(b"data-event-rows", dashboard.data)
        self.assertNotIn(b"LATEST SECURITY EVENTS", dashboard.data)
        self.assertNotIn(b"Reports &amp; events", dashboard.data)

        email_page = self.client.get("/email")
        self.assertEqual(email_page.status_code, 200)
        self.assertIn(b"Analyze email content", email_page.data)
        self.assertNotIn(b"data-email-module", email_page.data)
        self.assertNotIn(b"data-email-auth-methods", email_page.data)

        authentication_page = self.client.get("/authentication")
        self.assertEqual(authentication_page.status_code, 200)
        self.assertIn(b"data-authentication-page", authentication_page.data)
        self.assertIn(b"data-authentication-methods", authentication_page.data)
        self.assertIn(b"data-authentication-rows", authentication_page.data)
        for source in (b"email", b"file", b"url"):
            self.assertIn(
                b'data-auth-history-tab="' + source + b'"',
                authentication_page.data,
            )
            self.assertIn(
                b'data-auth-history-panel="' + source + b'"',
                authentication_page.data,
            )

        history_page = self.client.get("/history")
        self.assertEqual(history_page.status_code, 200)
        self.assertIn(b"data-investigation-history", history_page.data)
        self.assertIn(b"All modules", history_page.data)
        self.assertIn(b"data-history-rows", history_page.data)
        self.assertIn(b"Export CSV", history_page.data)
        self.assertEqual(self.client.get("/events").status_code, 404)
        endpoints = (
            "/api/dashboard/summary",
            "/api/dashboard/activity",
            "/api/dashboard/threat-distribution",
            "/api/dashboard/recent-events",
            "/api/dashboard/email-statistics",
            "/api/dashboard/email-statistics?range=all",
            "/api/dashboard/url-statistics",
            "/api/dashboard/file-statistics",
            "/api/dashboard/authentication-statistics",
            "/api/dashboard/threat-intelligence",
            "/api/dashboard/incidents",
            "/api/dashboard/top-indicators",
            "/api/dashboard/system-health",
            "/api/dashboard/search?q=example",
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, "application/json")

        summary = self.client.get("/api/dashboard/summary").get_json()
        self.assertEqual(summary["kpis"][0]["value"], 0)
        events = self.client.get("/api/dashboard/recent-events").get_json()
        self.assertEqual(events["events"], [])
        self.assertEqual(events["total"], 0)

    def test_all_time_email_view_includes_historical_reports(self):
        with web_app._connection() as connection:
            connection.execute(
                """
                INSERT INTO email_scans
                (id, subject, sender, risk_score, risk_level, results_json, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "historical-email",
                    "Old report",
                    "sender@example.test",
                    12,
                    "Low",
                    json.dumps({"subject": "Old report", "sender": "sender@example.test"}),
                    "2010-06-15 12:00:00",
                ),
            )

        response = self.client.get("/api/dashboard/email-statistics?range=all")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["records"][0]["id"], "historical-email")

        searched = self.client.get(
            "/api/dashboard/email-statistics"
            "?range=all&page=1&page_size=1&q=historical-email"
        )
        self.assertEqual(searched.status_code, 200)
        searched_payload = searched.get_json()
        self.assertEqual(searched_payload["records_total"], 1)
        self.assertEqual(searched_payload["records"][0]["id"], "historical-email")

    def test_real_scan_records_feed_summary_events_and_csv(self):
        scanned_at = (datetime.now() - timedelta(seconds=5)).replace(
            microsecond=0
        ).strftime("%Y-%m-%d %H:%M:%S")
        email_results = {
            "sender": "alerts@sender.example",
            "sender_domain": "sender.example",
            "subject": "Urgent account review",
            "to": "analyst@example.test",
            "verdict": "High risk",
            "authentication": {"spf": "fail", "dkim": "unknown", "dmarc": "fail"},
            "links": [{"url": "https://login.example.test"}],
            "attachments": [],
            "findings": [{"title": "Credential request"}],
        }
        file_results = {
            "engines": [{
                "provider": "ClamAV",
                "status": "complete",
                "detections": 1,
            }],
            "file_type": "application/octet-stream",
        }
        with web_app._connection() as connection:
            connection.execute(
                "INSERT INTO scans (url, result, probability, risk_level, scan_time) "
                "VALUES (?, ?, ?, ?, ?)",
                ("https://login.example.test", "PHISHING", 96.5, "High", scanned_at),
            )
            connection.execute(
                """
                INSERT INTO email_scans
                (id, subject, sender, risk_score, risk_level, results_json, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "email-test-id",
                    "Urgent account review",
                    "alerts@sender.example",
                    92,
                    "Critical",
                    json.dumps(email_results),
                    scanned_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO file_scans
                (id, filename, file_size, sha256, file_type, status, message,
                 results_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "file-test-id",
                    "invoice.bin",
                    2048,
                    "a" * 64,
                    "application/octet-stream",
                    "complete",
                    "Detection reported",
                    json.dumps(file_results),
                    scanned_at,
                    scanned_at,
                ),
            )

        summary = self.client.get("/api/dashboard/summary").get_json()
        values = {item["key"]: item["value"] for item in summary["kpis"]}
        self.assertEqual(values["emails"], 1)
        self.assertEqual(values["files"], 1)
        self.assertEqual(values["urls"], 1)
        self.assertEqual(values["events"], 3)
        self.assertEqual(values["phishing_emails"], 1)
        self.assertEqual(values["malicious_files"], 1)
        self.assertEqual(values["malicious_urls"], 1)

        events = self.client.get("/api/dashboard/recent-events").get_json()
        self.assertEqual(events["total"], 3)
        self.assertEqual(
            {event["source_type"] for event in events["events"]},
            {"email", "file", "url"},
        )
        file_history = self.client.get(
            "/api/dashboard/file-statistics?range=all&page=1&page_size=1"
        ).get_json()
        self.assertEqual(file_history["total"], 1)
        self.assertEqual(file_history["records"][0]["id"], "file-test-id")
        url_history = self.client.get(
            "/api/dashboard/url-statistics?range=all&page=1&page_size=1"
        ).get_json()
        self.assertEqual(url_history["total"], 1)
        self.assertEqual(url_history["records"][0]["url"], "https://login.example.test")
        history_page = self.client.get("/history")
        self.assertEqual(history_page.status_code, 200)
        self.assertIn(b"UNIFIED SCAN TIMELINE", history_page.data)
        authentication_page = self.client.get("/authentication")
        self.assertEqual(authentication_page.status_code, 200)
        self.assertIn(b"Email authentication history", authentication_page.data)
        authentication = self.client.get(
            "/api/dashboard/authentication-statistics"
        ).get_json()
        self.assertEqual(authentication["methods"]["spf"]["fail"], 1)
        self.assertEqual(authentication["methods"]["dkim"]["unknown"], 1)
        self.assertEqual(authentication["methods"]["dmarc"]["fail"], 1)
        self.assertEqual(
            self.client.get("/api/dashboard/incidents").get_json()["total"],
            3,
        )
        csv_response = self.client.get("/api/dashboard/recent-events.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn(b"Event ID", csv_response.data)
        self.assertIn(b"invoice.bin", csv_response.data)

    def test_incident_update_requires_csrf_and_valid_status(self):
        with web_app._connection() as connection:
            connection.execute(
                "INSERT INTO scans (url, result, probability, risk_level, scan_time) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "https://bad.example",
                    "PHISHING",
                    90,
                    "High",
                    (datetime.now() - timedelta(seconds=5)).replace(
                        microsecond=0
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
        incident = self.client.get("/api/dashboard/incidents").get_json()["incidents"][0]
        url = f"/api/dashboard/incidents/{incident['id']}"
        payload = {"status": "Investigating", "assigned_analyst": "SOC analyst"}

        rejected = self.client.patch(url, json=payload)
        self.assertEqual(rejected.status_code, 400)
        invalid = self.client.patch(
            url,
            json={"status": "Unknown"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(invalid.status_code, 400)
        accepted = self.client.patch(
            url,
            json=payload,
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.get_json()["status"], "Investigating")
        self.assertEqual(accepted.get_json()["assigned_analyst"], "SOC analyst")

    def test_rejects_invalid_dashboard_ranges_and_activity_buckets(self):
        invalid_range = self.client.get("/api/dashboard/summary?range=unknown")
        self.assertEqual(invalid_range.status_code, 400)
        invalid_bucket = self.client.get("/api/dashboard/activity?bucket=1m")
        self.assertEqual(invalid_bucket.status_code, 400)
