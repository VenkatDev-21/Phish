import json
import tempfile
import unittest
from pathlib import Path

import app as web_app
from security import LIMITER, RateRule


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.original = {
            key: web_app.app.config.get(key)
            for key in (
                "ACCESS_CODE",
                "RATE_LIMIT_ENABLED",
                "RATE_LIMIT_IN_TESTS",
                "TESTING",
                "DATABASE",
                "UPLOAD_DIR",
            )
        }
        web_app.app.config.update(
            TESTING=True,
            DATABASE=str(root / "hardening.db"),
            UPLOAD_DIR=str(root / "uploads"),
            ACCESS_CODE="",
            RATE_LIMIT_IN_TESTS=False,
        )
        web_app.init_db()
        LIMITER.clear()
        self.client = web_app.app.test_client()

    def tearDown(self):
        LIMITER.clear()
        web_app.app.config.update(self.original)
        self.temp_dir.cleanup()

    def _csrf_token(self, path="/"):
        self.client.get(path)
        with self.client.session_transaction() as current_session:
            return current_session["_csrf_token"]

    def test_security_headers_guard_every_response(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_health_endpoints_report_state(self):
        probe = self.client.get("/healthz")
        self.assertEqual(probe.status_code, 200)
        self.assertEqual(probe.get_json()["status"], "ok")
        self.assertEqual(probe.get_json()["database"], "ok")

        capabilities = self.client.get("/api/v1/health")
        self.assertEqual(capabilities.status_code, 200)
        body = capabilities.get_json()
        self.assertIn("url_scan", body["capabilities"])
        self.assertTrue(body["capabilities"]["url_features"])
        self.assertIn("public_api", body["limits"])

    def test_public_api_scan_returns_a_report_and_cors_headers(self):
        response = self.client.post(
            "/api/v1/scan/url",
            json={"url": "http://secure-account-verify.example/login"},
            headers={"Origin": "https://phishguard.example"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")
        body = response.get_json()
        for key in ("scan_id", "scanned_at", "url", "result", "risk_level",
                    "probability", "features", "engine"):
            self.assertIn(key, body)
        self.assertIn(body["result"], ("PHISHING", "LEGITIMATE"))
        self.assertIsInstance(body["probability"], float)

    def test_public_api_rejects_invalid_payloads(self):
        missing = self.client.post("/api/v1/scan/url", json={})
        self.assertEqual(missing.status_code, 400)

        bad_scheme = self.client.post(
            "/api/v1/scan/url", json={"url": "ftp://example.com"}
        )
        self.assertEqual(bad_scheme.status_code, 400)

        spaced = self.client.post(
            "/api/v1/scan/url", json={"url": "http://exa mple.com"}
        )
        self.assertEqual(spaced.status_code, 400)

        not_json = self.client.post(
            "/api/v1/scan/url", data="", content_type="application/json"
        )
        self.assertEqual(not_json.status_code, 400)

    def test_cors_preflight_is_answered(self):
        response = self.client.options(
            "/api/v1/scan/url",
            headers={
                "Origin": "https://phishguard.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")

    def test_access_gate_protects_dashboard_and_history(self):
        web_app.app.config["ACCESS_CODE"] = "correct-horse-battery"
        token = self._csrf_token("/unlock")

        redirect_response = self.client.get("/dashboard")
        self.assertEqual(redirect_response.status_code, 302)
        self.assertIn("/unlock", redirect_response.headers["Location"])

        api_response = self.client.get("/api/dashboard/summary")
        self.assertEqual(api_response.status_code, 401)
        self.assertIn("unlock_url", api_response.get_json())

        rejected = self.client.post(
            "/unlock",
            data={"csrf_token": token, "access_code": "wrong-code"},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        accepted = self.client.post(
            "/unlock",
            data={"csrf_token": token, "access_code": "correct-horse-battery"},
        )
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

        lock_token = self._csrf_token("/dashboard")
        self.client.post("/lock", data={"csrf_token": lock_token})
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_scanners_stay_open_while_history_is_gated(self):
        web_app.app.config["ACCESS_CODE"] = "open-scanners"
        for route in ("/", "/email", "/files", "/api"):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 200)

    def test_rate_limit_returns_429_with_retry_after(self):
        web_app.app.config["RATE_LIMIT_IN_TESTS"] = True
        previous = web_app.RATE_RULES["public_api"]
        web_app.RATE_RULES["public_api"] = RateRule(
            limit=1, window_seconds=60, scope="test"
        )
        try:
            first = self.client.post(
                "/api/v1/scan/url", json={"url": "https://example.com/"}
            )
            self.assertEqual(first.status_code, 201)
            second = self.client.post(
                "/api/v1/scan/url", json={"url": "https://example.com/"}
            )
            self.assertEqual(second.status_code, 429)
            self.assertIn("Retry-After", second.headers)
            self.assertIn("retry_after", second.get_json())
        finally:
            web_app.RATE_RULES["public_api"] = previous

    def test_unlock_is_inert_when_the_gate_is_disabled(self):
        response = self.client.get("/unlock")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

    def test_file_upload_still_requires_csrf(self):
        response = self.client.post("/files/scan", data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("form expired", response.get_json()["error"])

    def test_robots_and_branded_404(self):
        robots = self.client.get("/robots.txt")
        self.assertEqual(robots.status_code, 200)
        self.assertTrue(robots.mimetype.startswith("text/plain"))
        self.assertIn(b"Disallow: /dashboard", robots.data)

        missing = self.client.get("/this-page-does-not-exist")
        self.assertEqual(missing.status_code, 404)
        self.assertIn(b"Page not found", missing.data)

        missing_api = self.client.get("/api/v1/nope")
        self.assertEqual(missing_api.status_code, 404)
        self.assertEqual(missing_api.get_json()["error"], "Not found.")

    def test_api_page_and_related_routes_render(self):
        page = self.client.get("/api")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"POST /api/v1/scan/url", page.data)
        self.assertIn(b"/healthz", page.data)

    def test_scan_is_persisted_and_visible_to_the_dashboard(self):
        self.client.post(
            "/api/v1/scan/url", json={"url": "https://example.org/login"}
        )
        summary = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary.status_code, 200)
        payload = summary.get_json()
        self.assertTrue(json.dumps(payload))
        with web_app._connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        self.assertEqual(count, 1)


class RateLimiterUnitTests(unittest.TestCase):
    def test_sliding_window_blocks_and_recovers(self):
        limiter = LIMITER
        limiter.clear()
        rule = RateRule(limit=2, window_seconds=60, scope="unit")
        self.assertEqual(limiter.retry_after("1.2.3.4", rule, "demo"), 0)
        self.assertEqual(limiter.retry_after("1.2.3.4", rule, "demo"), 0)
        self.assertGreater(limiter.retry_after("1.2.3.4", rule, "demo"), 0)
        self.assertEqual(limiter.retry_after("5.6.7.8", rule, "demo"), 0)
        limiter.clear()


if __name__ == "__main__":
    unittest.main()
