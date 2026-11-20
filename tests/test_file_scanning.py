import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as web_app
import file_analysis


class FileScanningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        web_app.app.config.update(
            TESTING=True,
            DATABASE=str(root / "test.db"),
            UPLOAD_DIR=str(root / "uploads"),
            MAX_UPLOAD_BYTES=16,
            MAX_CONTENT_LENGTH=1024 * 1024,
        )
        web_app.init_db()
        self.client = web_app.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _csrf_token(self):
        self.client.get("/files")
        with self.client.session_transaction() as current_session:
            return current_session["_csrf_token"]

    def test_existing_url_pages_and_file_scanner_render(self):
        for route in ("/", "/dashboard", "/history", "/files"):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 200)
        response = self.client.get("/files")
        self.assertIn(b"SCANNER READINESS", response.data)
        self.assertIn(b"VirusTotal", response.data)
        self.assertNotIn(b"Recent file analyses", response.data)
        self.assertNotIn(b"file-recent-panel", response.data)

    @patch.dict("os.environ", {}, clear=True)
    @patch.object(file_analysis.shutil, "which", return_value=None)
    def test_scanner_readiness_requires_clamav_and_valid_cloud_setup(
        self, _which
    ):
        self.assertEqual(
            [scanner["configured"] for scanner in file_analysis.get_scanner_configuration()],
            [False, False, False],
        )

        database_dir = Path(self.temp_dir.name) / "clamav-db"
        database_dir.mkdir()
        (database_dir / "main.cvd").write_bytes(b"test-signature-database")
        clamscan_path = Path(self.temp_dir.name) / "clamscan.exe"
        clamscan_path.write_bytes(b"test executable")
        with patch.dict(
            "os.environ",
            {
                "CLAMSCAN_PATH": str(clamscan_path),
                "CLAMAV_DATABASE_DIR": str(database_dir),
                "VT_API_KEY": "test-key",
                "OPSWAT_API_KEY": "test-key",
                "OPSWAT_MAX_UPLOAD_BYTES": "5000000",
            },
        ):
            configured = file_analysis.get_scanner_configuration()

        self.assertEqual([scanner["configured"] for scanner in configured], [True] * 3)
        self.assertNotIn("test-key", repr(configured))

    @patch.dict(
        "os.environ",
        {
            "CLAMSCAN_PATH": "C:\\ClamAV\\clamscan.exe",
            "CLAMAV_DATABASE_DIR": "C:\\ClamAV\\database",
        },
    )
    @patch.object(file_analysis.subprocess, "run")
    def test_clamav_uses_configured_signature_directory(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""

        result = file_analysis.scan_with_clamav("sample.bin")

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            run.call_args.args[0],
            [
                "C:\\ClamAV\\clamscan.exe",
                "--no-summary",
                "--infected",
                "--database",
                "C:\\ClamAV\\database",
                "sample.bin",
            ],
        )

    @patch.object(web_app.file_scan_executor, "submit")
    def test_upload_streams_to_private_storage_and_queues_local_scan(self, submit):
        payload = b"MZsample-data"
        response = self.client.post(
            "/files/scan",
            data={
                "csrf_token": self._csrf_token(),
                "file": (io.BytesIO(payload), "../sample.exe"),
            },
            headers={"X-CSRF-Token": self._csrf_token()},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 202)
        scan_id = json.loads(response.data)["url"].rsplit("/", 1)[-1]
        with web_app._connection() as conn:
            scan = conn.execute(
                "SELECT * FROM file_scans WHERE id = ?", (scan_id,)
            ).fetchone()
        self.assertEqual(scan["filename"], "sample.exe")
        self.assertEqual(scan["file_size"], len(payload))
        self.assertEqual(scan["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(scan["status"], "queued")
        self.assertFalse(submit.call_args.args[-1])

    @patch.object(web_app.file_scan_executor, "submit")
    def test_rejects_files_over_configured_limit(self, submit):
        response = self.client.post(
            "/files/scan",
            data={
                "csrf_token": self._csrf_token(),
                "file": (io.BytesIO(b"x" * 17), "large.bin"),
            },
            headers={"X-CSRF-Token": self._csrf_token()},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 413)
        self.assertIn(b"upload limit", response.data)
        with web_app._connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM file_scans").fetchone()[0]
        self.assertEqual(count, 0)
        submit.assert_not_called()
        self.assertEqual(list(Path(web_app.app.config["UPLOAD_DIR"]).glob("*")), [])

    def test_rejects_upload_without_csrf_token(self):
        response = self.client.post(
            "/files/scan",
            data={"file": (io.BytesIO(b"content"), "sample.bin")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"form expired", response.data)

    def test_startup_marks_interrupted_jobs_failed_and_removes_temp_sample(self):
        scan_id = "c" * 32
        sample_path = Path(web_app.app.config["UPLOAD_DIR"]) / f"{scan_id}.upload"
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        sample_path.write_bytes(b"unfinished")
        with web_app._connection() as conn:
            conn.execute("""
                INSERT INTO file_scans
                (id, filename, file_size, sha256, file_type, status, message,
                 results_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'scanning', '', '{}', 'now', 'now')
            """, (scan_id, "sample.bin", 10, "c" * 64, "Unknown"))

        web_app.init_db()

        self.assertFalse(sample_path.exists())
        with web_app._connection() as conn:
            status = conn.execute(
                "SELECT status FROM file_scans WHERE id = ?", (scan_id,)
            ).fetchone()["status"]
        self.assertEqual(status, "failed")

    @patch.object(file_analysis, "submit_to_external_providers")
    @patch.object(
        file_analysis,
        "scan_with_clamav",
        return_value={"provider": "ClamAV", "status": "not_configured"},
    )
    def test_external_providers_are_not_called_without_consent(
        self, _clamav, submit_external
    ):
        sample_path = Path(self.temp_dir.name) / "sample.exe"
        sample_path.write_bytes(b"MZsample")
        results = file_analysis.analyze_file(
            sample_path,
            "sample.exe",
            8,
            hashlib.sha256(b"MZsample").hexdigest(),
            False,
        )

        self.assertEqual(_clamav.call_count, 1)
        submit_external.assert_not_called()
        self.assertEqual(
            [engine["status"] for engine in results["engines"][1:]],
            ["not_shared", "not_shared"],
        )

    def test_identifies_file_type_from_signature_not_extension(self):
        sample_path = Path(self.temp_dir.name) / "sample.txt"
        sample_path.write_bytes(b"MZ" + b"\x00" * 20)
        self.assertEqual(
            file_analysis.identify_file_type(sample_path),
            "Windows executable (PE)",
        )

    def test_file_verdict_distinguishes_detection_no_detection_and_unscanned(self):
        malicious = file_analysis.summarize_file_verdict([
            {"provider": "ClamAV", "status": "complete", "detections": 1},
        ])
        self.assertEqual(malicious["status"], "threat_detected")
        self.assertIn("ClamAV", malicious["message"])

        no_detections = file_analysis.summarize_file_verdict([
            {"provider": "ClamAV", "status": "complete", "detections": 0},
            {"provider": "VirusTotal", "status": "not_shared"},
        ])
        self.assertEqual(no_detections["status"], "no_detections")
        self.assertIn("No detections", no_detections["label"])

        inconclusive = file_analysis.summarize_file_verdict([
            {"provider": "ClamAV", "status": "not_configured"},
            {"provider": "VirusTotal", "status": "not_shared"},
        ])
        self.assertEqual(inconclusive["status"], "inconclusive")
        self.assertIn("not been cleared as safe", inconclusive["message"])

    @patch(
        "app.analyze_file",
        return_value={
            "file_type": "Text or unknown",
            "engines": [
                {
                    "provider": "ClamAV",
                    "status": "not_configured",
                    "message": "Install ClamAV and ensure clamscan is on PATH.",
                }
            ],
        },
    )
    def test_worker_saves_results_removes_sample_and_serves_report(self, _analyze):
        scan_id = "a" * 32
        sample_path = Path(web_app.app.config["UPLOAD_DIR"]) / f"{scan_id}.upload"
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        sample_path.write_bytes(b"sample")
        with web_app._connection() as conn:
            conn.execute("""
                INSERT INTO file_scans
                (id, filename, file_size, sha256, file_type, status, message,
                 results_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'queued', '', '{}', 'now', 'now')
            """, (scan_id, "sample.txt", 6, "b" * 64, "Pending identification"))

        web_app._process_file(
            scan_id, str(sample_path), "sample.txt", 6, "b" * 64, False
        )

        _analyze.assert_called_once()
        self.assertFalse(sample_path.exists())
        response = self.client.get(f"/files/{scan_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Engine and provider status", response.data)
        self.assertIn(b"Unable to determine", response.data)
        self.assertIn(b"CLAMSCAN_PATH", response.data)
        with web_app._connection() as conn:
            record = conn.execute(
                "SELECT status, file_type, results_json FROM file_scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["file_type"], "Text or unknown")
        self.assertEqual(
            json.loads(record["results_json"])["sha256"], "b" * 64
        )

    @patch.object(file_analysis.requests, "post")
    def test_skips_virustotal_over_its_provider_upload_limit(self, post):
        result = file_analysis._send_virustotal_file(
            "does-not-need-to-exist",
            "sample.bin",
            file_analysis.VIRUSTOTAL_MAX_UPLOAD_BYTES + 1,
            "a" * 64,
            "test-key",
        )

        self.assertEqual(result["status"], "skipped")
        post.assert_not_called()

    @patch.object(file_analysis.requests, "post")
    @patch.object(file_analysis.requests, "get")
    @patch.object(file_analysis, "_poll_virustotal_analysis")
    def test_virustotal_uses_large_file_upload_url(self, poll, get, post):
        get.return_value.ok = True
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "data": "http://www.virustotal.com/_ah/upload/test-token/"
        }
        post.return_value.ok = True
        post.return_value.status_code = 200
        post.return_value.json.return_value = {"data": {"id": "analysis-id"}}
        poll.return_value = {
            "provider": "VirusTotal",
            "status": "complete",
            "analysis_id": "analysis-id",
        }
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        sample_path.write_bytes(b"sample")

        result = file_analysis._send_virustotal_file(
            sample_path,
            "sample.bin",
            file_analysis.VIRUSTOTAL_STANDARD_UPLOAD_BYTES + 1,
            "a" * 64,
            "test-key",
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["analysis_id"], "analysis-id")
        poll.assert_called_once_with("analysis-id", "a" * 64, "test-key")
        get.assert_called_once()
        self.assertIn("/files/upload_url", get.call_args.args[0])
        self.assertEqual(
            post.call_args.args[0],
            "https://www.virustotal.com/_ah/upload/test-token/",
        )

    @patch.object(file_analysis.requests, "get")
    def test_virustotal_report_aggregates_completed_engine_counts(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"malicious": 2, "suspicious": 1},
                }
            }
        }

        result = file_analysis._poll_virustotal_analysis(
            "analysis-id", "a" * 64, "test-key"
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["detections"], 3)
        self.assertEqual(result["stats"]["malicious"], 2)

    def test_virustotal_upload_url_must_target_trusted_tls_host(self):
        self.assertIsNone(
            file_analysis._safe_virustotal_upload_url("https://example.com/upload")
        )
        self.assertIsNone(
            file_analysis._safe_virustotal_upload_url(
                "https://www.virustotal.com:444/upload"
            )
        )
        self.assertEqual(
            file_analysis._safe_virustotal_upload_url(
                "http://www.virustotal.com/_ah/upload/token"
            ),
            "https://www.virustotal.com/_ah/upload/token",
        )

    @patch.object(file_analysis.requests, "get")
    def test_opswat_report_aggregates_completed_engine_counts(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "scan_results": {
                "progress_percentage": 100,
                "total_detected_avs": 2,
                "total_avs": 35,
            }
        }

        result = file_analysis._poll_opswat_scan("scan-id", "test-key")

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["detections"], 2)
        self.assertEqual(result["total_engines"], 35)


if __name__ == "__main__":
    unittest.main()
