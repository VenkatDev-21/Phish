import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as web_app
from email_attachment_analysis import analyze_attachment
from email_auth import lookup_domain_dns
from email_security import MAX_EMAIL_CHARACTERS, analyze_email
from email_security import parse_email_upload


class EmailSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        web_app.app.config.update(
            TESTING=True,
            DATABASE=str(Path(self.temp_dir.name) / "email-test.db"),
            UPLOAD_DIR=str(Path(self.temp_dir.name) / "uploads"),
        )
        web_app.init_db()
        self.client = web_app.app.test_client()
        self.client.get("/email")
        with self.client.session_transaction() as current_session:
            self.csrf_token = current_session["_csrf_token"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extracts_headers_authentication_sender_mismatch_and_links(self):
        message = (
            "From: Finance <finance@example.com>\n"
            "Reply-To: verify@other.example\n"
            "Subject: Account verification\n"
            "Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail\n"
            "\n"
            "Review your account at http://192.0.2.10/login\n"
        )

        result = analyze_email(message)

        self.assertEqual(result["subject"], "Account verification")
        self.assertEqual(result["sender_domain"], "example.com")
        self.assertEqual(result["authentication"]["spf"], "fail")
        self.assertEqual(result["authentication"]["dmarc"], "fail")
        self.assertEqual(result["risk_level"], "High")
        self.assertIn("192.0.2.10", result["links"][0]["host"])
        self.assertTrue(any("Reply-To" in finding["title"] for finding in result["findings"]))

    def test_parses_received_spf_and_html_anchor_mismatch_without_opening_links(self):
        message = (
            "From: updates@brand.example\n"
            "Subject: Please review\n"
            "Received-SPF: softfail (mail.example: domain does not designate)\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/html; charset=utf-8\n"
            "\n"
            '<a href="https://lookalike.example/login">https://brand.example</a>'
        )

        result = analyze_email(message)

        self.assertEqual(result["authentication"]["spf"], "softfail")
        self.assertEqual(len(result["links"]), 2)
        self.assertTrue(any(link["anchor_mismatch"] for link in result["links"]))
        self.assertTrue(
            any("link text differs" in finding["title"].lower() for finding in result["findings"])
        )

    def test_accepts_a_pasted_subject_body_or_single_url(self):
        for pasted_text in (
            "Subject: One line\n\nA short message",
            "https://example.net/path",
            "Just a pasted body",
        ):
            with self.subTest(pasted_text=pasted_text):
                result = analyze_email(pasted_text)
                self.assertIn(result["risk_level"], ("Low", "Medium", "High", "Critical"))

    def test_rejects_empty_or_oversized_input(self):
        with self.assertRaises(ValueError):
            analyze_email(" \n ")
        with self.assertRaises(ValueError):
            analyze_email("x" * (MAX_EMAIL_CHARACTERS + 1))

    def test_authentication_headers_are_unverified_and_dmarc_alignment_is_reported(self):
        message = (
            "From: alerts@shop.example.com\n"
            "Authentication-Results: mx.example; "
            "spf=pass smtp.mailfrom=mailer.example.com; "
            "dkim=pass header.d=example.com; "
            "dmarc=pass header.from=shop.example.com\n"
            "DKIM-Signature: v=1; d=example.com; s=notice;\n"
            "\n"
            "Your receipt is ready."
        )

        result = analyze_email(message)

        self.assertEqual(result["authentication"]["spf"], "pass")
        self.assertEqual(result["authentication"]["dkim"], "pass")
        self.assertEqual(
            result["authentication_details"]["dmarc"]["reported_alignment"],
            "reported pass with an aligned mechanism",
        )
        self.assertIn(
            "not independently verified",
            result["authentication_details"]["dkim"]["evidence"],
        )
        self.assertEqual(result["authentication_details"]["dkim"]["selectors"], ["notice"])

    def test_dkim_signature_alone_does_not_count_as_a_pass_or_alignment(self):
        signature_only = analyze_email(
            "From: alerts@example.com\n"
            "DKIM-Signature: v=1; d=example.com; s=notice;\n"
            "\n"
            "Please review."
        )
        self.assertEqual(signature_only["authentication"]["dkim"], "unknown")
        self.assertEqual(signature_only["authentication_details"]["dkim"]["domains"], [])
        self.assertEqual(
            signature_only["authentication_details"]["dkim"]["signature_domains"],
            ["example.com"],
        )

        message = (
            "From: alerts@example.com\n"
            "DKIM-Signature: v=1; d=example.com; s=notice;\n"
            "Authentication-Results: mx.example; dmarc=pass header.from=example.com\n"
            "Authentication-Results: other.example; dkim=pass header.d=example.com\n"
            "\n"
            "Please review."
        )

        result = analyze_email(message)

        self.assertEqual(result["authentication"]["dkim"], "pass")
        self.assertEqual(
            result["authentication_details"]["dmarc"]["reported_alignment"],
            "reported pass without a matching aligned mechanism",
        )
        self.assertEqual(result["authentication_details"]["dkim"]["domains"], ["example.com"])

    @patch("email_auth.lookup_domain_dns")
    def test_dns_lookup_is_opt_in_and_exposes_query_results(self, lookup):
        lookup.return_value = {
            "domain": "example.com",
            "checked": True,
            "spf": {"status": "found", "records": ["v=spf1 -all"]},
            "dmarc": {
                "status": "found",
                "records": ["v=DMARC1; p=reject"],
                "policy": "reject",
            },
            "mx": {"status": "found", "records": ["mx.example.com"]},
            "a": {"status": "found", "records": ["192.0.2.1"]},
            "ns": {"status": "found", "records": ["ns.example.com"]},
        }
        message = "From: sender@example.com\n\nReview this message."

        result_without_lookup = analyze_email(message)
        lookup.assert_not_called()
        result_with_lookup = analyze_email(message, dns_lookup=True)

        lookup.assert_called_once_with("example.com")
        self.assertEqual(result_without_lookup["dns"]["checked"], False)
        self.assertEqual(result_with_lookup["dns"]["a"]["records"], ["192.0.2.1"])

    @patch("email_auth.lookup_domain_dns")
    def test_dmarc_alignment_obeys_published_strict_spf_policy(self, lookup):
        lookup.return_value = {
            "domain": "shop.example.com",
            "checked": True,
            "spf": {"status": "found", "records": ["v=spf1 -all"]},
            "dmarc": {
                "status": "found",
                "records": ["v=DMARC1; p=reject; aspf=s"],
                "policy": "reject",
            },
            "mx": {"status": "no_record", "records": []},
            "a": {"status": "no_record", "records": []},
            "ns": {"status": "no_record", "records": []},
        }
        message = (
            "From: alerts@shop.example.com\n"
            "Authentication-Results: mx.example; "
            "spf=pass smtp.mailfrom=mailer.example.com; "
            "dmarc=pass header.from=shop.example.com\n\n"
            "Please review."
        )

        result = analyze_email(message, dns_lookup=True)

        self.assertEqual(result["dns"]["dmarc"]["spf_alignment"], "strict")
        self.assertEqual(
            result["authentication_details"]["dmarc"]["reported_alignment"],
            "reported pass without a matching aligned mechanism",
        )

    @patch("email_auth._lookup", return_value={"status": "no_record", "records": []})
    @patch("email_auth._txt_records")
    @patch("email_auth.dns.resolver.Resolver")
    def test_dns_dmarc_lookup_falls_back_to_organizational_domain(
        self, resolver, txt_records, _lookup_records
    ):
        txt_records.side_effect = [
            [],
            [],
            ["v=DMARC1; p=reject"],
        ]

        result = lookup_domain_dns("mail.shop.example.com")

        self.assertEqual(result["dmarc"]["record_domain"], "example.com")
        self.assertEqual(result["dmarc"]["policy"], "reject")
        self.assertEqual(txt_records.call_count, 3)
        resolver.assert_called_once_with()
        self.assertEqual(_lookup_records.call_count, 3)

    def test_existing_url_model_is_used_for_email_links(self):
        class FakeModel:
            feature_names_in_ = [
                "url_length", "hostname_length", "dot_count", "hyphen_count",
                "slash_count", "digit_count", "special_char_count", "has_at_symbol",
                "has_ip", "https", "subdomain_count", "has_login_word",
            ]
            classes_ = ["legitimate", "phishing"]

            def predict(self, frame):
                self.assert_features(frame)
                return ["phishing"]

            def predict_proba(self, frame):
                self.assert_features(frame)
                return [[0.08, 0.92]]

            def assert_features(self, frame):
                if list(frame.columns) != self.feature_names_in_:
                    raise AssertionError("URL feature columns did not match the model.")

        result = analyze_email(
            "Please sign in: https://example.net/login",
            url_model=FakeModel(),
        )

        self.assertEqual(result["links"][0]["model"]["prediction"], "phishing")
        self.assertEqual(result["links"][0]["model"]["phishing_probability"], 92.0)

    def test_uploaded_eml_extracts_attachment_without_retaining_body(self):
        raw_message = (
            b"From: alerts@example.com\r\n"
            b"Subject: Review this document\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=mail-boundary\r\n"
            b"\r\n"
            b"--mail-boundary\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please review https://example.net/notice\r\n"
            b"--mail-boundary\r\n"
            b"Content-Type: text/plain; name=notice.txt\r\n"
            b"Content-Disposition: attachment; filename=notice.txt\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"dmVyaWZ5IHlvdXIgcGFzc3dvcmQgYXQgaHR0cHM6Ly9leGFtcGxlLm5ldC9sb2dpbg==\r\n"
            b"--mail-boundary--\r\n"
        )
        message = parse_email_upload("sample.eml", raw_message)

        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {
                "file_type": "Text or unknown",
                "engines": [{
                    "provider": "ClamAV",
                    "status": "not_configured",
                    "message": "ClamAV is unavailable.",
                }],
            }
            result = analyze_email(
                "",
                parsed_message=message,
                external_consent=False,
            )

        self.assertEqual(result["input_kind"], "Uploaded email file")
        self.assertEqual(result["attachments"][0]["filename"], "notice.txt")
        self.assertIn(
            "https://example.net/login",
            result["attachments"][0]["extracted_urls"],
        )
        self.assertTrue(any("Credential collection" in finding["title"] for finding in result["findings"]))
        self.assertNotIn("verify your password", str(result))
        scan_file.assert_called_once()
        self.assertFalse(scan_file.call_args.args[-1])

    def test_unavailable_body_parser_reports_the_part(self):
        message = (
            "From: sender@example.com\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=not-a-real-charset\n\n"
            "Read this body."
        )

        result = analyze_email(message)

        self.assertTrue(any(
            finding["title"] == "Email body could not be decoded"
            for finding in result["findings"]
        ))

    def test_rejects_msg_and_oversized_email_files_explicitly(self):
        with self.assertRaisesRegex(ValueError, r"\.msg files are not supported"):
            parse_email_upload("outlook.msg", b"sample")
        with self.assertRaisesRegex(ValueError, "20 MiB"):
            parse_email_upload("large.eml", b"x" * (20 * 1024 * 1024 + 1))

    def test_attachment_detection_and_zip_expansion_limits(self):
        import zipfile

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("invoice.pdf.exe", b"MZ" + b"x" * 100)
            archive.writestr("mail.html", '<form><input type="password"></form>')
        archive_bytes = archive_buffer.getvalue()

        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {
                "engines": [{"provider": "ClamAV", "status": "not_configured"}],
            }
            result = analyze_attachment("bundle.zip", archive_bytes)

        self.assertEqual(result["actual_type"], "ZIP archive")
        self.assertTrue(any("Executable or script" in item["title"] for item in result["findings"]))
        self.assertTrue(any("HTML form" in item["title"] for item in result["findings"]))
        self.assertEqual(result["status"], "analyzed")
        scan_file.assert_called_once()

    def test_archive_expansion_limit_prevents_member_inspection(self):
        import zipfile

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.txt", "x" * 100)

        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {"engines": []}
            with patch("email_attachment_analysis.MAX_ARCHIVE_EXPANDED_BYTES", 50):
                result = analyze_attachment("bundle.zip", archive_buffer.getvalue())

        self.assertTrue(any(
            finding["title"] == "Archive expansion limit exceeded"
            for finding in result["findings"]
        ))
        self.assertEqual(result["extracted_urls"], [])
        scan_file.assert_called_once()

    def test_oversized_attachment_is_skipped_before_scanning(self):
        with patch("email_attachment_analysis.analyze_file") as scan_file:
            with patch("email_attachment_analysis.MAX_ATTACHMENT_BYTES", 4):
                result = analyze_attachment("sample.txt", b"12345")

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["scanners"]["engines"][0]["status"], "skipped")
        scan_file.assert_not_called()

    def test_malformed_pdf_is_reported_without_aborting_email_analysis(self):
        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {"engines": []}
            result = analyze_attachment(
                "broken.pdf",
                b"%PDF-1.7\nthis is not a PDF",
            )

        self.assertEqual(result["status"], "analyzed")
        self.assertTrue(any(
            finding["title"] == "PDF could not be parsed"
            for finding in result["findings"]
        ))

    def test_invalid_attachment_payload_is_reported_instead_of_raising(self):
        result = analyze_email(
            "From: sender@example.com\n\nReview this message.",
            attachments=[None],
        )

        self.assertEqual(result["attachments"][0]["status"], "error")
        self.assertEqual(result["attachments"][0]["filename"], "unknown")

    def test_report_saves_findings_not_raw_message_body_and_updates_dashboard(self):
        secret_body_text = "PRIVATE BODY TEXT THAT MUST NOT BE SAVED"
        response = self.client.post(
            "/email/analyze",
            data={
                "csrf_token": self.csrf_token,
                "email_content": (
                    "From: alerts@example.com\n"
                    "Subject: Monthly update\n\n"
                    f"{secret_body_text}"
                ),
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"EMAIL SECURITY REPORT", response.data)
        self.assertIn(b'data-risk-bar', response.data)
        self.assertNotIn(b'style="width: {{', response.data)
        with web_app._connection() as conn:
            row = conn.execute("SELECT * FROM email_scans").fetchone()
        self.assertNotIn(secret_body_text, row["results_json"])
        self.assertNotIn(secret_body_text, row["subject"])
        self.assertEqual(json.loads(row["results_json"])["subject"], "Monthly update")

        email_page = self.client.get("/email")
        self.assertEqual(email_page.status_code, 200)
        self.assertIn(b"Analyze an ", email_page.data)
        self.assertNotIn(b"Message investigation history", email_page.data)
        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Message risk overview", dashboard.data)
        email_data = self.client.get(
            "/api/dashboard/email-statistics"
            "?range=custom&start=2000-01-01T00:00&end=2099-01-01T00:00"
        ).get_json()
        self.assertIn(
            "Monthly update",
            [record["subject"] for record in email_data["records"]],
        )

    def test_email_attachment_route_and_json_export_respect_local_default(self):
        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {
                "file_type": "Text or unknown",
                "engines": [{
                    "provider": "ClamAV",
                    "status": "not_configured",
                    "message": "ClamAV is unavailable.",
                }],
            }
            response = self.client.post(
                "/email/analyze",
                data={
                    "csrf_token": self.csrf_token,
                    "email_content": "From: sender@example.com\n\nPlease review.",
                    "attachments": (io.BytesIO(b"read this file"), "note.txt"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 302)
        scan_file.assert_called_once()
        self.assertFalse(scan_file.call_args.args[-1])

        report_response = self.client.get(response.headers["Location"])
        self.assertEqual(report_response.status_code, 200)
        self.assertIn(b"note.txt", report_response.data)

        export_response = self.client.get(response.headers["Location"] + "/export.json")
        self.assertEqual(export_response.status_code, 200)
        self.assertIn("attachment;", export_response.headers["Content-Disposition"])
        self.assertNotIn(b"Please review.", export_response.data)

    def test_email_route_requires_consent_to_forward_attachment(self):
        with patch("email_attachment_analysis.analyze_file") as scan_file:
            scan_file.return_value = {"engines": []}
            response = self.client.post(
                "/email/analyze",
                data={
                    "csrf_token": self.csrf_token,
                    "email_content": "From: sender@example.com\n\nReview.",
                    "external_consent": "on",
                    "attachments": (io.BytesIO(b"local attachment"), "note.txt"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(scan_file.call_args.args[-1])

    def test_email_route_enforces_its_request_limit_before_form_parsing(self):
        with patch.object(web_app, "MAX_EMAIL_REQUEST_BYTES", 10):
            response = self.client.post(
                "/email/analyze",
                data={"csrf_token": self.csrf_token, "email_content": "too large"},
            )

        self.assertEqual(response.status_code, 413)
        self.assertIn(b"Email requests must be", response.data)

    def test_email_health_endpoint_documents_supported_inputs(self):
        response = self.client.get("/api/email/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["inputs"],
            ["paste", ".eml", ".txt", ".html", ".htm"],
        )

    def test_report_renders_when_url_model_is_unavailable(self):
        loaded_model = web_app.model
        web_app.model = None
        try:
            response = self.client.post(
                "/email/analyze",
                data={
                    "csrf_token": self.csrf_token,
                    "email_content": "From: sender@example.com\n\nhttps://example.net/login",
                },
                follow_redirects=True,
            )
        finally:
            web_app.model = loaded_model

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"example.net", response.data)

    def test_rejects_email_analysis_without_csrf_token(self):
        response = self.client.post(
            "/email/analyze",
            data={"email_content": "Subject: test\n\nhello"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"form expired", response.data)


if __name__ == "__main__":
    unittest.main()
