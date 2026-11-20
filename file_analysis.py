import os
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests_toolbelt import MultipartEncoder


VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
OPSWAT_API = "https://api.metadefender.com/v4"
VIRUSTOTAL_MAX_UPLOAD_BYTES = 650_000_000
VIRUSTOTAL_STANDARD_UPLOAD_BYTES = 32_000_000
PROVIDER_POLL_INTERVAL_SECONDS = 15
PROVIDER_POLL_TIMEOUT_SECONDS = 180


def identify_file_type(file_path):
    with open(file_path, "rb") as sample:
        header = sample.read(16)

    signatures = (
        (b"MZ", "Windows executable (PE)"),
        (b"\x7fELF", "ELF executable"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document"),
        (b"\x1f\x8b", "GZIP archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    )
    for signature, label in signatures:
        if header.startswith(signature):
            return label
    if not header:
        return "Empty file"
    if b"\x00" not in header:
        return "Text or unknown"
    return "Unknown binary"


def get_scanner_configuration():
    clamscan = os.environ.get("CLAMSCAN_PATH") or shutil.which("clamscan")
    has_executable = bool(clamscan and Path(clamscan).is_file())
    database_dir = os.environ.get("CLAMAV_DATABASE_DIR")
    if not database_dir and has_executable:
        database_dir = str(Path(clamscan).resolve().parent / "database")
    has_signatures = bool(
        database_dir
        and Path(database_dir).is_dir()
        and any(
            signature.is_file()
            for pattern in ("*.cvd", "*.cld")
            for signature in Path(database_dir).glob(pattern)
        )
    )
    virustotal_configured = bool(os.environ.get("VT_API_KEY", "").strip())
    opswat_key_configured = bool(os.environ.get("OPSWAT_API_KEY", "").strip())
    opswat_limit = os.environ.get("OPSWAT_MAX_UPLOAD_BYTES", "").strip()
    try:
        opswat_limit_configured = int(opswat_limit) > 0
    except ValueError:
        opswat_limit_configured = False

    return [
        {
            "provider": "ClamAV",
            "configured": bool(has_executable and has_signatures),
            "message": (
                "Scanner and local signature database are ready."
                if has_executable and has_signatures
                else (
                    "ClamAV executable found; update signatures and set CLAMAV_DATABASE_DIR."
                    if has_executable
                    else "Install ClamAV or set CLAMSCAN_PATH."
                )
            ),
        },
        {
            "provider": "VirusTotal",
            "configured": virustotal_configured,
            "message": (
                "API key is set; sharing still requires upload consent."
                if virustotal_configured
                else "Set VT_API_KEY in the local .env file."
            ),
        },
        {
            "provider": "OPSWAT MetaDefender",
            "configured": opswat_key_configured and opswat_limit_configured,
            "message": (
                "API key and upload limit are set; sharing still requires upload consent."
                if opswat_key_configured and opswat_limit_configured
                else "Set OPSWAT_API_KEY and your account's OPSWAT_MAX_UPLOAD_BYTES."
            ),
        },
    ]


def summarize_file_verdict(engines):
    completed = [
        engine
        for engine in engines
        if engine.get("status") == "complete"
        and isinstance(engine.get("detections"), int)
        and not isinstance(engine.get("detections"), bool)
    ]
    detected = [engine for engine in completed if engine["detections"] > 0]
    if detected:
        names = ", ".join(engine["provider"] for engine in detected)
        count = sum(engine["detections"] for engine in detected)
        return {
            "status": "threat_detected",
            "label": "Potential threat detected",
            "message": (
                f"{count} detection(s) reported by {names}. Treat this file as "
                "unsafe unless you can verify otherwise."
            ),
        }

    if completed:
        pending = any(engine.get("status") == "submitted" for engine in engines)
        message = (
            f"{len(completed)} scanner(s) completed with no detections."
        )
        if pending:
            message += " Other provider scans may still be processing."
        return {
            "status": "no_detections",
            "label": "No detections by completed scanners",
            "message": message,
        }

    return {
        "status": "inconclusive",
        "label": "Unable to determine",
        "message": (
            "No antivirus scanner completed a scan. The file has not been "
            "cleared as safe."
        ),
    }


def scan_with_clamav(file_path):
    executable = os.environ.get("CLAMSCAN_PATH") or shutil.which("clamscan")
    if not executable:
        return {
            "provider": "ClamAV",
            "status": "not_configured",
            "message": "Install ClamAV and ensure clamscan is on PATH.",
        }

    command = [executable, "--no-summary", "--infected"]
    database_dir = os.environ.get("CLAMAV_DATABASE_DIR")
    if database_dir:
        command.extend(["--database", database_dir])
    command.append(str(file_path))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "provider": "ClamAV",
            "status": "timeout",
            "message": "ClamAV did not finish within 30 minutes.",
        }
    except OSError as error:
        return {
            "provider": "ClamAV",
            "status": "error",
            "message": f"Could not start ClamAV ({error.__class__.__name__}).",
        }

    if result.returncode == 0:
        return {
            "provider": "ClamAV",
            "status": "complete",
            "detections": 0,
            "message": "No detections reported by ClamAV.",
        }
    if result.returncode == 1:
        detections = sum(
            1 for line in result.stdout.splitlines() if line.rstrip().endswith("FOUND")
        )
        return {
            "provider": "ClamAV",
            "status": "complete",
            "detections": detections or 1,
            "message": "ClamAV reported a detection.",
        }
    return {
        "provider": "ClamAV",
        "status": "error",
        "message": f"ClamAV exited with status {result.returncode}.",
    }


def _provider_error(provider, error):
    return {
        "provider": provider,
        "status": "error",
        "message": f"Provider request failed ({error.__class__.__name__}).",
    }


def _provider_response_error(provider, response):
    return {
        "provider": provider,
        "status": "error",
        "message": f"Provider returned HTTP {response.status_code}.",
    }


def _response_succeeded(response):
    return 200 <= response.status_code < 300


def _json_object(response):
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _safe_virustotal_upload_url(value):
    if not isinstance(value, str):
        return None
    parsed = urlparse(value)
    trusted_host = parsed.hostname == "virustotal.com" or bool(
        parsed.hostname and parsed.hostname.endswith(".virustotal.com")
    )
    if (
        parsed.scheme not in ("http", "https")
        or not trusted_host
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        return None
    return parsed._replace(scheme="https").geturl()


def _poll_virustotal_analysis(analysis_id, sha256, api_key):
    report_url = f"https://www.virustotal.com/gui/file/{sha256}"
    headers = {"x-apikey": api_key}
    deadline = time.monotonic() + PROVIDER_POLL_TIMEOUT_SECONDS
    while True:
        try:
            response = requests.get(
                f"{VIRUSTOTAL_API}/analyses/{analysis_id}",
                headers=headers,
                timeout=(10, 30),
                allow_redirects=False,
            )
        except requests.RequestException as error:
            return {
                "provider": "VirusTotal",
                "status": "submitted",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "message": f"Sample submitted, but status lookup failed ({error.__class__.__name__}).",
            }
        if response.status_code == 429:
            return {
                "provider": "VirusTotal",
                "status": "submitted",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "message": "Sample submitted; the provider rate-limited status checks. Open its report for the latest result.",
            }
        if not _response_succeeded(response):
            return {
                "provider": "VirusTotal",
                "status": "submitted",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "message": f"Sample submitted, but status lookup returned HTTP {response.status_code}.",
            }

        payload = _json_object(response)
        data = payload.get("data") if payload else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            return {
                "provider": "VirusTotal",
                "status": "submitted",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "message": "Sample submitted; the provider returned an incomplete analysis report.",
            }
        if attributes.get("status") == "completed":
            stats = attributes.get("stats")
            if not isinstance(stats, dict):
                return {
                    "provider": "VirusTotal",
                    "status": "error",
                    "analysis_id": analysis_id,
                    "report_url": report_url,
                    "message": "VirusTotal completed the analysis without returning engine statistics.",
                }
            try:
                malicious = int(stats["malicious"])
                suspicious = int(stats["suspicious"])
            except (KeyError, TypeError, ValueError):
                return {
                    "provider": "VirusTotal",
                    "status": "error",
                    "analysis_id": analysis_id,
                    "report_url": report_url,
                    "message": "VirusTotal returned invalid engine statistics.",
                }
            detections = malicious + suspicious
            return {
                "provider": "VirusTotal",
                "status": "complete",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "detections": detections,
                "stats": stats,
                "message": (
                    f"{detections} malicious or suspicious engine detections."
                    if detections
                    else "No malicious or suspicious detections reported."
                ),
            }

        if time.monotonic() >= deadline:
            return {
                "provider": "VirusTotal",
                "status": "submitted",
                "analysis_id": analysis_id,
                "report_url": report_url,
                "message": "Sample is still processing at VirusTotal; open its report for the latest result.",
            }
        time.sleep(PROVIDER_POLL_INTERVAL_SECONDS)


def _send_virustotal_file(file_path, filename, file_size, sha256, api_key):
    headers = {"x-apikey": api_key}
    try:
        if file_size > VIRUSTOTAL_MAX_UPLOAD_BYTES:
            return {
                "provider": "VirusTotal",
                "status": "skipped",
                "message": "The file exceeds VirusTotal's 650 MB upload limit.",
            }

        upload_url = f"{VIRUSTOTAL_API}/files"
        if file_size > VIRUSTOTAL_STANDARD_UPLOAD_BYTES:
            response = requests.get(
                f"{VIRUSTOTAL_API}/files/upload_url",
                headers=headers,
                timeout=(10, 30),
                allow_redirects=False,
            )
            if not _response_succeeded(response):
                return _provider_response_error("VirusTotal", response)
            payload = _json_object(response)
            provider_upload_url = payload.get("data") if payload else None
            upload_url = _safe_virustotal_upload_url(provider_upload_url)
            if not upload_url:
                return {
                    "provider": "VirusTotal",
                    "status": "error",
                    "message": "VirusTotal returned an unexpected upload URL.",
                }

        with open(file_path, "rb") as sample:
            encoder = MultipartEncoder(
                fields={"file": (filename, sample, "application/octet-stream")}
            )
            response = requests.post(
                upload_url,
                data=encoder,
                headers={**headers, "Content-Type": encoder.content_type},
                timeout=(30, 1800),
                allow_redirects=False,
            )
        if not _response_succeeded(response):
            return _provider_response_error("VirusTotal", response)

        payload = _json_object(response)
        data = payload.get("data") if payload else None
        analysis_id = data.get("id") if isinstance(data, dict) else None
        if not analysis_id:
            return {
                "provider": "VirusTotal",
                "status": "error",
                "message": "VirusTotal did not return an analysis ID.",
            }
        return _poll_virustotal_analysis(analysis_id, sha256, api_key)
    except (requests.RequestException, ValueError) as error:
        return _provider_error("VirusTotal", error)


def _send_opswat_file(file_path, filename, file_size, api_key):
    configured_limit = os.environ.get("OPSWAT_MAX_UPLOAD_BYTES")
    if not configured_limit:
        return {
            "provider": "OPSWAT MetaDefender",
            "status": "skipped",
            "message": "Set OPSWAT_MAX_UPLOAD_BYTES to your account's upload limit before enabling file submissions.",
        }
    try:
        max_upload_bytes = int(configured_limit)
    except ValueError:
        return {
            "provider": "OPSWAT MetaDefender",
            "status": "error",
            "message": "OPSWAT_MAX_UPLOAD_BYTES must be an integer byte count.",
        }
    if max_upload_bytes <= 0:
        return {
            "provider": "OPSWAT MetaDefender",
            "status": "skipped",
            "message": "OPSWAT file submissions are disabled by configuration.",
        }
    if file_size > max_upload_bytes:
        return {
            "provider": "OPSWAT MetaDefender",
            "status": "skipped",
            "message": "The file exceeds the configured OPSWAT upload limit.",
        }

    try:
        with open(file_path, "rb") as sample:
            encoder = MultipartEncoder(
                fields={"file": (filename, sample, "application/octet-stream")}
            )
            response = requests.post(
                f"{OPSWAT_API}/file",
                data=encoder,
                headers={
                    "apikey": api_key,
                    "Content-Type": encoder.content_type,
                },
                timeout=(30, 1800),
                allow_redirects=False,
            )
        if not _response_succeeded(response):
            return _provider_response_error("OPSWAT MetaDefender", response)
        payload = _json_object(response)
        data_id = payload.get("data_id") if payload else None
        if not data_id:
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "error",
                "message": "OPSWAT did not return a scan ID.",
            }
        return _poll_opswat_scan(data_id, api_key)
    except (requests.RequestException, ValueError) as error:
        return _provider_error("OPSWAT MetaDefender", error)


def _poll_opswat_scan(data_id, api_key):
    deadline = time.monotonic() + PROVIDER_POLL_TIMEOUT_SECONDS
    while True:
        try:
            response = requests.get(
                f"{OPSWAT_API}/file/{data_id}",
                headers={"apikey": api_key},
                timeout=(10, 30),
                allow_redirects=False,
            )
        except requests.RequestException as error:
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "submitted",
                "analysis_id": data_id,
                "message": f"Sample submitted, but status lookup failed ({error.__class__.__name__}).",
            }
        if response.status_code == 429:
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "submitted",
                "analysis_id": data_id,
                "message": "Sample submitted; the provider rate-limited status checks.",
            }
        if not _response_succeeded(response):
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "submitted",
                "analysis_id": data_id,
                "message": f"Sample submitted, but status lookup returned HTTP {response.status_code}.",
            }

        payload = _json_object(response)
        scan_results = payload.get("scan_results") if payload else None
        if not isinstance(scan_results, dict):
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "submitted",
                "analysis_id": data_id,
                "message": "Sample submitted; the provider returned an incomplete scan report.",
            }
        try:
            progress = int(scan_results.get("progress_percentage", 0))
        except (TypeError, ValueError):
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "error",
                "analysis_id": data_id,
                "message": "OPSWAT returned an invalid scan progress value.",
            }
        if progress >= 100:
            try:
                detections = int(scan_results["total_detected_avs"])
                total_engines = int(scan_results["total_avs"])
            except (KeyError, TypeError, ValueError):
                return {
                    "provider": "OPSWAT MetaDefender",
                    "status": "error",
                    "analysis_id": data_id,
                    "message": "OPSWAT completed the analysis without valid engine statistics.",
                }
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "complete",
                "analysis_id": data_id,
                "detections": detections,
                "total_engines": total_engines,
                "message": (
                    f"{detections} detections from {total_engines} engines."
                    if detections
                    else f"No detections from {total_engines} engines."
                ),
            }
        if time.monotonic() >= deadline:
            return {
                "provider": "OPSWAT MetaDefender",
                "status": "submitted",
                "analysis_id": data_id,
                "message": "Sample is still processing at OPSWAT; check the provider portal for the latest result.",
            }
        time.sleep(PROVIDER_POLL_INTERVAL_SECONDS)


def submit_to_external_providers(file_path, filename, file_size, sha256):
    results = []

    virustotal_key = os.environ.get("VT_API_KEY")
    if virustotal_key:
        results.append(
            _send_virustotal_file(
                file_path, filename, file_size, sha256, virustotal_key
            )
        )
    else:
        results.append(
            {
                "provider": "VirusTotal",
                "status": "not_configured",
                "message": "Set VT_API_KEY to enable VirusTotal submissions.",
            }
        )

    opswat_key = os.environ.get("OPSWAT_API_KEY")
    if opswat_key:
        results.append(
            _send_opswat_file(file_path, filename, file_size, opswat_key)
        )
    else:
        results.append(
            {
                "provider": "OPSWAT MetaDefender",
                "status": "not_configured",
                "message": "Set OPSWAT_API_KEY to enable OPSWAT submissions.",
            }
        )

    return results


def analyze_file(file_path, filename, file_size, sha256, external_consent):
    results = {
        "file_type": identify_file_type(file_path),
        "engines": [scan_with_clamav(file_path)],
    }
    if external_consent:
        results["engines"].extend(
            submit_to_external_providers(file_path, filename, file_size, sha256)
        )
    else:
        results["engines"].extend(
            [
                {
                    "provider": "VirusTotal",
                    "status": "not_shared",
                    "message": "Not submitted; external sharing was not approved.",
                },
                {
                    "provider": "OPSWAT MetaDefender",
                    "status": "not_shared",
                    "message": "Not submitted; external sharing was not approved.",
                },
            ]
        )
    return results
