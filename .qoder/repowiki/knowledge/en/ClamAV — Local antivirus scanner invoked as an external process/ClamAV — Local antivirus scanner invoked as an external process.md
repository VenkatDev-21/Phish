---
kind: external_dependency
name: ClamAV — Local antivirus scanner invoked as an external process
slug: clamav
category: external_dependency
category_hints:
    - vendor_identity
scope:
    - '**'
source_files:
    - file_analysis.py
---

### Identity
ClamAV is an open-source antivirus engine invoked as an external binary rather than linked as a library.

### Role in this repo
- `file_analysis.py` calls `clamscan` (found via PATH or `CLAMSCAN_PATH`) and interprets its exit code / output as a scan result.
- It is always available locally; unlike VirusTotal/OPSWAT it does not require an API key and is not subject to `PHISHGUARD_EXTERNAL_SUBMISSIONS`.

### Durable integration notes
- Signature database location is controlled by `CLAMAV_DATABASE_DIR`; if signatures are missing the engine reports a specific message.
- A 30-minute timeout is enforced around the subprocess call.
- This is a local-only execution path — no network egress to ClamAV servers from the app.