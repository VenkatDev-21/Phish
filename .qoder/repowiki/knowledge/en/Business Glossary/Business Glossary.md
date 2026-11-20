---
kind: business_term
name: Business Glossary
category: business_term
scope:
    - '**'
---

### passcode gate
- Definition：The shared-secret access control protecting read-only surfaces (`/dashboard`, `/history`, `/authentication`, `/api/dashboard/*`). Users submit a passcode via `/unlock`; successful unlocks are stored in the session using timing-safe comparison. Failures are rate-limited to 6 attempts per 15 minutes, and API callers receive a JSON `401` with an `unlock_url` instead of an HTML redirect. It is intentionally not a full authentication system — there is no lockout or per-user identity.
- Aliases：access gate、unlock gate

### history retention
- Definition：The persistence behavior of the scan history stored in the SQLite database (`phishguard.db`). On Render's free plan the file is discarded on restart unless `PHISHGUARD_DATA_DIR` is pointed at a mounted disk; otherwise history survives indefinitely with no automatic pruning.

### third-party submission
- Definition：The pathway by which a user-uploaded file is forwarded to an external malware-scanning provider (VirusTotal or OPSWAT MetaDefender). It is disabled by default for unconfigured providers, requires explicit user consent on the scan form, and can be globally removed by setting `PHISHGUARD_EXTERNAL_SUBMISSIONS=0`. Local ClamAV scanning is not considered a third-party submission.
- Aliases：cloud scan、external submission
