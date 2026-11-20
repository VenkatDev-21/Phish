# Security notes

PhishGuard is an educational detector. These notes describe what it defends against, what
it deliberately does not, and how to run the hosted deployment without turning it into a
liability.

---

## Threat model

**In scope**

- A public visitor submitting URLs, pasted email, or files to a hosted instance.
- Opportunistic abuse: scraping the history endpoints, hammering the API, uploading
  oversized bodies, framing or injecting into the UI.
- Accidental secret leakage through the repository.
- CSRF against state-changing form posts.

**Out of scope**

- Targeted attackers with platform access (Render/Vercel account compromise).
- Malware detonation. Files are hashed, sniffed, and optionally handed to ClamAV or a cloud
  provider; nothing is executed.
- Per-user accounts, audit trails, or multi-tenant isolation. The history gate is a single
  shared passcode, on or off.
- Data-at-rest encryption. The SQLite file relies on the platform's disk protection.

## Controls in place

| Control | Implementation |
|---|---|
| Session integrity | `FLASK_SECRET_KEY` is mandatory outside development and must be at least 16 characters, so CSRF tokens and sessions survive restarts and multiple gunicorn workers. |
| CSRF | Session-bound token compared with `secrets.compare_digest` on every form POST (`/email`, `/files`, `/unlock`, `/lock`). Missing or wrong tokens return `400`. |
| Response headers | Strict CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, restrictive `Permissions-Policy`, and HSTS when the request is HTTPS. |
| Cookies | HttpOnly and SameSite=Lax by default; `Secure` is added when `PHISHGUARD_ENV=production`. |
| Passcode gate | Optional shared code for `/dashboard`, `/history`, `/authentication` and `/api/dashboard/*`. Comparison is timing-safe, failures are rate limited (`6` per `15` minutes), and API callers receive `401` plus an `unlock_url` instead of an HTML redirect. Scanners remain public by design. |
| Rate limiting | Sliding-window limiter per client address and rule: URL scan 40/5 min, public API 60/5 min, email 25/30 min, file upload 12/hour, dashboard reads 600/5 min, unlock 6/15 min. `429` responses carry `Retry-After` and a JSON `retry_after`. |
| CORS | Only `/api/v1/*` answers cross-origin, limited to `GET, POST, OPTIONS` and `Content-Type`, restricted by `PHISHGUARD_ALLOWED_ORIGINS`. |
| Proxy trust | `ProxyFix` is applied only when `PHISHGUARD_BEHIND_PROXY` is on (default on Render), so `X-Forwarded-For` cannot be spoofed locally. |
| Upload ceilings | `MAX_UPLOAD_BYTES` (100 MiB hosted) and `MAX_EMAIL_REQUEST_BYTES` (64 MiB) bound both the Flask body limit and the analysis copy. Oversized requests get a branded `413`. |
| Third-party submission | Files reach VirusTotal/OPSWAT only when the operator configured keys **and** the user ticked consent for that scan. `PHISHGUARD_EXTERNAL_SUBMISSIONS=0` removes the path. ClamAV stays local. |
| Error surfaces | Branded 404/429/500 pages; JSON errors for `/api/*`. No stack traces or configuration details are rendered. |
| Indexing | `robots.txt` disallows every private prefix, and private responses send `no-store` plus `X-Robots-Tag: noindex`. |
| Secrets hygiene | `.env` and `.env.*` are ignored (`!.env.example` keeps the template), the template holds placeholders only, and the app never renders key values. |

## Operational recommendations

1. **Set `PHISHGUARD_ACCESS_CODE`** on any public instance. Without it, every saved scan is
   readable by anyone who finds the URL.
2. **Keep `FLASK_SECRET_KEY` stable** in the platform's environment variables, never in the
   repository.
3. **Rotate vendor keys** that were ever pasted into a tracked file, chat, or screenshot.
4. **Pin CORS** with `PHISHGUARD_ALLOWED_ORIGINS=https://your-front-end` once the Vercel
   domain is known.
5. **Lower `MAX_UPLOAD_BYTES`** if you do not need large samples; hosting platforms cap
   request bodies independently.
6. **Do not process regulated data.** The history stores sender/recipient metadata, subjects,
   extracted links, and attachment hashes. It never stores the raw email body, but the
   metadata is still sensitive.
7. **Read the history retention.** Free Render instances discard the SQLite file on restart;
   a mounted disk keeps it indefinitely with no automatic pruning.

## Known limitations

- The limiter is in-process: two gunicorn workers mean two independent budgets, and a
  restart resets counters. Behind a CDN, add edge rate limiting as well.
- The passcode is a shared secret with no lockout, only a rate limit; it is not an
  authentication system.
- Scanners are intentionally unauthenticated, which is also what makes the public API
  usable. Abuse resistance comes from rate limits and upload ceilings, not identity.
- `X-Forwarded-For` is trusted when `PHISHGUARD_BEHIND_PROXY` is on. Only enable it behind a
  proxy you control.
- The URL model sees structure only — length, dots, hyphens, `@`, IP hosts, login keywords.
  It cannot tell a freshly registered legitimate domain from a phishing one.
- "No detections" from ClamAV or a vendor API is not proof of safety.

## Reporting

This is a personal/educational project. If you find a vulnerability, open a private GitHub
security advisory on the repository rather than a public issue, and include reproduction
steps plus the deployment URL. Do not test against instances you do not own.
