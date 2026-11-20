import ipaddress
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from urllib.parse import urlparse

import pandas as pd
from bs4 import BeautifulSoup

from email_attachment_analysis import analyze_attachment
from email_auth import analyze_authentication, domains_aligned
from feature_extraction import extract_features


MAX_EMAIL_CHARACTERS = 250_000
MAX_EMAIL_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_EMAIL_ATTACHMENTS = 10
URL_PATTERN = re.compile(
    r"""(?ix)(?<![\w@])(?:https?://|hxxps?://|www\.)[^\s<>"']+"""
)
AUTH_FAILURES = {"fail", "softfail", "permerror"}
CONTENT_RULES = (
    (
        re.compile(r"\b(?:account|mailbox|service)\s+(?:will be|has been)\s+(?:suspend|block|close)\w*\b", re.I),
        "Account suspension threat",
        "The message threatens to suspend or close an account.",
        "high",
        15,
    ),
    (
        re.compile(r"\b(?:verify|confirm|validate)\s+(?:your\s+)?(?:password|login|account|identity|credentials)\b", re.I),
        "Credential verification request",
        "The message asks the reader to verify account credentials or identity.",
        "high",
        18,
    ),
    (
        re.compile(r"\b(?:otp|one[- ]time password|security code|verification code)\b", re.I),
        "One-time code request",
        "The message mentions a one-time or security code; do not share codes by email.",
        "high",
        16,
    ),
    (
        re.compile(r"\b(?:gift cards?|wire transfer|cryptocurrency|bitcoin)\b", re.I),
        "Unusual payment request",
        "The message mentions payment methods commonly used in scams.",
        "medium",
        12,
    ),
    (
        re.compile(r"\b(?:urgent|immediately|within 24 hours|act now|final warning)\b", re.I),
        "Urgency language",
        "The message pressures the reader to act quickly.",
        "low",
        7,
    ),
    (
        re.compile(r"\b(?:invoice attached|overdue invoice|payment overdue|delivery failed|missed delivery)\b", re.I),
        "Invoice or delivery lure",
        "The message uses an invoice or delivery-notification theme.",
        "low",
        6,
    ),
)
SHORTENER_HOSTS = {
    "bit.ly", "cutt.ly", "is.gd", "lnkd.in", "rb.gy", "t.co",
    "tinyurl.com", "ow.ly", "shorturl.at",
}
BRAND_DOMAINS = {
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
}


def _mailbox(value):
    display, address = parseaddr(value or "")
    if "@" not in address:
        return display.strip(), address.strip(), ""
    _, domain = address.rsplit("@", 1)
    domain = domain.strip().rstrip(".").lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_domain = domain
    return display.strip(), address.strip(), ascii_domain


def _normalize_url(value):
    value = value.strip().rstrip(".,;:!?)]}")
    value = value.replace("&amp;", "&")
    if value.lower().startswith("hxxp"):
        value = "http" + value[4:]
    elif value.lower().startswith("www."):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username or parsed.password:
            return value
        parsed.hostname.encode("idna")
        _ = parsed.port
    except (UnicodeError, ValueError):
        return ""
    return value


def _host(url):
    try:
        host = (urlparse(url).hostname or "").rstrip(".").lower()
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""


def _extract_urls(text):
    urls = []
    for match in URL_PATTERN.finditer(text):
        normalized = _normalize_url(match.group(0))
        if normalized and normalized not in urls:
            urls.append(normalized)
    return urls


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _model_prediction(url, model):
    if model is None:
        return None
    features = extract_features(url)
    frame = pd.DataFrame([features])
    expected = list(getattr(model, "feature_names_in_", []))
    if expected:
        if set(expected) != set(features):
            return {
                "status": "unavailable",
                "message": "The installed URL model features do not match the extractor.",
            }
        frame = frame[expected]
    try:
        prediction = str(model.predict(frame)[0]).lower()
        probabilities = model.predict_proba(frame)[0]
        classes = [str(value).lower() for value in model.classes_]
        phishing_index = classes.index("phishing")
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return {
            "status": "unavailable",
            "message": "The installed URL model could not score this link.",
        }
    return {
        "status": "predicted",
        "prediction": prediction,
        "phishing_probability": round(float(probabilities[phishing_index] * 100), 2),
        "features": features,
    }


def _html_signals(html, findings):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for anchor in soup.find_all("a", href=True):
        raw_href = str(anchor.get("href", "")).strip()
        if raw_href.lower().startswith(("javascript:", "data:", "file:")):
            _add_finding(
                findings, "html", "Unsafe HTML link scheme",
                "The message contains a link using a non-web scheme; it was not opened.",
                "high", 18,
            )
            continue
        href = _normalize_url(raw_href)
        if not href:
            continue
        label = anchor.get_text(" ", strip=True)
        label_url = _normalize_url(label) if label else ""
        mismatch = bool(label_url and _host(label_url) != _host(href))
        style = str(anchor.get("style", "")).lower().replace(" ", "")
        hidden = (
            anchor.has_attr("hidden")
            or "display:none" in style
            or "visibility:hidden" in style
        )
        links.append({
            "url": href,
            "host": _host(href),
            "anchor_text": label[:200],
            "anchor_mismatch": mismatch,
            "hidden": hidden,
        })

    if soup.find("form"):
        _add_finding(
            findings, "html", "HTML form in message",
            "The HTML body contains a form that could collect submitted data.",
            "high", 18,
        )
    if soup.find("input", attrs={"type": re.compile(r"password", re.I)}):
        _add_finding(
            findings, "html", "Password field in message",
            "The HTML body contains a password input field.",
            "high", 20,
        )
    if soup.find(["iframe", "script"]):
        _add_finding(
            findings, "html", "Active HTML content",
            "The message contains script or iframe elements; none were executed.",
            "medium", 10,
        )
    external_resources = [
        tag for tag in soup.find_all(["img", "iframe", "script", "link"])
        if str(tag.get("src") or tag.get("href") or "").lower().startswith(("http://", "https://"))
    ]
    if external_resources:
        _add_finding(
            findings, "html", "External HTML resources",
            f"The message references {len(external_resources)} remote image, script, frame, or stylesheet resource(s).",
            "low", 5,
        )
    if any(link["hidden"] for link in links):
        _add_finding(
            findings, "html", "Hidden link",
            "At least one link is hidden in the HTML body.",
            "medium", 12,
        )
    mismatches = [link for link in links if link["anchor_mismatch"]]
    if mismatches:
        _add_finding(
            findings, "html", "Visible link text differs from destination",
            f"{len(mismatches)} link label(s) display a different host from the actual destination.",
            "high", min(24, 16 + 2 * (len(mismatches) - 1)),
        )
    return soup.get_text(" ", strip=True), links


def _add_finding(findings, category, title, detail, severity, score):
    key = (category, title, detail)
    if any((item["category"], item["title"], item["detail"]) == key for item in findings):
        return
    findings.append({
        "category": category,
        "title": title,
        "detail": detail,
        "severity": severity,
        "score": score,
    })


def parse_email_upload(filename, data):
    if not isinstance(data, bytes):
        raise TypeError("Uploaded email data must be bytes.")
    if not data:
        raise ValueError("The uploaded email file is empty.")
    if len(data) > MAX_EMAIL_UPLOAD_BYTES:
        raise ValueError(
            f"Email files must be {MAX_EMAIL_UPLOAD_BYTES // (1024 * 1024)} MiB or smaller."
        )

    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if extension == "msg":
        raise ValueError(
            "Outlook .msg files are not supported. Export the message as .eml or .txt and upload that instead."
        )
    if extension == "eml":
        return BytesParser(policy=policy.default).parsebytes(data)
    if extension in {"txt", "html", "htm"}:
        text = data.decode("utf-8-sig", errors="replace")
        message = Parser(policy=policy.default).parsestr(text)
        if not message.keys():
            message.set_payload(text)
        return message
    raise ValueError("Supported email files are .eml, .txt, .html, and .htm.")


def analyze_email(
    text,
    url_model=None,
    dns_lookup=False,
    attachments=None,
    parsed_message=None,
    external_consent=False,
):
    if not isinstance(text, str) or (not text.strip() and parsed_message is None):
        raise ValueError("Paste an email header, subject, body, link, or message.")
    if parsed_message is None and len(text) > MAX_EMAIL_CHARACTERS:
        raise ValueError(
            f"Email text must be {MAX_EMAIL_CHARACTERS:,} characters or fewer."
        )

    message = parsed_message or Parser(policy=policy.default).parsestr(text)
    if not message.keys() and parsed_message is None:
        message.set_payload(text)

    body_parts = []
    html_parts = []
    findings = []
    attachment_inputs = list(attachments or [])
    omitted_attachments = max(0, len(attachment_inputs) - MAX_EMAIL_ATTACHMENTS)
    attachment_inputs = attachment_inputs[:MAX_EMAIL_ATTACHMENTS]
    for part in message.walk():
        if part.defects:
            defect_names = ", ".join(sorted({type(defect).__name__ for defect in part.defects}))
            _add_finding(
                findings, "content", "Malformed email structure",
                f"The parser found MIME structure issue(s): {defect_names}.",
                "medium", 6,
            )
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            if len(attachment_inputs) >= MAX_EMAIL_ATTACHMENTS:
                omitted_attachments += 1
                continue
            payload = part.get_payload(decode=True) or b""
            attachment_inputs.append({
                "filename": filename or "unnamed-attachment",
                "data": payload,
                "mime_type": part.get_content_type(),
            })
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            _add_finding(
                findings, "content", "Unsupported email content skipped",
                f"The {part.get_content_type()} MIME part was not analyzed as message text.",
                "info", 0,
            )
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, TypeError) as error:
            _add_finding(
                findings, "content", "Email body could not be decoded",
                f"A {part.get_content_type()} MIME part could not be decoded: {type(error).__name__}.",
                "medium", 6,
            )
            continue
        if not isinstance(content, str):
            _add_finding(
                findings, "content", "Email body could not be decoded",
                f"A {part.get_content_type()} MIME part did not contain text.",
                "medium", 6,
            )
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(content)
        else:
            body_parts.append(content)

    if not body_parts and not html_parts and not message.is_multipart():
        try:
            payload = message.get_content()
        except (LookupError, UnicodeError, TypeError):
            payload = message.get_payload()
        if isinstance(payload, str):
            if re.search(r"<\s*(?:html|body|a|form)\b", payload, re.I):
                html_parts.append(payload)
            else:
                body_parts.append(payload)

    plain_text = "\n".join(body_parts)
    html_text = "\n".join(html_parts)
    categories = {
        "authentication": 0,
        "sender": 0,
        "content": 0,
        "html": 0,
        "urls": 0,
        "attachments": 0,
        "reputation": 0,
    }

    sender_header = str(message.get("From", "")).strip()
    reply_to = str(message.get("Reply-To", "")).strip()
    return_path = str(message.get("Return-Path", "")).strip()
    display_name, sender_address, sender_domain = _mailbox(sender_header)
    _, _, reply_to_domain = _mailbox(reply_to)
    _, _, return_path_domain = _mailbox(return_path)
    subject = str(message.get("Subject", "")).strip() or "(no subject provided)"

    authentication_details = analyze_authentication(
        message, sender_domain, dns_lookup=dns_lookup
    )
    authentication = {
        method: authentication_details[method]["status"]
        for method in ("spf", "dkim", "dmarc")
    }
    failed_auth = [
        method for method, status in authentication.items()
        if any(value in AUTH_FAILURES for value in status.split(", "))
    ]
    if failed_auth:
        _add_finding(
            findings, "authentication", "Authentication failure reported",
            f"Supplied headers report a failure for {', '.join(name.upper() for name in failed_auth)}. Header results are unverified claims, not independent verification.",
            "high", 16,
        )
    if (
        authentication_details["dmarc"]["reported_alignment"]
        == "reported pass without a matching aligned mechanism"
    ):
        _add_finding(
            findings, "authentication", "DMARC result lacks an aligned passing mechanism",
            "The supplied headers report DMARC pass, but do not include an aligned SPF or DKIM pass in the same Authentication-Results header.",
            "medium", 12,
        )

    if sender_domain and reply_to_domain and not domains_aligned(
        sender_domain, reply_to_domain
    ):
        _add_finding(
            findings, "sender", "Reply-To domain differs from From",
            f"From uses {sender_domain}, while Reply-To uses {reply_to_domain}.",
            "medium", 16,
        )
    if sender_domain and return_path_domain and not domains_aligned(
        sender_domain, return_path_domain
    ):
        _add_finding(
            findings, "sender", "Return-Path domain differs from From",
            f"From uses {sender_domain}, while Return-Path uses {return_path_domain}.",
            "low", 6,
        )
    if sender_domain and "xn--" in sender_domain:
        _add_finding(
            findings, "sender", "Punycode sender domain",
            f"The sender domain is internationalized and encoded as {sender_domain}; inspect it carefully.",
            "medium", 10,
        )
    if sender_domain and display_name:
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in display_name.lower() and sender_domain != official_domain and not sender_domain.endswith("." + official_domain):
                _add_finding(
                    findings, "sender", "Brand name and sender domain differ",
                    f"The display name mentions {brand.title()}, but the sender domain is {sender_domain}.",
                    "medium", 14,
                )
                break

    combined_text = "\n".join([subject, plain_text, html_text])
    for pattern, title, detail, severity, score in CONTENT_RULES:
        if pattern.search(combined_text):
            _add_finding(findings, "content", title, detail, severity, score)

    visible_text, html_links = _html_signals(html_text, findings) if html_text else ("", [])
    all_text = "\n".join([subject, plain_text, visible_text])
    link_inputs = _extract_urls(all_text)
    links_by_url = {
        link["url"]: link
        for link in html_links
    }
    for url in link_inputs:
        links_by_url.setdefault(url, {
            "url": url,
            "host": _host(url),
            "anchor_text": "",
            "anchor_mismatch": False,
            "hidden": False,
        })

    attachment_reports = []
    for attachment in attachment_inputs[:MAX_EMAIL_ATTACHMENTS]:
        if not isinstance(attachment, dict) or not isinstance(attachment.get("data"), bytes):
            attachment_reports.append({
                "filename": str(
                    attachment.get("filename", "unknown")
                    if isinstance(attachment, dict)
                    else "unknown"
                ),
                "status": "error",
                "findings": [{
                    "title": "Attachment could not be read",
                    "detail": "The attachment payload was unavailable for local analysis.",
                    "severity": "medium",
                }],
                "extracted_urls": [],
            })
            continue
        report = analyze_attachment(
            attachment.get("filename", "attachment"),
            attachment["data"],
            attachment.get("mime_type"),
            external_consent=external_consent,
        )
        attachment_reports.append(report)
        for url in report.get("extracted_urls", []):
            links_by_url.setdefault(url, {
                "url": url,
                "host": _host(url),
                "anchor_text": "",
                "anchor_mismatch": False,
                "hidden": False,
                "source": f"Attachment: {report['filename']}",
            })
        for attachment_finding in report.get("findings", []):
            severity = attachment_finding.get("severity", "low")
            score = {"high": 18, "medium": 10, "low": 5}.get(severity, 0)
            _add_finding(
                findings, "attachments", attachment_finding["title"],
                f"{report['filename']}: {attachment_finding['detail']}",
                severity, score,
            )
        for engine in report.get("scanners", {}).get("engines", []):
            if engine.get("status") == "complete" and engine.get("detections", 0) > 0:
                _add_finding(
                    findings, "attachments", "Antivirus detection in attachment",
                    f"{report['filename']}: {engine['provider']} reported {engine['detections']} detection(s).",
                    "high", 35,
                )
    if omitted_attachments:
        _add_finding(
            findings, "attachments", "Attachment count limit reached",
            f"{omitted_attachments} attachment(s) beyond the first {MAX_EMAIL_ATTACHMENTS} were not inspected.",
            "medium", 8,
        )

    links = []
    for link in links_by_url.values():
        host = link["host"]
        parsed = urlparse(link["url"])
        if _is_ip(host):
            _add_finding(
                findings, "urls", "Link uses an IP address",
                f"A link points directly to {host} rather than a named host.",
                "medium", 14,
            )
        if "xn--" in host:
            _add_finding(
                findings, "urls", "Punycode link domain",
                f"The link host {host} contains an encoded internationalized domain.",
                "medium", 10,
            )
        if parsed.scheme.lower() == "http":
            _add_finding(
                findings, "urls", "Link does not use HTTPS",
                f"The link to {host} uses unencrypted HTTP.",
                "low", 5,
            )
        if parsed.username or parsed.password:
            _add_finding(
                findings, "urls", "Link embeds credentials",
                f"The URL to {host} contains user information before its host.",
                "high", 20,
            )
        if host in SHORTENER_HOSTS:
            _add_finding(
                findings, "urls", "URL shortener",
                f"The link uses {host}; its final destination was not visited.",
                "medium", 8,
            )
        if re.search(r"(?:login|verify|password|wallet|urgent|suspend|invoice)", link["url"], re.I):
            _add_finding(
                findings, "urls", "Sensitive-action word in URL",
                f"The URL for {host} contains a word commonly used in account or payment lures.",
                "low", 6,
            )
        prediction = _model_prediction(link["url"], url_model)
        if prediction:
            link["model"] = prediction
            if prediction.get("status") == "predicted":
                probability = prediction["phishing_probability"]
                if prediction["prediction"] == "phishing" or probability >= 80:
                    _add_finding(
                        findings, "reputation", "URL model predicts phishing",
                        f"The local URL model predicts phishing with {probability:.2f}% phishing probability. This is a model prediction, not a confirmed finding.",
                        "medium", 14,
                    )
                elif probability >= 60:
                    _add_finding(
                        findings, "reputation", "URL model raises a concern",
                        f"The local URL model estimates {probability:.2f}% phishing probability.",
                        "low", 7,
                    )
        links.append(link)

    for finding in findings:
        categories[finding["category"]] += finding["score"]
    categories = {key: min(35, value) for key, value in categories.items()}
    score = min(100, sum(categories.values()))
    if score >= 75:
        risk_level = "Critical"
        verdict = "Likely Phishing"
        recommendation = "Do not reply, open links, or open attachments. Verify the request through a separate trusted channel."
    elif score >= 50:
        risk_level = "High"
        verdict = "Suspicious"
        recommendation = "Do not follow the instructions or open attachments until independently verified."
    elif score >= 25:
        risk_level = "Medium"
        verdict = "Suspicious"
        recommendation = "Review the findings and verify the sender using a trusted contact method."
    else:
        risk_level = "Low"
        verdict = "Inconclusive"
        recommendation = "No strong static indicators were found; this is not proof the message is safe."

    if not findings:
        _add_finding(
            findings, "content", "No obvious static warning found",
            "This rule-based check did not find the indicators it looks for. That does not establish that the email is safe.",
            "info", 0,
        )

    dns_data = authentication_details.get("dns", {})
    return {
        "subject": subject,
        "sender": sender_header or "(not included)",
        "sender_address": sender_address or "(not available)",
        "sender_domain": sender_domain or "(not available)",
        "to": str(message.get("To", "")).strip() or "(not included)",
        "cc": str(message.get("Cc", "")).strip() or "(not included)",
        "bcc": str(message.get("Bcc", "")).strip() or "(not included)",
        "reply_to": reply_to or "(not included)",
        "return_path": return_path or "(not included)",
        "date": str(message.get("Date", "")).strip() or "(not included)",
        "message_id": str(message.get("Message-ID", "")).strip() or "(not included)",
        "received_header_count": len(message.get_all("Received", [])),
        "authentication": authentication,
        "authentication_details": authentication_details,
        "dns": dns_data,
        "links": links,
        "link_domains": sorted({link["host"] for link in links if link["host"]}),
        "attachments": attachment_reports,
        "findings": findings,
        "category_scores": categories,
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "confidence": "Rule-based indicators; not a calibrated probability.",
        "recommendation": recommendation,
        "input_kind": (
            "Uploaded email file" if parsed_message is not None
            else "Email headers and content" if message.keys()
            else "Pasted text, subject, or link"
        ),
    }
