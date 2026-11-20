import re

import dns.exception
import dns.resolver
import tldextract


AUTH_RESULT = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
DOMAIN_VALUE = re.compile(
    r"\b(?:smtp\.mailfrom|header\.from|header\.d|d)\s*=\s*"
    r"(?:[^@\s;<>]+@)?([a-z0-9._-]+(?:\.[a-z0-9_-]+)+)",
    re.IGNORECASE,
)
SELECTOR_VALUE = re.compile(r"\bs\s*=\s*([a-z0-9._-]+)", re.IGNORECASE)
SPF_RESULT = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
EXTRACT_DOMAIN = tldextract.TLDExtract(suffix_list_urls=())


def _registrable_domain(domain):
    extracted = EXTRACT_DOMAIN(domain.lower().rstrip("."))
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain.lower().rstrip(".")


def domains_aligned(from_domain, auth_domain, strict=False):
    if not from_domain or not auth_domain:
        return False
    if strict:
        return from_domain.lower().rstrip(".") == auth_domain.lower().rstrip(".")
    return _registrable_domain(from_domain) == _registrable_domain(auth_domain)


def _txt_records(resolver, name):
    answer = resolver.resolve(name, "TXT", lifetime=2)
    return [
        b"".join(part for part in record.strings).decode("utf-8", errors="replace")
        for record in answer
    ]


def _lookup(resolver, name, record_type):
    try:
        answer = resolver.resolve(name, record_type, lifetime=2)
        if record_type == "TXT":
            records = _txt_records_from_answer(answer)
        elif record_type == "MX":
            records = sorted(str(record.exchange).rstrip(".") for record in answer)
        elif record_type == "NS":
            records = sorted(str(record.target).rstrip(".") for record in answer)
        else:
            records = sorted(str(record.address) for record in answer)
        return {"status": "found" if records else "no_record", "records": records}
    except dns.resolver.NXDOMAIN:
        return {"status": "not_found", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "no_record", "records": []}
    except dns.exception.DNSException:
        return {"status": "lookup_error", "records": []}


def _dmarc_txt_records(resolver, domain):
    organizational_domain = _registrable_domain(domain)
    record_domain = domain
    try:
        records = [
            record for record in _txt_records(resolver, f"_dmarc.{domain}")
            if record.lower().startswith("v=dmarc1")
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        records = []

    if not records and organizational_domain != domain:
        record_domain = organizational_domain
        try:
            records = [
                record for record in _txt_records(
                    resolver, f"_dmarc.{organizational_domain}"
                )
                if record.lower().startswith("v=dmarc1")
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records = []
    return record_domain, records


def _txt_records_from_answer(answer):
    return [
        b"".join(record.strings).decode("utf-8", errors="replace")
        for record in answer
    ]


def lookup_domain_dns(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 2
    result = {
        "domain": domain,
        "checked": True,
        "spf": {"status": "not_found", "records": []},
        "dmarc": {
            "status": "not_found",
            "records": [],
            "record_domain": domain,
        },
        "mx": _lookup(resolver, domain, "MX"),
        "a": _lookup(resolver, domain, "A"),
        "ns": _lookup(resolver, domain, "NS"),
    }

    try:
        txt_records = _txt_records(resolver, domain)
        spf_records = [
            record for record in txt_records
            if record.lower().startswith("v=spf1")
        ]
        result["spf"] = {
            "status": (
                "multiple_records" if len(spf_records) > 1
                else "found" if spf_records
                else "not_found"
            ),
            "records": spf_records,
        }
    except dns.resolver.NXDOMAIN:
        result["spf"] = {"status": "not_found", "records": []}
    except dns.resolver.NoAnswer:
        result["spf"] = {"status": "no_record", "records": []}
    except dns.exception.DNSException:
        result["spf"] = {"status": "lookup_error", "records": []}

    try:
        record_domain, dmarc_records = _dmarc_txt_records(resolver, domain)
        policy = None
        if dmarc_records:
            policy_match = re.search(
                r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b",
                dmarc_records[0],
                re.IGNORECASE,
            )
            policy = policy_match.group(1).lower() if policy_match else "invalid"
        result["dmarc"] = {
            "status": (
                "multiple_records" if len(dmarc_records) > 1
                else "found" if dmarc_records
                else "not_found"
            ),
            "records": dmarc_records,
            "record_domain": record_domain,
            "policy": policy,
        }
    except dns.resolver.NXDOMAIN:
        result["dmarc"] = {
            "status": "not_found",
            "records": [],
            "record_domain": domain,
            "policy": None,
        }
    except dns.resolver.NoAnswer:
        result["dmarc"] = {
            "status": "no_record",
            "records": [],
            "record_domain": domain,
            "policy": None,
        }
    except dns.exception.DNSException:
        result["dmarc"] = {
            "status": "lookup_error",
            "records": [],
            "record_domain": domain,
            "policy": None,
        }

    return result


def analyze_authentication(message, from_domain, dns_lookup=False):
    statuses = {"spf": [], "dkim": [], "dmarc": []}
    domains = {"spf": [], "dkim": [], "dmarc": []}
    passed_domains = {"spf": [], "dkim": [], "dmarc": []}
    selectors = []
    auth_header_results = []
    auth_headers = [
        str(value) for value in message.get_all("Authentication-Results", [])
    ]

    for header in auth_headers:
        header_results = {"spf": [], "dkim": [], "dmarc": []}
        for match in AUTH_RESULT.finditer(header):
            mechanism, status = match.groups()
            mechanism = mechanism.lower()
            status = status.lower()
            statuses[mechanism].append(status)
            segment = header[match.end():].split(";", 1)[0]
            domain_match = DOMAIN_VALUE.search(segment)
            domain = None
            if domain_match:
                domain = domain_match.group(1).lower().rstrip(".")
                domains[mechanism].append(domain)
                if status == "pass":
                    passed_domains[mechanism].append(domain)
            header_results[mechanism].append((status, domain))

        auth_header_results.append(header_results)

    for received_spf in message.get_all("Received-SPF", []):
        match = SPF_RESULT.search(str(received_spf))
        if match:
            statuses["spf"].append(match.group(1).lower())
            domain_match = re.search(
                r"\b(?:envelope-from|domain of)\s*[:=]?\s*"
                r"(?:[^@\s<>]+@)?([a-z0-9._-]+(?:\.[a-z0-9_-]+)+)",
                str(received_spf),
                re.IGNORECASE,
            )
            if domain_match:
                domain = domain_match.group(1).lower().rstrip(".")
                domains["spf"].append(domain)
                if match.group(1).lower() == "pass":
                    passed_domains["spf"].append(domain)

    dkim_domains = []
    for signature in message.get_all("DKIM-Signature", []):
        value = str(signature)
        domain_match = re.search(r"\bd\s*=\s*([^;\s]+)", value, re.IGNORECASE)
        selector_match = SELECTOR_VALUE.search(value)
        if domain_match:
            dkim_domains.append(domain_match.group(1).lower().rstrip("."))
        if selector_match:
            selectors.append(selector_match.group(1))

    details = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        unique_statuses = list(dict.fromkeys(statuses[mechanism]))
        auth_domains = list(dict.fromkeys(domains[mechanism]))
        aligned = [
            domains_aligned(from_domain, domain)
            for domain in auth_domains
        ]
        strict_aligned = [
            domains_aligned(from_domain, domain, strict=True)
            for domain in auth_domains
        ]
        details[mechanism] = {
            "status": ", ".join(unique_statuses) if unique_statuses else "unknown",
            "evidence": "Reported in supplied headers; not independently verified.",
            "domains": auth_domains,
            "aligned": any(aligned),
            "strict_aligned": any(strict_aligned),
            "reported_pass_aligned": False,
        }
    details["dkim"]["selectors"] = list(dict.fromkeys(selectors))
    details["dkim"]["signature_domains"] = dkim_domains
    details["authserv_ids"] = [
        header.split(";", 1)[0].strip() for header in auth_headers
    ]
    details["dns"] = lookup_domain_dns(from_domain) if dns_lookup and from_domain else {
        "checked": False,
        "message": "Public DNS lookup was not requested.",
    }

    alignment_strict = {"spf": False, "dkim": False}
    if details["dns"].get("checked"):
        dmarc_records = details["dns"]["dmarc"].get("records", [])
        if dmarc_records:
            record = dmarc_records[0]
            aspf = re.search(r"(?:^|;)\s*aspf\s*=\s*([sr])", record, re.I)
            adkim = re.search(r"(?:^|;)\s*adkim\s*=\s*([sr])", record, re.I)
            alignment_strict["spf"] = bool(aspf and aspf.group(1).lower() == "s")
            alignment_strict["dkim"] = bool(adkim and adkim.group(1).lower() == "s")
            details["dns"]["dmarc"]["spf_alignment"] = (
                "strict" if alignment_strict["spf"] else "relaxed"
            )
            details["dns"]["dmarc"]["dkim_alignment"] = (
                "strict" if alignment_strict["dkim"] else "relaxed"
            )

    for mechanism in ("spf", "dkim"):
        details[mechanism]["reported_pass_aligned"] = any(
            domains_aligned(
                from_domain,
                domain,
                strict=alignment_strict[mechanism],
            )
            for domain in passed_domains[mechanism]
        )

    reported_dmarc_pass = "pass" in statuses["dmarc"]
    aligned_reported_pass = any(
        any(status == "pass" for status, _ in report["dmarc"])
        and any(
            status == "pass"
            and domain
            and domains_aligned(
                from_domain,
                domain,
                strict=alignment_strict[mechanism],
            )
            for mechanism in ("spf", "dkim")
            for status, domain in report[mechanism]
        )
        for report in auth_header_results
    )
    details["dmarc"]["reported_alignment"] = (
        "reported pass with an aligned mechanism"
        if reported_dmarc_pass and aligned_reported_pass
        else "reported pass without a matching aligned mechanism"
        if reported_dmarc_pass
        else "not established"
    )
    return details
