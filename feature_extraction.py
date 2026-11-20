from urllib.parse import urlparse
import re


def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.netloc

    features = {
        "url_length": len(url),

        "hostname_length": len(hostname),

        "dot_count": url.count("."),

        "hyphen_count": url.count("-"),

        "slash_count": url.count("/"),

        "digit_count": sum(c.isdigit() for c in url),

        "special_char_count": len(
            re.findall(r"[^a-zA-Z0-9]", url)
        ),

        "has_at_symbol": int("@" in url),

        "has_ip": int(
            bool(
                re.search(
                    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                    hostname
                )
            )
        ),

        "https": int(parsed.scheme == "https"),

        "subdomain_count": max(
            0,
            len(hostname.split(".")) - 2
        ),

        "has_login_word": int(
            any(
                word in url.lower()
                for word in [
                    "login",
                    "signin",
                    "verify",
                    "account",
                    "password"
                ]
            )
        )
    }

    return features