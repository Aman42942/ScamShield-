import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SENSITIVE_TERMS = {"login", "verify", "secure", "update", "wallet", "payment", "signin", "account"}

def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,!?;:)") for u in URL_PATTERN.findall(text)]


def analyze_urls(text: str) -> list[dict]:
    results = []
    for raw in extract_urls(text):
        normalized = raw if raw.startswith(("http://", "https://")) else "http://" + raw
        parsed = urlparse(normalized)
        host = parsed.netloc.lower()
        hostname = host.split(":")[0]
        flags = []
        score = 0

        if len(raw) > 80:
            flags.append("Unusually long URL"); score += 15
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
            flags.append("IP address used as domain"); score += 25
        if "@" in raw:
            flags.append("@ character in URL"); score += 20
        if hostname.count(".") >= 3:
            flags.append("Many subdomains"); score += 10
        if hostname in SHORTENERS:
            flags.append("URL shortener"); score += 15
        if any(term in raw.lower() for term in SENSITIVE_TERMS):
            flags.append("Sensitive-action keyword in URL"); score += 10
        if parsed.scheme == "http":
            flags.append("Not using HTTPS"); score += 10

        results.append({
            "url": raw,
            "domain": host,
            "scheme": parsed.scheme,
            "score": min(score, 100),
            "flags": flags,
            "is_suspicious": bool(flags),
        })
    return results
