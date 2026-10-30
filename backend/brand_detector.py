"""Brand Impersonation & Typosquatting Detection Engine for ScamShield.

Identifies unauthorized brand claims, deceptive subdomains, homoglyphs,
and lookalike domains targeting popular banking, e-commerce, and government institutions.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from typing import Any

BRAND_REGISTRY: dict[str, dict[str, Any]] = {
    "State Bank of India (SBI)": {
        "aliases": ["sbi", "state bank", "yono", "onlinesbi"],
        "official_domains": ["onlinesbi.sbi", "sbi.co.in", "bank.sbi"],
        "category": "Banking",
    },
    "HDFC Bank": {
        "aliases": ["hdfc", "hdfc bank", "hdfc netbanking"],
        "official_domains": ["hdfcbank.com", "hdfcbank.net"],
        "category": "Banking",
    },
    "ICICI Bank": {
        "aliases": ["icici", "icici bank", "imobile"],
        "official_domains": ["icicibank.com"],
        "category": "Banking",
    },
    "Axis Bank": {
        "aliases": ["axis bank", "axis mobile"],
        "official_domains": ["axisbank.com"],
        "category": "Banking",
    },
    "Paytm": {
        "aliases": ["paytm", "paytm payments bank"],
        "official_domains": ["paytm.com"],
        "category": "Fintech / Payments",
    },
    "PhonePe": {
        "aliases": ["phonepe"],
        "official_domains": ["phonepe.com"],
        "category": "Fintech / Payments",
    },
    "Google Pay / Google": {
        "aliases": ["gpay", "google pay", "google support"],
        "official_domains": ["google.com", "pay.google.com"],
        "category": "Technology",
    },
    "India Post": {
        "aliases": ["india post", "indiapost", "speed post", "dak seva"],
        "official_domains": ["indiapost.gov.in"],
        "category": "Postal / Government",
    },
    "Income Tax Department": {
        "aliases": ["income tax", "incometax", "itr refund", "tax department"],
        "official_domains": ["incometax.gov.in", "incometaxindiaefiling.gov.in"],
        "category": "Government / Tax",
    },
    "EPFO (Provident Fund)": {
        "aliases": ["epfo", "provident fund", "uan"],
        "official_domains": ["epfindia.gov.in"],
        "category": "Government",
    },
    "Electricity Board / Utility": {
        "aliases": ["electricity power", "electricity bill", "electricity office", "bijli", "mahavitaran", "bses", "uppcl"],
        "official_domains": ["mahadiscom.in", "bsesdelhi.com", "uppcl.org"],
        "category": "Public Utility",
    },
    "Law Enforcement / CBI / Cyber Crime": {
        "aliases": ["cbi", "narcotics control bureau", "mumbai police", "delhi police", "cyber crime department", "digital arrest"],
        "official_domains": ["cybercrime.gov.in", "cbi.gov.in"],
        "category": "Law Enforcement",
    },
    "Netflix": {
        "aliases": ["netflix"],
        "official_domains": ["netflix.com"],
        "category": "Entertainment",
    },
    "Amazon": {
        "aliases": ["amazon", "amazon prime"],
        "official_domains": ["amazon.in", "amazon.com"],
        "category": "E-Commerce",
    },
    "Flipkart": {
        "aliases": ["flipkart"],
        "official_domains": ["flipkart.com"],
        "category": "E-Commerce",
    },
    "Apple": {
        "aliases": ["apple", "icloud", "apple id"],
        "official_domains": ["apple.com", "icloud.com"],
        "category": "Technology",
    },
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".vip", ".icu", ".work", ".click", ".cc", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".live", ".store", ".online", ".site", ".rest",
}

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a", "vv": "w",
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes basic edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_homoglyphs(domain: str) -> str:
    res = domain.lower()
    for char, rep in HOMOGLYPH_MAP.items():
        res = res.replace(char, rep)
    return res


def _extract_base_domain(hostname: str) -> tuple[str, str]:
    """Returns (registered_domain, subdomains)."""
    parts = hostname.lower().strip().split(".")
    if len(parts) <= 2:
        return hostname, ""
    # Check for known 2-part ccTLDs like .co.in, .gov.in, .ac.in
    if len(parts) >= 3 and parts[-2] in {"co", "gov", "ac", "org", "net", "com"} and len(parts[-1]) == 2:
        registered = ".".join(parts[-3:])
        sub = ".".join(parts[:-3])
        return registered, sub
    registered = ".".join(parts[-2:])
    sub = ".".join(parts[:-2])
    return registered, sub


def detect_brand_impersonation(text: str, urls: list[dict] | None = None) -> dict:
    """Analyzes text and extracted URLs for brand impersonation and typosquatting."""
    text_lower = text.lower()
    urls = urls or []

    targeted_brands: list[dict] = []
    findings: list[str] = []
    impersonation_score = 0

    # 1. Check brand mentions in text
    for brand_name, info in BRAND_REGISTRY.items():
        matched_alias = next((a for a in info["aliases"] if re.search(rf"\b{re.escape(a)}\b", text_lower)), None)
        if matched_alias:
            targeted_brands.append({
                "brand": brand_name,
                "matched_alias": matched_alias,
                "category": info["category"],
                "official_domains": info["official_domains"],
            })

    # 2. Check URL domain spoofing against detected brands and typosquatting
    url_threats: list[dict] = []
    for u in urls:
        raw_url = u.get("url", "")
        host = u.get("domain", "")
        if not host:
            parsed = urlparse(raw_url if raw_url.startswith("http") else "http://" + raw_url)
            host = parsed.netloc.lower()

        hostname = host.split(":")[0]
        registered_domain, subdomains = _extract_base_domain(hostname)

        # Check high-risk TLD
        has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            findings.append(f"URL '{hostname}' utilizes a high-risk scam TLD commonly used in disposable phishing.")
            impersonation_score += 20

        # Check if URL mimics any registered brand
        for brand_name, info in BRAND_REGISTRY.items():
            official_domains = [d.lower() for d in info["official_domains"]]
            normalized_domain = _normalize_homoglyphs(registered_domain.split(".")[0])

            # Check if genuine official domain
            is_genuine = any(hostname == d or hostname.endswith("." + d) for d in official_domains)

            # Check deceptive subdomain: attacker creates sbi.malicious-site.com
            for alias in info["aliases"]:
                clean_alias = alias.replace(" ", "")
                if len(clean_alias) >= 3 and clean_alias in subdomains and not is_genuine:
                    findings.append(
                        f"Deceptive Subdomain Attack: '{subdomains}' imitates '{brand_name}' "
                        f"on unauthorized domain '{registered_domain}'."
                    )
                    impersonation_score += 45
                    url_threats.append({
                        "url": raw_url,
                        "brand": brand_name,
                        "threat_type": "Deceptive Subdomain",
                    })

                # Check brand in registered domain without being official (e.g. sbi-kyc-update.com)
                if len(clean_alias) >= 3 and clean_alias in registered_domain and not is_genuine:
                    findings.append(
                        f"Domain Brand Spoofing: '{registered_domain}' incorporates '{brand_name}' "
                        f"without official authorization."
                    )
                    impersonation_score += 40
                    url_threats.append({
                        "url": raw_url,
                        "brand": brand_name,
                        "threat_type": "Brand Spoofing",
                    })

                # Check typosquatting on base domain and hyphen-separated parts (Levenshtein distance 1 or 2)
                for off_d in official_domains:
                    off_name = off_d.split(".")[0]
                    domain_tokens = [normalized_domain] + [t for t in re.split(r"[-_]", normalized_domain) if len(t) >= 4]
                    is_typo = any(0 <= _levenshtein_distance(tok, off_name) <= 2 for tok in domain_tokens)
                    if is_typo and len(normalized_domain) >= 4 and not is_genuine:
                        findings.append(
                            f"Typosquatting / Homoglyph Attack: Domain '{registered_domain}' "
                            f"is a close visual lookalike of official '{off_d}'."
                        )
                        impersonation_score += 50
                        url_threats.append({
                            "url": raw_url,
                            "brand": brand_name,
                            "threat_type": "Typosquatting",
                        })

    # If brand was claimed in text, but URL provided is NOT official
    if targeted_brands and urls:
        for b in targeted_brands:
            off_domains = b["official_domains"]
            if off_domains:
                all_urls_are_official = all(
                    any(u.get("domain", "").endswith(d) for d in off_domains)
                    for u in urls
                )
                if not all_urls_are_official:
                    findings.append(
                        f"Sender claims affiliation with '{b['brand']}', but provided links point "
                        f"to unauthorized external domains."
                    )
                    impersonation_score += 35

    is_impersonation = impersonation_score >= 30 or bool(url_threats)
    score_clamped = min(100, impersonation_score)

    return {
        "impersonation_detected": is_impersonation,
        "impersonation_score": score_clamped,
        "targeted_brands": [b["brand"] for b in targeted_brands],
        "brand_details": targeted_brands,
        "findings": list(dict.fromkeys(findings)),
        "url_threats": url_threats,
        "primary_brand": targeted_brands[0]["brand"] if targeted_brands else None,
    }
