"""Cybercrime Incident Reporting and 1930 Complaint Draft Generator.

Formats structured, evidence-backed cyber incident complaints conforming
to Indian Cyber Crime Coordination Centre (I4C) and cybercrime.gov.in standards,
including IT Act 2000 section references and SHA-256 evidence integrity hashing.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

PHONE_REGEX = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{9}\b")
UPI_REGEX = re.compile(r"\b[\w.-]+@(?:okaxis|okhdfcbank|okicici|okbizaxis|ybl|ibl|axl|paytm|apl|upi)\b", re.I)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
AMOUNT_REGEX = re.compile(r"(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d+)?|\b[\d,]+\s*(?:rupees|rs)\b", re.I)


def generate_complaint_draft(
    text: str,
    scam_type: str,
    risk_level: str,
    risk_percent: int,
    stage: str,
    urls: list[dict] | None = None,
    impersonation_info: dict | None = None,
) -> dict[str, Any]:
    """Generates an official complaint draft with extracted entities and forensic hash."""
    clean_text = (text or "").strip()
    evidence_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
    incident_id = f"CYB-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{evidence_hash[:8].upper()}"
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract forensic artifacts
    phone_numbers = list(dict.fromkeys(PHONE_REGEX.findall(clean_text)))
    upi_ids = list(dict.fromkeys(UPI_REGEX.findall(clean_text)))
    emails = list(dict.fromkeys(EMAIL_REGEX.findall(clean_text)))
    amounts = list(dict.fromkeys(AMOUNT_REGEX.findall(clean_text)))

    url_list = [u.get("url", "") for u in (urls or []) if u.get("url")]
    domains = list(dict.fromkeys(u.get("domain", "") for u in (urls or []) if u.get("domain")))

    # Identify primary brand if impersonated
    brand_impersonated = "None / General Impersonation"
    if impersonation_info and impersonation_info.get("targeted_brands"):
        brand_impersonated = ", ".join(impersonation_info["targeted_brands"])

    # Determine legal clauses
    it_act_sections = ["Section 66D (Cheating by personation using computer resource)"]
    if any(k in clean_text.lower() for k in ["otp", "password", "pin", "cvv", "aadhaar", "pan"]):
        it_act_sections.append("Section 66C (Identity theft / unauthorized capture of credentials)")
    it_act_sections.append("IPC Section 419/420 / BNS 318 (Cheating and criminal deception)")

    # Build formatted complaint text
    suspect_contact_lines = []
    if phone_numbers:
        suspect_contact_lines.append(f"• Suspect Phone Number(s): {', '.join(phone_numbers)}")
    if upi_ids:
        suspect_contact_lines.append(f"• Suspect UPI Handle(s): {', '.join(upi_ids)}")
    if domains:
        suspect_contact_lines.append(f"• Fraudulent Domain(s) / Links: {', '.join(domains)}")
    if emails:
        suspect_contact_lines.append(f"• Suspect Email Address(es): {', '.join(emails)}")
    if not suspect_contact_lines:
        suspect_contact_lines.append("• Contact Details: Electronic transmission / SMS / Direct Message")

    complaint_body = (
        f"OFFICIAL CYBER INCIDENT COMPLAINT DRAFT\n"
        f"Portal: National Cyber Crime Reporting Portal (cybercrime.gov.in)\n"
        f"Helpline: 1930 (Citizen Financial Cyber Fraud Reporting System)\n"
        f"{'=' * 72}\n\n"
        f"INCIDENT REFERENCE ID : {incident_id}\n"
        f"RECORDING TIMESTAMP    : {timestamp_str}\n"
        f"INCIDENT CATEGORY      : {scam_type}\n"
        f"ATTACK STAGE           : {stage}\n"
        f"AUTOMATED RISK LEVEL   : {risk_level} ({risk_percent}% confidence)\n"
        f"IMPERSONATED ENTITY    : {brand_impersonated}\n"
        f"EVIDENCE SHA-256 HASH  : {evidence_hash}\n\n"
        f"1. SUSPECT IDENTIFIERS:\n"
        f"{chr(10).join(suspect_contact_lines)}\n\n"
        f"2. MODUS OPERANDI (SUMMARY OF ATTEMPTED FRAUD):\n"
        f"The suspect approached the victim using deceptive communication tactics designed to simulate "
        f"official correspondence from {brand_impersonated}. The message applies artificial urgency, "
        f"intimidation, or deceptive inducements to elicit sensitive credentials or unauthorized financial "
        f"transfers."
    )

    if amounts:
        complaint_body += f"\nFinancial demand / claimed amount referenced: {', '.join(amounts)}."

    complaint_body += (
        f"\n\n3. EVIDENCE / ORIGINAL MESSAGE CONTENT:\n"
        f"\"\"\"\n{clean_text}\n\"\"\"\n\n"
        f"4. APPLICABLE LEGAL SECTIONS FOR INVESTIGATION:\n"
        f"• " + "\n• ".join(it_act_sections) + "\n\n"
        f"5. RELIEF SOUGHT:\n"
        f"1. Immediate blocking and blacklisting of the suspect phone numbers / phishing domains.\n"
        f"2. Preventive freeze of associated UPI VPAs or beneficiary bank accounts (via Helpline 1930).\n"
        f"3. Registration of formal First Information Report (FIR) under the IT Act 2000.\n\n"
        f"{'=' * 72}\n"
        f"Generated automatically by ScamShield Digital Forensics & Scam Defense Engine.\n"
        f"Preserve this document and submit with transaction SMS/screenshot at cybercrime.gov.in."
    )

    return {
        "incident_id": incident_id,
        "timestamp": timestamp_str,
        "evidence_sha256": evidence_hash,
        "phone_numbers": phone_numbers,
        "upi_ids": upi_ids,
        "domains": domains,
        "amounts": amounts,
        "legal_sections": it_act_sections,
        "complaint_draft": complaint_body,
        "helpline": "1930",
        "portal_url": "https://cybercrime.gov.in",
    }
