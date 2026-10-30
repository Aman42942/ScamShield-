"""ScamShield Detection & Forensics Orchestrator.

Integrates ML classification, Explainable AI (XAI) feature attribution,
brand impersonation & typosquatting detection, multilingual phrase normalization,
URL heuristics, stage profiling, and I4C 1930 cybercrime complaint drafting.
"""
from ml.model_service import load_or_train
from backend.rules import RULES, SCAM_TYPES, STAGES
from backend.url_analyzer import analyze_urls
from backend.stage_detector import detect_stage
from backend.scoring import calculate_risk
from backend.recommendations import recommendation_for, explanation_for
from backend.validation import validate_input_type, validate_text
from backend.language_detector import normalize_for_detection
from backend.xai_engine import extract_token_attributions
from backend.brand_detector import detect_brand_impersonation
from backend.complaint_generator import generate_complaint_draft

MODEL = load_or_train()


def normalize(text: str) -> str:
    import re
    return re.sub(r"\s+", " ", text.lower()).strip()


def detect_rules(text: str) -> list[dict]:
    t = normalize(text)
    matches = []
    for category, words in RULES.items():
        found = [w for w in words if w in t]
        if found:
            matches.append({"category": category, "matches": found[:6], "hit_count": len(found)})
    return matches


def detect_scam_type(text: str) -> dict:
    t = normalize(text)
    scores = {name: sum(word in t for word in words) for name, words in SCAM_TYPES.items()}
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    name, score = ranked[0]
    return {
        "name": name if score else "General / Unclassified Scam",
        "score": score,
        "ranking": [{"type": n, "hits": s} for n, s in ranked if s],
    }


def model_probability(text: str) -> float:
    probs = MODEL.predict_proba([text])[0]
    classes = list(MODEL.classes_)
    if "scam" in classes:
        return float(probs[classes.index("scam")])
    return float(max(probs))


def analyze_text(text: str, input_type: str = "message") -> dict:
    original_text = validate_text(text)
    input_type = validate_input_type(input_type)

    normalized_text, language_info = normalize_for_detection(original_text)
    # URL extraction operates on original text to preserve authentic parameters and tokens
    urls = analyze_urls(original_text)
    brand_info = detect_brand_impersonation(original_text, urls)
    rule_hits = detect_rules(normalized_text)
    stage, stage_hits, stage_matches, stage_ranking = detect_stage(normalized_text)
    scam_type = detect_scam_type(normalized_text)
    ml_probability_value = model_probability(normalized_text)

    risk_data = calculate_risk(
        ml_probability_value,
        len(rule_hits),
        sum(u["score"] for u in urls),
        stage_hits,
        brand_score=brand_info["impersonation_score"],
    )

    flags = [x["category"] for x in rule_hits]
    for url in urls:
        flags.extend(url["flags"])
    if brand_info["impersonation_detected"]:
        flags.append(f"Brand Impersonation ({brand_info['primary_brand']})")
        for finding in brand_info["findings"][:2]:
            flags.append(finding)

    if not flags:
        flags = ["No major red flags detected"]

    risk = risk_data["risk"]

    # Explainable AI token attribution
    xai_info = extract_token_attributions(MODEL, normalized_text)

    # National Cybercrime Reporting Portal & 1930 Helpline Complaint Draft
    complaint_info = generate_complaint_draft(
        text=original_text,
        scam_type=scam_type["name"],
        risk_level=risk_data["level"],
        risk_percent=risk,
        stage=stage,
        urls=urls,
        impersonation_info=brand_info,
    )

    return {
        **risk_data,
        "scam_probability": round(ml_probability_value * 100, 2),
        "input_type": input_type.title(),
        "scam_type": scam_type["name"],
        "scam_type_score": scam_type["score"],
        "scam_type_ranking": scam_type["ranking"],
        "stage": stage,
        "stage_hits": stage_hits,
        "stage_matches": stage_matches,
        "stage_ranking": stage_ranking,
        "rule_hits": rule_hits,
        "red_flags": list(dict.fromkeys(flags)),
        "urls": urls,
        "recommendation": recommendation_for(risk),
        "explanation": explanation_for(rule_hits, urls, stage),
        "language_analysis": language_info,
        "brand_analysis": brand_info,
        "xai_analysis": xai_info,
        "complaint_draft": complaint_info,
        "evidence_sha256": complaint_info["evidence_sha256"],
        "incident_id": complaint_info["incident_id"],
        "normalized_text_preview": normalized_text[:500],
        "model": {
            "name": "TF-IDF + Logistic Regression",
            "version": "v2.0-xai-brand-defense",
        },
    }


def analyze_batch(items: list[dict]) -> list[dict]:
    return [analyze_text(item.get("content", ""), item.get("input_type", "message")) for item in items]


def backend_metadata() -> dict:
    return {
        "service": "ScamShield Detection & Forensics API",
        "version": "2.0.0",
        "model": "TF-IDF + Logistic Regression with Explainable AI (XAI)",
        "features": [
            "Local XAI Feature Attribution",
            "Brand Impersonation & Typosquatting Detection",
            "Multilingual & Hinglish Phrase Normalization",
            "Phishing URL & Deceptive Subdomain Analysis",
            "National Cyber Crime 1930 Complaint Draft Generator",
            "SHA-256 Tamper-Evident Evidence Integrity",
        ],
        "supported_inputs": ["message", "email", "conversation", "url"],
        "scam_types": list(SCAM_TYPES.keys()),
        "stages": [stage for stage, _ in STAGES],
        "language_support": ["English", "Hindi", "Hinglish", "Bengali", "Tamil", "Telugu", "Marathi", "Punjabi"],
    }
