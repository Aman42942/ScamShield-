"""Lightweight multilingual normalization for ScamShield.

This is a phrase/keyword normalizer, not a general-purpose machine translator.
It uses only the Python standard library and deliberately reports its coverage.
Supported starter coverage: Hindi (Devanagari), Hinglish (Romanized Hindi),
Bengali, Tamil, Telugu, Marathi, and Punjabi. English text passes through.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Tuple

# Phrase replacements are intentionally conservative: they map common scam-related
# phrases to English concepts already understood by the existing baseline detector.
# Keep longer phrases before shorter phrases where possible.
PHRASE_MAP: Dict[str, Dict[str, str]] = {
    "Hindi": {
        "आपका खाता बंद कर दिया जाएगा": "account will be blocked",
        "आपका खाता बंद हो जाएगा": "account will be blocked",
        "तुरंत सत्यापन करें": "verify immediately",
        "अभी क्लिक करें": "click now",
        "अपना ओटीपी साझा करें": "share your otp",
        "ओटीपी बताएं": "tell me your otp",
        "ओटीपी साझा करें": "share your otp",
        "पासवर्ड भेजें": "send password",
        "पैसे भेजें": "send money",
        "पैसे ट्रांसफर करें": "transfer money",
        "प्रोसेसिंग फीस": "processing fee",
        "इनाम जीता है": "you won prize",
        "आपने इनाम जीता": "you won prize",
        "खाता सत्यापित करें": "verify account",
        "नौकरी पाने के लिए फीस": "job registration fee",
        "गारंटीड मुनाफा": "guaranteed profit",
        "अभी भुगतान करें": "pay now",
    },
    "Hinglish": {
        "aapka account band ho jayega": "account will be blocked",
        "aapka khata band ho jayega": "account will be blocked",
        "turant verify karo": "verify immediately",
        "abhi verify karo": "verify now",
        "abhi click karo": "click now",
        "apna otp batao": "tell me your otp",
        "otp share karo": "share your otp",
        "otp bhejo": "send otp",
        "password bhejo": "send password",
        "paise bhejo": "send money",
        "paisa transfer karo": "transfer money",
        "paise transfer karo": "transfer money",
        "abhi payment karo": "pay now",
        "processing fee do": "processing fee",
        "inaam jeeta hai": "you won prize",
        "inaam mila hai": "you won prize",
        "guaranteed munafa": "guaranteed profit",
        "ghar baithe job": "work from home job",
        "account verify karo": "verify account",
        "link par click karo": "click link",
        "police arrest karegi": "police arrest",
        "account block ho jayega": "account will be blocked",
    },
    "Bengali": {
        "আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে": "account will be blocked",
        "এখনই টাকা পাঠান": "send money immediately",
        "ওটিপি দিন": "share your otp",
        "পাসওয়ার্ড দিন": "share password",
        "এখনই পেমেন্ট করুন": "pay now",
        "আপনি পুরস্কার জিতেছেন": "you won prize",
        "অ্যাকাউন্ট যাচাই করুন": "verify account",
    },
    "Tamil": {
        "உங்கள் கணக்கு முடக்கப்படும்": "account will be blocked",
        "உடனே பணம் அனுப்புங்கள்": "send money immediately",
        "ஓடிபி சொல்லுங்கள்": "tell me your otp",
        "கடவுச்சொல்லை பகிரவும்": "share password",
        "இப்போது பணம் செலுத்துங்கள்": "pay now",
        "நீங்கள் பரிசு வென்றுள்ளீர்கள்": "you won prize",
        "கணக்கை சரிபார்க்கவும்": "verify account",
    },
    "Telugu": {
        "మీ ఖాతా నిలిపివేయబడుతుంది": "account will be blocked",
        "వెంటనే డబ్బు పంపండి": "send money immediately",
        "ఓటిపి చెప్పండి": "tell me your otp",
        "పాస్‌వర్డ్ పంపండి": "send password",
        "ఇప్పుడే చెల్లించండి": "pay now",
        "మీరు బహుమతి గెలుచుకున్నారు": "you won prize",
        "ఖాతాను ధృవీకరించండి": "verify account",
    },
    "Marathi": {
        "तुमचे खाते बंद केले जाईल": "account will be blocked",
        "लगेच पैसे पाठवा": "send money immediately",
        "ओटीपी सांगा": "tell me your otp",
        "पासवर्ड पाठवा": "send password",
        "आता पैसे भरा": "pay now",
        "तुम्ही बक्षीस जिंकले आहे": "you won prize",
        "खाते सत्यापित करा": "verify account",
    },
    "Punjabi": {
        "ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਕਰ ਦਿੱਤਾ ਜਾਵੇਗਾ": "account will be blocked",
        "ਤੁਰੰਤ ਪੈਸੇ ਭੇਜੋ": "send money immediately",
        "ਓਟੀਪੀ ਦੱਸੋ": "tell me your otp",
        "ਪਾਸਵਰਡ ਭੇਜੋ": "send password",
        "ਹੁਣੇ ਭੁਗਤਾਨ ਕਰੋ": "pay now",
        "ਤੁਸੀਂ ਇਨਾਮ ਜਿੱਤਿਆ ਹੈ": "you won prize",
        "ਖਾਤਾ ਤਸਦੀਕ ਕਰੋ": "verify account",
    },
}

# Romanized Hindi words/phrases that commonly occur in short messages.
# These are only cues; they are not enough to translate arbitrary Hinglish text.
HINGLISH_WORD_MAP: Dict[str, str] = {
    "otp": "otp", "otपी": "otp", "paise": "money", "paisa": "money",
    "bhejo": "send", "bhej": "send", "bhejna": "send", "bhejiye": "send",
    "turant": "immediately", "abhi": "now", "jaldi": "immediately",
    "karo": "do", "karein": "do", "kijiye": "do", "khata": "account",
    "khata": "account", "account": "account", "band": "blocked",
    "rok": "block", "block": "block", "hojayega": "will be",
    "ho": "be", "jayega": "will", "jeeta": "won", "inaam": "prize",
    "inaam": "prize", "muft": "free", "naukri": "job", "naukari": "job",
    "shulk": "fee", "fees": "fee", "jama": "deposit", "bhugtan": "payment",
    "verify": "verify", "satyapit": "verify", "password": "password",
    "guaranteed": "guaranteed", "munafa": "profit", "laabh": "profit",
    "link": "link", "click": "click", "khole": "open", "kholiye": "open",
}

SCRIPT_RANGES: List[Tuple[str, int, int]] = [
    ("Hindi", 0x0900, 0x097F),       # Devanagari (also used by Marathi)
    ("Bengali", 0x0980, 0x09FF),
    ("Punjabi", 0x0A00, 0x0A7F),     # Gurmukhi
    ("Tamil", 0x0B80, 0x0BFF),
    ("Telugu", 0x0C00, 0x0C7F),
]

LANGUAGE_CUES = {
    "Hindi": {"hai", "hain", "aap", "aapka", "apna", "karo", "bhejo", "paise", "paisa", "turant", "abhi", "nahi", "kyc", "inaam", "naukri"},
    "Bengali": {"apnar", "taka", "ekhoni", "puraskar", "account", "otp"},
    "Tamil": {"ungal", "panam", "udane", "parisu", "kanakku", "otp"},
    "Telugu": {"mee", "dabbu", "ventane", "bahumati", "khata", "otp"},
    "Marathi": {"tumche", "lagech", "paise", "khate", "bakshees", "otp"},
    "Punjabi": {"tuhada", "paise", "turant", "inaam", "khata", "otp"},
}


def _script_counts(text: str) -> Counter:
    counts = Counter()
    for char in text:
        cp = ord(char)
        for language, start, end in SCRIPT_RANGES:
            if start <= cp <= end:
                counts[language] += 1
                break
    return counts


def detect_language(text: str) -> dict:
    """Return a best-effort language/script label and confidence indicator."""
    text = text or ""
    counts = _script_counts(text)
    script_total = sum(counts.values())
    if script_total:
        script_language, script_hits = counts.most_common(1)[0]
        # Devanagari is shared by Hindi and Marathi; distinguish with a few cues.
        if script_language == "Hindi":
            lower = text.lower()
            marathi_markers = ("तुमचे", "आहे", "लगेच", "करा", "जिंकल")
            if any(marker in lower for marker in marathi_markers):
                script_language = "Marathi"
        ratio = script_hits / max(script_total, 1)
        return {
            "language": script_language,
            "script": "native script",
            "confidence": round(min(0.99, 0.55 + 0.4 * ratio), 2),
            "method": "script heuristic",
        }

    tokens = set(re.findall(r"[a-zA-Z]+", text.lower()))
    cue_scores = {lang: len(tokens & cues) for lang, cues in LANGUAGE_CUES.items()}
    best_language, best_score = max(cue_scores.items(), key=lambda item: item[1])
    if best_score >= 2:
        return {
            "language": "Hinglish" if best_language == "Hindi" else best_language,
            "script": "Latin / transliterated",
            "confidence": round(min(0.85, 0.45 + 0.1 * best_score), 2),
            "method": "keyword heuristic",
        }
    if best_score == 1 and (tokens & {"paise", "paisa", "bhejo", "turant", "aapka", "inaam", "naukri"}):
        return {"language": "Hinglish", "script": "Latin / transliterated", "confidence": 0.5, "method": "keyword heuristic"}
    return {"language": "English / undetermined", "script": "Latin / mixed", "confidence": 0.5, "method": "fallback"}


def normalize_for_detection(text: str) -> tuple[str, dict]:
    """Map known scam-related phrases to English so existing rules/model can use them."""
    original = text or ""
    metadata = detect_language(original)
    normalized = original.lower()
    matched = []

    # Apply phrase maps for every script so mixed-language messages are supported.
    # Longer phrase replacement first avoids a shorter phrase masking a longer one.
    for language, phrases in PHRASE_MAP.items():
        for phrase, english in sorted(phrases.items(), key=lambda item: len(item[0]), reverse=True):
            if phrase.lower() in normalized:
                normalized = normalized.replace(phrase.lower(), english)
                matched.append({"language": language, "source_phrase": phrase, "normalized_phrase": english})

    # Translate only a small set of standalone Romanized Hindi tokens. This is not
    # a full translation and intentionally leaves unknown words untouched.
    tokens = re.findall(r"\w+|[^\w\s]", normalized, flags=re.UNICODE)
    translated_tokens = []
    for token in tokens:
        replacement = HINGLISH_WORD_MAP.get(token.lower())
        if replacement and token.isalpha():
            translated_tokens.append(replacement)
            if replacement != token.lower():
                matched.append({"language": "Hinglish", "source_phrase": token, "normalized_phrase": replacement})
        else:
            translated_tokens.append(token)
    normalized = " ".join(translated_tokens)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    metadata = {
        **metadata,
        "normalization_applied": bool(matched),
        "matched_terms": matched[:20],
        "coverage_note": "Keyword/phrase-based prototype; not full translation. Unrecognized wording may be missed.",
    }
    return normalized, metadata
