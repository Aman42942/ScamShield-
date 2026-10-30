"""Explainable AI (XAI) feature attribution engine for ScamShield.

Provides local feature contribution analysis for the TF-IDF + Logistic Regression
pipeline, calculating token-level weights that explain why the model classified
a given text as scam or legitimate.
"""
from __future__ import annotations
import html
import re
from typing import Any


def extract_token_attributions(model: Any, text: str, top_n: int = 8) -> dict:
    """Computes token-level feature attribution and HTML highlighting.

    Args:
        model: Trained scikit-learn Pipeline with 'tfidf' and 'classifier' steps.
        text: Input message or email text.
        top_n: Maximum number of top contributing tokens to return.

    Returns:
        Dictionary with risk_tokens, safe_tokens, highlighted_html, and xai_summary.
    """
    if not text or not str(text).strip():
        return {
            "available": False,
            "risk_tokens": [],
            "safe_tokens": [],
            "highlighted_html": html.escape(text or ""),
            "summary": "No text provided for feature attribution.",
        }

    try:
        tfidf = model.named_steps.get("tfidf")
        classifier = model.named_steps.get("classifier")
        if tfidf is None or classifier is None:
            return {
                "available": False,
                "risk_tokens": [],
                "safe_tokens": [],
                "highlighted_html": html.escape(text),
                "summary": "Model pipeline does not expose tfidf or classifier steps.",
            }

        feature_names = tfidf.get_feature_names_out()
        classes = list(getattr(model, "classes_", []))
        scam_idx = classes.index("scam") if "scam" in classes else 1
        coefficients = classifier.coef_[0] if classifier.coef_.ndim == 2 else classifier.coef_

        # Vectorize single sample
        X = tfidf.transform([text])
        non_zero_indices = X.nonzero()[1]

        if len(non_zero_indices) == 0:
            return {
                "available": True,
                "risk_tokens": [],
                "safe_tokens": [],
                "highlighted_html": html.escape(text),
                "summary": "None of the tokens in this input matched the trained vocabulary.",
            }

        contributions: list[dict] = []
        for idx in non_zero_indices:
            token = str(feature_names[idx])
            tfidf_weight = float(X[0, idx])
            coef = float(coefficients[idx])
            impact = tfidf_weight * coef

            contributions.append({
                "token": token,
                "tfidf": round(tfidf_weight, 4),
                "coef": round(coef, 4),
                "impact": round(impact, 4),
                "direction": "risk" if impact > 0 else "legitimate",
            })

        # Separate risk (positive) vs safe (negative)
        risk_tokens = sorted(
            [c for c in contributions if c["impact"] > 0],
            key=lambda x: x["impact"],
            reverse=True,
        )[:top_n]

        safe_tokens = sorted(
            [c for c in contributions if c["impact"] < 0],
            key=lambda x: x["impact"],
        )[:top_n]

        # Generate HTML highlighting
        highlighted = _generate_highlighted_html(text, risk_tokens, safe_tokens)

        # Generate human-readable explanation
        summary = _build_xai_summary(risk_tokens, safe_tokens)

        return {
            "available": True,
            "risk_tokens": risk_tokens,
            "safe_tokens": safe_tokens,
            "total_features_activated": len(non_zero_indices),
            "highlighted_html": highlighted,
            "summary": summary,
        }

    except Exception as exc:
        return {
            "available": False,
            "risk_tokens": [],
            "safe_tokens": [],
            "highlighted_html": html.escape(text),
            "summary": f"Feature attribution unavailable: {exc}",
        }


def _generate_highlighted_html(
    text: str, risk_tokens: list[dict], safe_tokens: list[dict]
) -> str:
    """Safely injects visual highlights for top risk and safe tokens."""
    escaped_text = html.escape(text)

    # Sort target tokens from longest to shortest so n-grams take precedence over unigrams
    token_map: dict[str, tuple[str, str, float]] = {}
    for r in risk_tokens:
        tok = r["token"].strip().lower()
        if tok:
            token_map[tok] = ("xai-risk", "Risk Indicator", r["impact"])
    for s in safe_tokens:
        tok = s["token"].strip().lower()
        if tok and tok not in token_map:
            token_map[tok] = ("xai-safe", "Legitimate Context", s["impact"])

    sorted_tokens = sorted(token_map.keys(), key=lambda t: len(t), reverse=True)

    result = escaped_text
    for tok in sorted_tokens:
        cls, label, weight = token_map[tok]
        # Match case-insensitively with boundary checking
        pattern = re.compile(rf"\b({re.escape(html.escape(tok))})\b", re.IGNORECASE)
        replacement = (
            rf'<mark class="xai-mark {cls}" data-weight="{weight:+.4f}" '
            rf'title="{label}: {weight:+.4f}">\1</mark>'
        )
        result = pattern.sub(replacement, result)

    return result


def _build_xai_summary(risk_tokens: list[dict], safe_tokens: list[dict]) -> str:
    if risk_tokens and safe_tokens:
        top_risk_names = ", ".join(f"'{t['token']}' (+{t['impact']:.3f})" for t in risk_tokens[:3])
        return (
            f"Model decision was primarily driven by suspicious tokens {top_risk_names}, "
            f"offset slightly by standard conversational terms."
        )
    if risk_tokens:
        top_risk_names = ", ".join(f"'{t['token']}' (+{t['impact']:.3f})" for t in risk_tokens[:3])
        return f"High risk attribution identified key pressure cues: {top_risk_names}."
    if safe_tokens:
        top_safe_names = ", ".join(f"'{t['token']}'" for t in safe_tokens[:3])
        return f"Attribution shows standard legitimate context tokens like {top_safe_names}."
    return "Balanced token distribution across trained vocabulary."
