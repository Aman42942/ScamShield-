from typing import Any

ALLOWED_INPUT_TYPES = {"message", "email", "conversation", "url"}
MAX_TEXT_LENGTH = 5000
MAX_BATCH_ITEMS = 20


class ValidationError(ValueError):
    """Raised when an API or form payload is invalid."""


def validate_input_type(value: Any) -> str:
    value = str(value or "message").strip().lower()
    if value not in ALLOWED_INPUT_TYPES:
        raise ValidationError(
            f"Invalid input_type. Use one of: {', '.join(sorted(ALLOWED_INPUT_TYPES))}."
        )
    return value


def validate_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("content must be a text string.")
    text = value.strip()
    if not text:
        raise ValidationError("Please enter content to analyze.")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValidationError(
            f"Content is too long. Maximum length is {MAX_TEXT_LENGTH} characters."
        )
    return text


def validate_payload(payload: Any) -> tuple[str, str]:
    if not isinstance(payload, dict):
        raise ValidationError("Request body must be a JSON object.")
    text = validate_text(payload.get("content"))
    input_type = validate_input_type(payload.get("input_type", "message"))
    return text, input_type
