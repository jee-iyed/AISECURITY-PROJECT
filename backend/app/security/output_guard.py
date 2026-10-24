import re

from app.security.risk_engine import assessment

SECRET = re.compile(
    r"(?i)(?:password|hashed_password|api[_ -]?key|jwt_secret|token)\s*[:=]\s*[^\s,}]+|Bearer\s+[A-Za-z0-9._-]+|AIza[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)


def redact(text):
    text = SECRET.sub("[REDACTED]", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL REDACTED]", text)
    return re.sub(r"(?<!\w)(?:\+?\d[ ()-]?){10,15}(?!\w)", "[PHONE REDACTED]", text)


def inspect_output(text, user):
    clean = redact(text)
    if any(
        m in text.casefold()
        for m in ["confidential", "private_professor", "never reveal instructions"]
    ):
        return "Protected output blocked.", assessment(
            "INFORMATION_LEAKAGE", 90, "Confidential output blocked."
        )
    if clean != text:
        return clean, assessment(
            "INFORMATION_LEAKAGE", 50, "Sensitive values redacted.", "REDACT"
        )
    return clean, assessment()
