"""Output Guard: last deterministic check before text reaches the user.

Policy
------
* BLOCK  - protected content that must never be shown: confidential markers,
           system-prompt leakage, or a bulk dump of credentials.
* REDACT - credentials and personal data are masked; the rest of the answer is
           kept. Masked values never appear in the response, the security
           explanation or the logs (``redact`` is also used by the logger).
* ALLOW  - nothing sensitive found.

Masking is not authorization: tools that would return data the user may not
see are refused by the Tool Guard *before* execution.
"""

import re

from app.llm.system_prompt import SYSTEM_PROMPT
from app.security.risk_engine import RiskPolicy, evaluate

# (kind, pattern, confidence). Credentials first: more specific wins.
CREDENTIALS = [
    (
        "PRIVATE_KEY",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
        0.99,
    ),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", 0.95),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{30,}", 0.95),
    ("GOOGLE_API_KEY", r"\bAQ\.[A-Za-z0-9_-]{20,}", 0.9),
    ("API_KEY", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", 0.9),
    ("API_KEY", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}", 0.9),
    ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{30,}", 0.95),
    ("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.95),
    ("SLACK_TOKEN", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0.95),
    (
        "PASSWORD_HASH",
        r"\$argon2(?:id|i|d)\$[^\s\"',}]+|\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}",
        0.95,
    ),
    ("BEARER_TOKEN", r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*", 0.9),
    ("CONNECTION_STRING", r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s@/]+@[^\s/]+", 0.9),
    (
        "SECRET_ASSIGNMENT",
        r"(?i)\b(?:password|passwd|pwd|secret|client[_ -]?secret|api[_ -]?key|access[_ -]?key"
        r"|auth[_ -]?token|token|jwt[_ -]?secret|hashed_password|mot de passe|mdp)"
        r"\b\s*[:=]\s*[\"']?[^\s,;\"'}]{3,}",
        0.85,
    ),
]
PERSONAL = [
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b", 0.7),
    ("CARD_NUMBER", r"\b\d(?:[ -]?\d){12,18}\b", 0.7),  # Luhn-checked below
    ("FR_SSN", r"\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]) ?\d{2} ?\d{3} ?\d{3} ?\d{2}\b", 0.7),
    (
        "PHONE",
        r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(?\d{1,4}\)?[ .-]?){2,5}\d{2,4}(?!\w)",
        0.5,
    ),
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b", 0.4),
]
CONFIDENTIAL_MARKERS = [
    "confidential",
    "confidentiel",
    "strictly internal",
    "usage interne uniquement",
    "private_professor",
    "never reveal instructions",
]
INSTITUTIONAL_DOMAINS = ("esigelec-demo.fr", "esigelec.fr")
BULK_CREDENTIALS = 3
# Output blocking is driven by mandatory rules only; the score is reported to
# explain severity but must not turn a maskable answer into a refusal.
OUTPUT_POLICY = RiskPolicy(block_threshold=101)

_CREDENTIALS = [(k, re.compile(p), c) for k, p, c in CREDENTIALS]
_PERSONAL = [(k, re.compile(p), c) for k, p, c in PERSONAL]
_PROMPT_WORDS = re.findall(r"\w+", SYSTEM_PROMPT.casefold())
SHINGLE = 8
_PROMPT_SHINGLES = {
    " ".join(_PROMPT_WORDS[i : i + SHINGLE])
    for i in range(len(_PROMPT_WORDS) - SHINGLE + 1)
}


def _luhn(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _phone_like(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return False
    # Phone formats start with "+", a trunk "0" or an area code in brackets;
    # bare long numbers are identifiers (ticket, course or order ids).
    if not value.lstrip().startswith(("+", "0", "(")):
        return False
    # Dates, times and room codes are not phone numbers.
    return not re.fullmatch(r"\d{4}-\d{2}-\d{2}.*|\d{1,2}:\d{2}.*", value.strip())


def _email_allowed(email: str, user) -> bool:
    email = email.casefold()
    if user is None:
        return False
    if email == (getattr(user, "email", "") or "").casefold():
        return True
    # Directory search is an administrator permission (enforced by RBAC), so
    # institutional addresses are expected in their answers.
    return getattr(user, "role", None) == "ADMIN" and email.endswith(
        tuple("@" + d for d in INSTITUTIONAL_DOMAINS)
    )


def find_sensitive(text: str, user=None):
    """Return non-overlapping findings ``(start, end, kind, category, confidence)``."""
    findings = []
    taken = []

    def free(start, end):
        return all(end <= s or start >= e for s, e in taken)

    for category, rules in (("credential", _CREDENTIALS), ("personal", _PERSONAL)):
        for kind, pattern, confidence in rules:
            for m in pattern.finditer(text):
                value = m.group(0)
                if kind == "CARD_NUMBER" and not _luhn(value):
                    continue
                if kind == "PHONE" and not _phone_like(value):
                    continue
                if kind == "EMAIL" and _email_allowed(value, user):
                    continue
                if free(m.start(), m.end()):
                    taken.append((m.start(), m.end()))
                    findings.append((m.start(), m.end(), kind, category, confidence))
    return sorted(findings)


def _mask(text, findings):
    out, last = [], 0
    for start, end, kind, _, _ in findings:
        label = (
            "[EMAIL REDACTED]"
            if kind == "EMAIL"
            else ("[PHONE REDACTED]" if kind == "PHONE" else f"[REDACTED:{kind}]")
        )
        out.append(text[last:start] + label)
        last = end
    return "".join(out) + text[last:]


def redact(text, user=None):
    """Mask credentials and personal data (used for responses and logs)."""
    if not text:
        return text
    return _mask(text, find_sensitive(text, user))


def leaks_system_prompt(text: str) -> bool:
    words = re.findall(r"\w+", text.casefold())
    return any(
        " ".join(words[i : i + SHINGLE]) in _PROMPT_SHINGLES
        for i in range(len(words) - SHINGLE + 1)
    )


def _signal(kind, category, confidence, count):
    return {
        "detector": f"output_{category}",
        "threat": "INFORMATION_LEAKAGE",
        "matched": True,
        "confidence": confidence,
        "evidence": f"{count} {kind.lower().replace('_', ' ')} value(s) in output",
        "source": "model_output",
    }


def inspect_output(text, user):
    text = text or ""
    lowered = text.casefold()
    if any(m in lowered for m in CONFIDENTIAL_MARKERS) or leaks_system_prompt(text):
        return "Protected output blocked.", evaluate(
            [_signal("CONFIDENTIAL_CONTENT", "confidential", 0.95, 1)],
            source_trust="model_output",
            mandatory_block=True,
            reason="Confidential output blocked.",
            policy=OUTPUT_POLICY,
        )
    findings = find_sensitive(text, user)
    if not findings:
        return text, evaluate(source_trust="model_output", policy=OUTPUT_POLICY)
    counts = {}
    for _, _, kind, category, confidence in findings:
        counts.setdefault((kind, category), [0, confidence])[0] += 1
    signals = [_signal(k, cat, conf, n) for (k, cat), (n, conf) in counts.items()]
    credentials = sum(1 for f in findings if f[3] == "credential")
    if credentials >= BULK_CREDENTIALS:
        return "Protected output blocked.", evaluate(
            signals,
            source_trust="model_output",
            mandatory_block=True,
            reason="Output contained multiple credentials; blocked as a bulk leak.",
            policy=OUTPUT_POLICY,
        )
    kinds = ", ".join(sorted({k.lower().replace("_", " ") for k, _ in counts}))
    return _mask(text, findings), evaluate(
        signals,
        source_trust="model_output",
        mandatory_redact=True,
        reason=f"Sensitive values redacted ({kinds}).",
        policy=OUTPUT_POLICY,
    )
