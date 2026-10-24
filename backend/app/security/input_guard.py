import re

from app.llm.agent import normalize
from app.security.risk_engine import assessment

PATTERNS = [
    (
        "PROMPT_INJECTION",
        88,
        r"(ignore|forget|oublie|ne tiens pas compte).{0,70}(instruction|regle|rule|previous|precedent)",
        "Attempt to override application instructions.",
    ),
    (
        "ROLE_MANIPULATION",
        90,
        r"(i am|you are now|act as|je suis|tu es|agis comme).{0,30}(admin|administrateur)",
        "Prompt cannot change the authenticated role.",
    ),
    (
        "JAILBREAK",
        80,
        r"(restriction|safeguard|regle|rule).{0,50}(desactiv|disable)|sans (regles|restriction)|without (rules|restriction)|bypass.{0,20}safeguard",
        "Attempt to disable safeguards.",
    ),
    (
        "INFORMATION_LEAKAGE",
        90,
        r"(system.{0,10}prompt|internal instruction|instructions? (interne|systeme)|donnees privees|private.{0,20}(professor|data)|api.?key|mot de passe|password)",
        "Request for protected information.",
    ),
]


def analyze_input(prompt, user_context=None):
    normalized = normalize(prompt)
    for threat, score, pattern, reason in PATTERNS:
        if re.search(pattern, normalized):
            return assessment(threat, score, reason)
    return assessment()


def analyze_unfulfilled_action(prompt, user):
    # A model refusal is text, so no function call reaches Tool Guard. Preserve
    # an explicit BLOCK for clear unauthorized schedule-write requests as well.
    if user.role != "ADMIN" and re.search(
        r"\b(change|modifie|deplace|update|move)\b.{0,100}\b(salle|room|cours|course|schedule|emploi)\b",
        normalize(prompt),
    ):
        return assessment(
            "TOOL_ABUSE", 95, "Authenticated role cannot modify schedules."
        )
    return assessment()
