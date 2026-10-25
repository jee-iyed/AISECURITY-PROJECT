"""Baseline: the original single-pass regex Input Guard (commit 35e819a).

Kept verbatim (patterns, scores, first-match semantics, NFKD normalization)
so the benchmark compares against what the prototype actually shipped. It is
NOT used by the application; production uses app.security.input_guard.
"""

import re
import unicodedata

PATTERNS = [
    (
        "PROMPT_INJECTION",
        88,
        r"(ignore|forget|oublie|ne tiens pas compte).{0,70}(instruction|regle|rule|previous|precedent)",
    ),
    (
        "ROLE_MANIPULATION",
        90,
        r"(i am|you are now|act as|je suis|tu es|agis comme).{0,30}(admin|administrateur)",
    ),
    (
        "JAILBREAK",
        80,
        r"(restriction|safeguard|regle|rule).{0,50}(desactiv|disable)|sans (regles|restriction)|without (rules|restriction)|bypass.{0,20}safeguard",
    ),
    (
        "INFORMATION_LEAKAGE",
        90,
        r"(system.{0,10}prompt|internal instruction|instructions? (interne|systeme)|donnees privees|private.{0,20}(professor|data)|api.?key|mot de passe|password)",
    ),
]


def normalize(text):
    return "".join(
        c
        for c in unicodedata.normalize("NFKD", text.casefold())
        if not unicodedata.combining(c)
    )


def analyze(text, source="user_prompt"):
    """Return (decision, threat_type, score) like the original guard.

    The original Context Guard reused this exact function and relabelled any
    hit as INDIRECT_PROMPT_INJECTION with score 80.
    """
    normalized = normalize(text or "")
    for threat, score, pattern in PATTERNS:
        if re.search(pattern, normalized):
            if source != "user_prompt":
                return "BLOCK", "INDIRECT_PROMPT_INJECTION", 80
            return "BLOCK", threat, score
    return "ALLOW", None, 10
