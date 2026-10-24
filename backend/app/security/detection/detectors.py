"""Complementary deterministic detectors.

Every detector receives the prepared analysis views and returns structured
:class:`Signal` objects. Detectors never decide: the risk engine combines their
signals with the execution context.
"""

import re
from dataclasses import asdict, dataclass

from app.security.detection.framing import framing_factor
from app.security.detection.lexicon import (
    COMPACT,
    INSTRUCTION_DETECTORS,
    LEXICON,
    THREAT_OF,
)
from app.security.detection.normalizer import AnalysisText

EXCERPT_CHARS = 80
_COMPILED = {
    detector: [
        (re.compile(pattern), confidence, evidence)
        for patterns in languages.values()
        for pattern, confidence, evidence in patterns
    ]
    for detector, languages in LEXICON.items()
}
_COMPACT = [(d, re.compile(p), c, e) for d, p, c, e in COMPACT]
_CLAIMED_ROLE = {
    "ADMIN": re.compile(r"\b(admin\w*|root|superu\w*|sysadmin)\b"),
    "PROFESSOR": re.compile(r"\b(professor|teacher|professeur|enseignant)\b"),
}


@dataclass(frozen=True)
class Signal:
    detector: str
    threat: str
    matched: bool
    confidence: float
    evidence: str
    source: str
    view: str = "normalized"
    framing: str = "direct"
    excerpt: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DetectionContext:
    source: str = "user_prompt"
    role: str | None = None


def _excerpt(text: str, start: int, end: int) -> str:
    # Excerpts come from the normalized view and are capped; callers redact
    # them again before logging.
    return text[start:end][:EXCERPT_CHARS]


def _threat(detector: str, ctx: DetectionContext) -> str:
    if ctx.source != "user_prompt" and detector in INSTRUCTION_DETECTORS:
        return "INDIRECT_PROMPT_INJECTION"
    return THREAT_OF[detector]


def _scan(detector: str, text: AnalysisText, ctx: DetectionContext) -> list[Signal]:
    best: dict[str, Signal] = {}
    for pattern, base, evidence in _COMPILED[detector]:
        for view, content in text.views.items():
            if view == "squeezed":
                continue
            match = pattern.search(content)
            if not match:
                continue
            if view == "normalized":
                factor, label = framing_factor(content, match.start(), match.end())
                confidence = base * factor
            else:
                # Matches that only appear after de-obfuscation are not
                # attenuated: hiding an instruction is itself suspicious.
                if pattern.search(text.normalized):
                    continue
                label = f"revealed by {view.split('#')[0]}"
                confidence = min(0.99, base + 0.05)
            if detector == "role_manipulation" and ctx.role:
                claimed = _CLAIMED_ROLE.get(ctx.role)
                if claimed and claimed.search(match.group(0)):
                    confidence *= 0.2
                    label = "claim matches authenticated role"
            signal = Signal(
                detector=detector,
                threat=_threat(detector, ctx),
                matched=True,
                confidence=round(confidence, 3),
                evidence=evidence,
                source=ctx.source,
                view=view,
                framing=label,
                excerpt=_excerpt(content, match.start(), match.end()),
            )
            key = f"{view}:{match.start()}"
            current = best.get(key)
            if current is None or signal.confidence > current.confidence:
                best[key] = signal
    squeezed = text.views.get("squeezed")
    if squeezed and not best:
        for name, pattern, confidence, evidence in _COMPACT:
            match = pattern.search(squeezed) if name == detector else None
            if match:
                best["squeezed"] = Signal(
                    detector=detector,
                    threat=_threat(detector, ctx),
                    matched=True,
                    confidence=confidence,
                    evidence=evidence,
                    source=ctx.source,
                    view="squeezed",
                    framing="revealed by squeezed",
                    excerpt=_excerpt(squeezed, match.start(), match.end()),
                )
    return list(best.values())


def detect_obfuscation(text: AnalysisText, ctx: DetectionContext) -> list[Signal]:
    flags = text.flags
    checks = [
        ("invisible_in_word", 0.6, "invisible characters inside words"),
        ("homoglyphs", 0.6, "mixed-script homoglyph tokens"),
        ("separator_runs", 0.5, "letters split by separators"),
        ("decoded_segments", 0.5, "encoded payload decoded to text"),
        ("control_chars", 0.4, "control characters in text"),
        ("leet_tokens", 0.3, "leetspeak substitutions"),
    ]
    signals = []
    for flag, confidence, evidence in checks:
        if flags.get(flag):
            signals.append(
                Signal(
                    detector="obfuscation",
                    threat="OBFUSCATION",
                    matched=True,
                    confidence=confidence,
                    evidence=f"{evidence} ({flags[flag]})",
                    source=ctx.source,
                    view="raw",
                    framing="n/a",
                )
            )
    return signals


DETECTORS = {
    "signature": lambda t, c: _scan("signature", t, c),
    "obfuscation": detect_obfuscation,
    "instruction_override": lambda t, c: _scan("instruction_override", t, c),
    "role_manipulation": lambda t, c: _scan("role_manipulation", t, c),
    "jailbreak": lambda t, c: _scan("jailbreak", t, c),
    "sensitive_information": lambda t, c: _scan("sensitive_information", t, c),
    "tool_manipulation": lambda t, c: _scan("tool_manipulation", t, c),
    "trust_boundary": lambda t, c: _scan("trust_boundary", t, c),
}


def run_detectors(text: AnalysisText, ctx: DetectionContext) -> list[Signal]:
    signals: list[Signal] = []
    for detector in DETECTORS.values():
        signals.extend(detector(text, ctx))
    return signals
