"""Security-oriented text normalization.

The original text is never modified: callers keep it for audit purposes. This
module only derives *analysis views* used for pattern matching:

- ``normalized``: NFKC, invisible/format characters removed, control characters
  removed, homoglyphs mapped to Latin, casefolded, diacritics stripped,
  unusual whitespace collapsed.
- ``deleet``: leetspeak tokens mapped back to letters (``1gn0r3`` -> ``ignore``).
- ``collapsed``: runs of single letters joined (``i.g.n.o.r.e`` -> ``ignore``).
- ``decoded:*``: bounded decoding of base64, hex, percent-encoding and ROT13.

Transformations are deliberately lossy *only* in the analysis views so that
legitimate text is never altered in what the user or the model sees.
"""

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Resource limits: analysis cost stays linear and bounded for hostile inputs.
MAX_ANALYSIS_CHARS = 20_000
MAX_DECODED_SEGMENTS = 5
MAX_DECODE_DEPTH = 2
MAX_SEGMENT_CHARS = 4_096

# Cyrillic and Greek letters that render like Latin letters.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "ո": "n", "ԛ": "q", "ԝ": "w", "ν": "v", "α": "a", "ε": "e", "ι": "i",
    "ο": "o", "ρ": "p", "υ": "u", "κ": "k", "τ": "t", "χ": "x",
}  # fmt: skip
# Typographic quotes map to ASCII so quotation analysis sees one form.
PUNCTUATION = {"’": "'", "‘": "'", "ʼ": "'", "“": '"', "”": '"',
               "«": '"', "»": '"', "„": '"'}  # fmt: skip
_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS | PUNCTUATION)
_LEET_TABLE = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_LEET_TOKEN = re.compile(r"[a-z0-9@$]+")
# "i.g.n.o.r.e" (punctuation separators keep word boundaries) and
# "i g n o r e" (spaced letters; word boundaries are lost, see "squeezed").
_SEPARATED_RUN = re.compile(r"(?<![a-z])(?:[a-z][.\-_*/\\|+~,]{1,3}){2,}[a-z](?![a-z])")
_SPACED_RUN = re.compile(r"(?<![a-z])(?:[a-z] ){3,}[a-z](?![a-z])")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:\\x)?(?:[0-9a-fA-F]{2}(?:\\x|\s)?){8,}")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_SPACES = re.compile(r"[ \t\f\v]+")


@dataclass
class AnalysisText:
    original: str
    normalized: str
    views: dict[str, str] = field(default_factory=dict)
    flags: dict[str, int] = field(default_factory=dict)


def _strip_diacritics(text: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)
    )


def _clean(text: str, flags: dict[str, int]) -> str:
    """Remove invisible and control characters, counting suspicious ones."""
    out = []
    for i, c in enumerate(text):
        category = unicodedata.category(c)
        if category == "Cf":
            prev_ok = i > 0 and text[i - 1].isalnum()
            next_ok = i + 1 < len(text) and text[i + 1].isalnum()
            flags["invisible_chars"] += 1
            if prev_ok and next_ok:
                flags["invisible_in_word"] += 1
            continue
        if category == "Cc" and c not in "\n\t\r":
            flags["control_chars"] += 1
            continue
        if category == "Zs" and c != " ":
            flags["unusual_spaces"] += 1
            c = " "
        out.append(c)
    return "".join(out)


def _count_mixed_script(text: str) -> int:
    count = 0
    for token in re.findall(r"\w+", text):
        has_latin = any("a" <= c.lower() <= "z" for c in token)
        if has_latin and any(c in HOMOGLYPHS for c in token):
            count += 1
    return count


def _deleet(text: str, flags: dict[str, int]) -> str:
    def repl(match):
        token = match.group(0)
        mapped = token.translate(_LEET_TABLE)
        letters = sum(c.isalpha() for c in token)
        if mapped != token and mapped.isalpha() and letters >= 3:
            flags["leet_tokens"] += 1
            return mapped
        return token

    return _LEET_TOKEN.sub(repl, text)


def _collapse(text: str, flags: dict[str, int]) -> str:
    def repl(match):
        flags["separator_runs"] += 1
        return re.sub(r"[^a-z]", "", match.group(0))

    return _SPACED_RUN.sub(repl, _SEPARATED_RUN.sub(repl, text))


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isprintable() or c in "\n\t" for c in text) / len(text)


def _try_text(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    letters = sum(c.isalpha() for c in decoded)
    if _printable_ratio(decoded) < 0.9 or letters < max(4, len(decoded) // 3):
        return None
    return decoded


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in _BASE64.finditer(text):
        token = match.group(0)[:MAX_SEGMENT_CHARS]
        if token.isalpha() and (token.islower() or token.isupper()):
            continue  # Plain words, not encodings.
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _try_text(decoder(padded))
            except (binascii.Error, ValueError):
                continue
            if decoded:
                found.append(("base64", decoded))
                break
    for match in _HEX.finditer(text):
        digits = re.sub(r"\\x|\s", "", match.group(0))[:MAX_SEGMENT_CHARS]
        if digits.isdigit():
            continue  # Phone numbers and IDs, not encodings.
        try:
            decoded = _try_text(bytes.fromhex(digits))
        except ValueError:
            decoded = None
        if decoded:
            found.append(("hex", decoded))
    for match in _PERCENT.finditer(text):
        decoded = urllib.parse.unquote(match.group(0)[:MAX_SEGMENT_CHARS])
        if _try_text(decoded.encode("utf-8", "ignore")):
            found.append(("percent", decoded))
    if re.search(r"\brot[\s-]?13\b", text, re.IGNORECASE):
        found.append(("rot13", codecs.decode(text[:MAX_SEGMENT_CHARS], "rot13")))
    return found


def basic_normalize(text: str, flags: dict[str, int] | None = None) -> str:
    flags = flags if flags is not None else _new_flags()
    cleaned = _clean(unicodedata.normalize("NFKC", text), flags)
    flags["homoglyphs"] += _count_mixed_script(cleaned)
    mapped = _strip_diacritics(cleaned.translate(_HOMOGLYPH_TABLE).casefold())
    lines = [_SPACES.sub(" ", line).strip() for line in mapped.splitlines()]
    return "\n".join(line for line in lines if line)


def _new_flags() -> dict[str, int]:
    return dict.fromkeys(
        [
            "invisible_chars",
            "invisible_in_word",
            "control_chars",
            "unusual_spaces",
            "homoglyphs",
            "leet_tokens",
            "separator_runs",
            "decoded_segments",
            "truncated",
        ],
        0,
    )


def prepare(text: str | None) -> AnalysisText:
    original = text or ""
    flags = _new_flags()
    if len(original) > MAX_ANALYSIS_CHARS:
        flags["truncated"] = 1
    bounded = original[:MAX_ANALYSIS_CHARS]
    normalized = basic_normalize(bounded, flags)
    views = {"normalized": normalized}
    deleet = _deleet(normalized, flags)
    if deleet != normalized:
        views["deleet"] = deleet
    collapsed = _collapse(deleet, flags)
    if collapsed != deleet:
        views["collapsed"] = collapsed
    if flags["separator_runs"] or flags["invisible_in_word"]:
        # Letters only: defeats arbitrary separators at the cost of word
        # boundaries, so only compact signatures are matched against it.
        views["squeezed"] = re.sub(r"[^a-z]", "", collapsed)

    pending = [(bounded, 0)]
    while pending and flags["decoded_segments"] < MAX_DECODED_SEGMENTS:
        source, depth = pending.pop(0)
        if depth >= MAX_DECODE_DEPTH:
            continue
        for kind, decoded in _decode_candidates(source):
            if flags["decoded_segments"] >= MAX_DECODED_SEGMENTS:
                break
            flags["decoded_segments"] += 1
            views[f"decoded:{kind}#{flags['decoded_segments']}"] = basic_normalize(
                decoded, _new_flags()
            )
            pending.append((decoded, depth + 1))
    return AnalysisText(original=original, normalized=normalized, views=views, flags=flags)
