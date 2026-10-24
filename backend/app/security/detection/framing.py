"""Mention-versus-use analysis.

A security course legitimately *mentions* attack strings ("why is 'ignore
previous instructions' dangerous?"). An attacker *uses* them as directives.
This module returns a multiplicative attenuation factor for a matched span
based on its local syntactic framing. It is not a phrase allowlist: the
attenuation depends on where the match sits (quoted, introduced by a
referential noun, inside a definitional question) and is cancelled when the
text also asks the assistant to act on the quoted content, when the match is
addressed to the assistant (second person), or when it follows a coordinating
conjunction ("explain X and ignore your rules").
"""

import re

# Factors are heuristic and documented in docs/risk-model.md.
QUOTED_AND_FRAMED = 0.3
REFERENTIAL = 0.35
QUESTION_FRAME = 0.4
QUOTED_ONLY = 0.7
EDUCATIONAL_CONTEXT = 0.6

_CLAUSE_SPLIT = re.compile(
    r"[.!?;\n]+|\b(?:puis|ensuite|then|and then|after that|apres ca|et ensuite)\b"
)
# Single quotes only count at word boundaries so French elisions (l', qu')
# cannot be abused to make an instruction look quoted.
_QUOTES = re.compile(r"\"[^\"]{1,300}\"|(?<![a-z])'[^']{3,300}'(?![a-z])|`[^`]{1,300}`")
_REFERENTIAL = re.compile(
    r"\b(the phrase|the sentence|the string|the text|the prompt|the instruction|the words"
    r"|phrases? like|such as|like|for example|e\.g\.|example of|examples of|called"
    r"|known as|la phrase|cette phrase|le texte|la chaine|le prompt|l'instruction"
    r"|les mots|comme|par exemple|exemple de|exemples de|appelee?s?|dite?s?"
    r"|du type|de type)\W{0,3}$"
)
_QUESTION_START = re.compile(
    r"^\W*(what|why|how|when|which|is|are|does|do|can|explain|describe|define"
    r"|give an example|show an example|qu'?est-ce|c'?est quoi|pourquoi|comment|quand"
    r"|quel|quelle|est-ce|explique\w*|decri\w*|defini\w*|donne un exemple"
    r"|donne-moi un exemple)\b"
)
_EDUCATIONAL = re.compile(
    # "course"/"cours" are deliberately absent: every request mentions courses
    # in a university assistant, so they carry no educational intent.
    r"\b(pedagogi\w*|educati\w*|lesson|training|formation|research"
    r"|recherche|exercise|exercice|homework|thesis|memoire|detect\w*"
    r"|prevent\w*|preven\w*|protect\w*|defend\w*|defens\w*|mitigat\w*|attenu\w*)\b"
)
_ADDRESSED = re.compile(
    r"\b(you|your|yours|yourself|tu|toi|ton|ta|tes|te|t'|vous|votre|vos)\b"
)
_CONJUNCTION_BEFORE = re.compile(r"\b(and|et|but|mais|also|aussi|now|maintenant)\W*$")
_EXECUTION_DIRECTIVE = re.compile(
    r"\b(do it|apply it|execute it|follow it|obey it|comply|do what it says"
    r"|follow (these|those|this|the) instructions?|act on it|appliquez?-la|applique-le"
    r"|execute-la|execute-le|suis-la|suis-les|obeis|fais ce qu'?(elle|il) dit"
    r"|applique cette instruction|execute cette instruction)\b"
)


def _clause_bounds(text: str, start: int) -> tuple[int, int]:
    begin, end = 0, len(text)
    for m in _CLAUSE_SPLIT.finditer(text):
        if m.end() <= start:
            begin = m.end()
        elif m.start() >= start:
            end = m.start()
            break
    return begin, end


def _inside_quotes(text: str, start: int, end: int) -> bool:
    return any(q.start() <= start and end <= q.end() for q in _QUOTES.finditer(text))


def framing_factor(text: str, start: int, end: int) -> tuple[float, str]:
    """Return (factor, label) for the span ``text[start:end]``.

    ``text`` must be the normalized analysis view.
    """
    if _EXECUTION_DIRECTIVE.search(text):
        return 1.0, "execution directive present"
    quoted = _inside_quotes(text, start, end)
    begin, clause_end = _clause_bounds(text, start)
    clause = text[begin:clause_end]
    before = text[begin:start]
    addressed = bool(_ADDRESSED.search(text[start:end]))
    referential = bool(_REFERENTIAL.search(before[-40:]))
    after_conjunction = bool(_CONJUNCTION_BEFORE.search(before))
    question = bool(_QUESTION_START.search(clause)) and not after_conjunction

    if quoted and (referential or question):
        return QUOTED_AND_FRAMED, "quoted and discussed"
    if referential and not after_conjunction:
        return REFERENTIAL, "referenced as an example"
    if question and not addressed:
        return QUESTION_FRAME, "definitional question"
    if quoted:
        return QUOTED_ONLY, "quoted"
    if _EDUCATIONAL.search(clause) and not addressed and not after_conjunction:
        return EDUCATIONAL_CONTEXT, "educational context"
    return 1.0, "direct"
