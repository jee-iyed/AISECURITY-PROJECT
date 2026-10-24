# Detection and Risk Model

This document explains how the gateway turns text and execution context into a
decision. Every number below is a **heuristic design choice**, not a
statistically calibrated probability. The benchmark (`docs/benchmark.md`)
measures the actual error rates these choices produce on a labelled dataset.

## 1. Pipeline

```
text ──► normalizer ──► 8 detectors ──► signals ──► risk engine ──► decision
            (views)       (+ framing)                 (score + policy)
```

No LLM is called. The guard keeps working when Gemini is unavailable.

## 2. Normalization (`app/security/detection/normalizer.py`)

The original text is kept untouched for audit. Analysis runs on derived views:

| View | Built when | Purpose |
|---|---|---|
| `normalized` | always | NFKC, `Cf` format chars and `Cc` control chars removed, homoglyphs → Latin, typographic quotes → ASCII, casefold, diacritics stripped, whitespace collapsed |
| `deleet` | a token mixes letters and leet digits | `1gn0r3` → `ignore` (only if the result is purely alphabetic and has ≥ 3 letters, so `A201` is untouched) |
| `collapsed` | separator runs found | `i.g.n.o.r.e` → `ignore`, `i g n o r e` → `ignore` |
| `squeezed` | separator or in-word invisible chars found | letters only; matched against a short list of compact signatures |
| `decoded:*` | base64 / hex / percent / ROT13 segment decodes to text | bounded recursive decoding |

Resource limits: 20,000 characters analysed, ≤ 5 decoded segments, depth ≤ 2,
4,096 characters per segment. The chat API already caps prompts at 4,000.

## 3. Detectors (`app/security/detection/detectors.py`, `lexicon.py`)

| Detector | Threat type reported | Examples |
|---|---|---|
| `signature` | PROMPT_INJECTION | DAN, chat-template tokens, path/SQL/shell payloads |
| `obfuscation` | OBFUSCATION | invisible chars in words, mixed-script tokens, decoded payloads |
| `instruction_override` | PROMPT_INJECTION | "ignore previous instructions", hierarchy claims |
| `role_manipulation` | ROLE_MANIPULATION | "je suis administrateur", "grant me admin" |
| `jailbreak` | JAILBREAK | "disable safety filters", "sans règles" |
| `sensitive_information` | INFORMATION_LEAKAGE | system prompt extraction, credentials, private data |
| `tool_manipulation` | TOOL_MANIPULATION | "without approval", injected `{"name": "update_schedule"}` |
| `trust_boundary` | PROMPT_INJECTION | "SYSTEM:", "note to the AI", forged delimiters |

When the text comes from an untrusted source (document, tool result), every
instruction-type detector reports `INDIRECT_PROMPT_INJECTION` instead.

Each pattern has a *confidence* in [0.5, 0.95] reflecting how rarely its
wording appears in benign text, as judged by the authors.

Languages: French and English. Adding a language means adding a key under each
category in `LEXICON`; no code change.

### Mention versus use (`framing.py`)

A matched span is attenuated (confidence × factor) when it is:

| Framing | Factor |
|---|---|
| quoted **and** introduced by a reference ("la phrase", "such as") or a question | 0.30 |
| introduced by a referential noun | 0.35 |
| inside a definitional question, not addressed to the assistant | 0.40 |
| educational context word (pédagogique, training, detect…) | 0.60 |
| quoted only | 0.70 |

Attenuation is cancelled when the text asks the assistant to act on the quoted
content ("…now do it"), when the match is addressed to the assistant (*your*,
*tes*), or when it follows a conjunction ("explain X **and** ignore your rules").
French elisions (`l'`, `qu'`) are not treated as quotation marks. Matches that
only appear after de-obfuscation are never attenuated.

A claimed role equal to the authenticated role ("I am a professor" from a
professor) is attenuated × 0.2.

## 4. Score (`app/security/risk_engine.py`)

```
strength_i  = threat_weight[threat_i] × confidence_i
detection   = 1 − Π_d (1 − max_i∈d strength_i)          (noisy-OR over detectors)
impact      = max(tool, resource, potential impact)      NONE 0 … CRITICAL 1, default MEDIUM 0.5
threat      = detection × (0.8 + 0.2 × impact) × source_trust_factor
action      = 0.45 × impact                              (only when an impact is supplied)
score       = round(100 × min(1, max(threat, action))) + history_bonus,  clamped to [0, 100]
```

* **Noisy-OR**: the aggregate is never below the strongest signal (a critical
  signal cannot be diluted by an average) and corroboration from independent
  detectors raises it without the linear sum reaching 100 for every attack.
* **Max per detector**: near-duplicate patterns in one detector do not stack.
* **Source trust**: system 0.5, user prompt / model output 1.0, tool result /
  database 1.1, document / external 1.15.
* **History**: +3 per recent BLOCK by the same user (cap +10), applied only when
  the current request already carries a signal, so benign users are never
  penalised.

Threat weights: TOOL_ABUSE / UNAUTHORIZED_ACTION 0.95; TOOL_MANIPULATION,
ROLE_MANIPULATION, INDIRECT_PROMPT_INJECTION 0.9; PROMPT_INJECTION,
INFORMATION_LEAKAGE, JAILBREAK, INVALID_ARGUMENTS 0.85; SENSITIVE_ACTION and
OBFUSCATION 0.4 (obfuscation alone is not an attack). Rationale: categories
that directly target privileges or tool execution rank above those that target
model behaviour.

Severity bands are unchanged from the original prototype: LOW < 30 ≤ MEDIUM
< 60 ≤ HIGH < 85 ≤ CRITICAL.

## 5. Decision policy

Mandatory rules are evaluated first; the score can only make a decision
stricter.

| Priority | Condition | Decision | Rule |
|---|---|---|---|
| 1 | RBAC or resource authorization denied | BLOCK | `DENY_UNAUTHORIZED_ACTION` |
| 2 | tool arguments invalid | BLOCK | `DENY_INVALID_ARGUMENTS` |
| 3 | protected data that must never be shown | BLOCK | `BLOCK_PROTECTED_DATA` |
| 4 | score ≥ 60 | BLOCK | `BLOCK_HIGH_RISK_SCORE` |
| 5 | sensitive operation | REQUIRE_APPROVAL | `REQUIRE_HUMAN_APPROVAL` |
| 6 | secret / personal data that can be masked | REDACT | `REDACT_SENSITIVE_DATA` |
| 7 | score ≥ 30 with a signal | ALLOW (logged) | `ALLOW_WITH_MONITORING` |
| 8 | otherwise | ALLOW | `ALLOW_DEFAULT` |

A denied authorization adds a deterministic `policy` signal (confidence 1.0)
so the reported score reflects the attempt, but the decision would be BLOCK
even with `block_threshold = 101` (see `tests/test_risk_engine.py`).

All weights live in the frozen `RiskPolicy` dataclass and can be overridden
for experiments without code changes.

## 6. Known limitations

* Pattern-based: novel phrasings, other languages and semantic paraphrases
  without trigger words are missed. The benchmark reports these misses.
* Framing analysis is shallow (clause splitting and local cues); a skilled
  attacker can craft text that is attenuated.
* Text beyond 20,000 characters is not analysed (flagged `truncated`).
* Confidences and weights are not fitted to data.

Detection is defense in depth. Authorization (RBAC, resource ownership,
approval) never depends on it.
