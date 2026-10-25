"""Centralized, deterministic risk engine.

The engine combines detector signals with execution context into a bounded
0-100 score, then applies a *policy* whose mandatory rules take precedence over
the score. See docs/risk-model.md for the rationale behind every weight.

Score model (all inputs in [0, 1]):

    strength_i  = threat_weight[threat_i] * confidence_i
    detection   = 1 - prod(1 - max strength per detector)        # noisy-OR
    impact      = max(tool, resource, potential impact levels)
    threat      = detection * (0.8 + 0.2 * impact) * source_trust_factor
    action      = action_weight * impact                         # inherent risk
    score       = 100 * min(1, max(threat, action)) + history_bonus

Noisy-OR guarantees the aggregate is never below the strongest signal (no
dilution by averaging) while independent corroborating detectors raise it
without the linear sum saturating at 100. Taking the max per detector stops a
single detector from inflating the score with near-duplicate matches.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

IMPACT_LEVELS = MappingProxyType(
    {"NONE": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
)


@dataclass(frozen=True)
class RiskPolicy:
    # Severity of a threat category if the signal is certain (confidence 1).
    threat_weights: Mapping[str, float] = field(
        default_factory=lambda: MappingProxyType(
            {
                "TOOL_ABUSE": 0.95,
                "UNAUTHORIZED_ACTION": 0.95,
                "TOOL_MANIPULATION": 0.9,
                "ROLE_MANIPULATION": 0.9,
                "INDIRECT_PROMPT_INJECTION": 0.9,
                "PROMPT_INJECTION": 0.85,
                "INFORMATION_LEAKAGE": 0.85,
                "INVALID_ARGUMENTS": 0.85,
                "JAILBREAK": 0.85,
                "SENSITIVE_ACTION": 0.4,
                "OBFUSCATION": 0.4,
            }
        )
    )
    default_threat_weight: float = 0.6
    # Multiplier for where the analysed text came from.
    source_trust_factors: Mapping[str, float] = field(
        default_factory=lambda: MappingProxyType(
            {
                "system": 0.5,
                "user_prompt": 1.0,
                "model_output": 1.0,
                "tool_result": 1.1,
                "database": 1.1,
                "document": 1.15,
                "external": 1.15,
            }
        )
    )
    default_impact: str = "MEDIUM"
    action_weight: float = 0.45
    history_step: int = 3
    history_cap: int = 10
    block_threshold: int = 60
    monitor_threshold: int = 30


DEFAULT_POLICY = RiskPolicy()


def severity(score: int) -> str:
    return (
        "CRITICAL"
        if score >= 85
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 30
        else "LOW"
    )


def _signal_field(signal, name, default=None):
    return signal.get(name, default) if isinstance(signal, Mapping) else getattr(
        signal, name, default
    )


def _impact(*levels: str | None, policy: RiskPolicy) -> float:
    known = [IMPACT_LEVELS[level] for level in levels if level in IMPACT_LEVELS]
    return max(known) if known else IMPACT_LEVELS[policy.default_impact]


def calculate_risk(
    detection_signals: Iterable = (),
    source_trust: str = "user_prompt",
    tool_sensitivity: str | None = None,
    resource_sensitivity: str | None = None,
    potential_impact: str | None = None,
    recent_blocks: int = 0,
    policy: RiskPolicy = DEFAULT_POLICY,
) -> tuple[int, dict]:
    """Return ``(score, breakdown)``. Pure and deterministic."""
    best: dict[str, float] = {}
    for signal in detection_signals:
        if not _signal_field(signal, "matched", True):
            continue
        threat = _signal_field(signal, "threat")
        weight = policy.threat_weights.get(threat, policy.default_threat_weight)
        confidence = min(1.0, max(0.0, float(_signal_field(signal, "confidence", 0))))
        detector = _signal_field(signal, "detector", threat)
        best[detector] = max(best.get(detector, 0.0), weight * confidence)
    remaining = 1.0
    for strength in best.values():
        remaining *= 1 - strength
    detection = 1 - remaining
    impact = _impact(
        tool_sensitivity, resource_sensitivity, potential_impact, policy=policy
    )
    trust = policy.source_trust_factors.get(source_trust, 1.0)
    threat_component = detection * (0.8 + 0.2 * impact) * trust
    explicit_impact = any(
        level in IMPACT_LEVELS
        for level in (tool_sensitivity, resource_sensitivity, potential_impact)
    )
    action_component = policy.action_weight * impact if explicit_impact else 0.0
    history = (
        min(policy.history_cap, policy.history_step * max(0, recent_blocks))
        if detection > 0
        else 0
    )
    raw = 100 * min(1.0, max(threat_component, action_component)) + history
    score = int(round(min(100.0, max(0.0, raw))))
    return score, {
        "detection": round(detection, 4),
        "impact": impact,
        "source_trust_factor": trust,
        "threat_component": round(threat_component, 4),
        "action_component": round(action_component, 4),
        "history_bonus": history,
    }


def evaluate(
    signals: Iterable = (),
    *,
    source_trust: str = "user_prompt",
    tool_sensitivity: str | None = None,
    resource_sensitivity: str | None = None,
    potential_impact: str | None = None,
    recent_blocks: int = 0,
    authorization_denied: bool = False,
    invalid_arguments: bool = False,
    requires_approval: bool = False,
    mandatory_block: bool = False,
    mandatory_redact: bool = False,
    reason: str | None = None,
    threat: str | None = None,
    deny_rule: str = "DENY_UNAUTHORIZED_ACTION",
    policy: RiskPolicy = DEFAULT_POLICY,
) -> dict:
    """Score the signals, then apply mandatory rules in priority order.

    Mandatory rules (authorization, validation, approval, secret protection)
    decide regardless of the numeric score; the score can only make a decision
    stricter, never relax a mandatory rule.
    """
    signals = [s for s in signals if _signal_field(s, "matched", True)]
    for flag, kind, confidence in [
        (authorization_denied, "UNAUTHORIZED_ACTION", 1.0),
        (invalid_arguments, "INVALID_ARGUMENTS", 0.7),
    ]:
        if flag:
            # A deterministic control outcome is itself evidence of risk.
            signals.append(
                {
                    "detector": "policy",
                    "threat": threat or kind,
                    "matched": True,
                    "confidence": confidence,
                    "evidence": reason or kind.lower().replace("_", " "),
                    "source": "policy",
                }
            )
    score, breakdown = calculate_risk(
        signals,
        source_trust,
        tool_sensitivity,
        resource_sensitivity,
        potential_impact,
        recent_blocks,
        policy,
    )
    ranked = sorted(
        signals,
        key=lambda s: (
            -policy.threat_weights.get(
                _signal_field(s, "threat"), policy.default_threat_weight
            )
            * float(_signal_field(s, "confidence", 0)),
            _signal_field(s, "detector", ""),
        ),
    )
    threats = list(dict.fromkeys(_signal_field(s, "threat") for s in ranked))
    if len(threats) > 1 and threats[0] == "OBFUSCATION":
        threats.append(threats.pop(0))  # Obfuscation is a modifier, not a goal.
    if threat and threat not in threats:
        threats.insert(0, threat)
    primary = threat or (threats[0] if threats else None)

    if authorization_denied:
        decision, rule = "BLOCK", deny_rule
    elif invalid_arguments:
        decision, rule = "BLOCK", "DENY_INVALID_ARGUMENTS"
    elif mandatory_block:
        decision, rule = "BLOCK", "BLOCK_PROTECTED_DATA"
    elif score >= policy.block_threshold:
        decision, rule = "BLOCK", "BLOCK_HIGH_RISK_SCORE"
    elif requires_approval:
        decision, rule = "REQUIRE_APPROVAL", "REQUIRE_HUMAN_APPROVAL"
    elif mandatory_redact:
        decision, rule = "REDACT", "REDACT_SENSITIVE_DATA"
    elif score >= policy.monitor_threshold and threats:
        decision, rule = "ALLOW", "ALLOW_WITH_MONITORING"
    else:
        decision, rule = "ALLOW", "ALLOW_DEFAULT"

    if reason is None:
        if ranked and decision != "ALLOW":
            reason = str(_signal_field(ranked[0], "evidence", "")).capitalize() + "."
        elif ranked:
            reason = "Low-confidence signals recorded; request allowed."
        else:
            reason = "Request passed deterministic controls."
    level = severity(score)
    return {
        "threat_detected": primary is not None,
        "threat_type": primary,
        "threats": threats,
        "risk_score": score,
        "risk_level": level,
        "severity": level,
        "decision": decision,
        "reason": reason,
        "policy_rules": [rule],
        "signals": [
            s.to_dict() if hasattr(s, "to_dict") else dict(s) for s in ranked
        ],
        "score_breakdown": breakdown,
    }


def assessment(
    threat=None,
    score=10,
    reason="Request passed deterministic controls.",
    decision=None,
):
    """Legacy fixed-score assessment, kept for simple non-detector outcomes."""
    score = max(0, min(100, score))
    level = severity(score)
    decision = decision or ("BLOCK" if score >= 60 else "ALLOW")
    return {
        "threat_detected": threat is not None,
        "threat_type": threat,
        "threats": [threat] if threat else [],
        "risk_score": score,
        "risk_level": level,
        "severity": level,
        "decision": decision,
        "reason": reason,
        "policy_rules": [],
        "signals": [],
    }
