import re

from app.llm.agent import normalize
from app.security.detection import DetectionContext, prepare, run_detectors
from app.security.risk_engine import assessment, evaluate

# Below this many characters there is nothing meaningful to analyse.
MIN_ANALYSIS_CHARS = 1


def analyze_input(prompt, user_context=None, source="user_prompt", recent_blocks=0):
    """Multilayer, deterministic analysis of text entering the agent.

    Pipeline: secure normalization -> eight complementary detectors (with
    mention-versus-use framing) -> centralized risk engine. No LLM call is made,
    so the guard keeps working when Gemini is unavailable.
    """
    text = prepare(prompt)
    if len(text.normalized) < MIN_ANALYSIS_CHARS:
        result = assessment(reason="Empty input; nothing to analyse.")
        result["normalization"] = text.flags
        return result
    role = getattr(user_context, "role", None)
    signals = run_detectors(text, DetectionContext(source=source, role=role))
    result = evaluate(signals, source_trust=source, recent_blocks=recent_blocks)
    result["normalization"] = {k: v for k, v in text.flags.items() if v}
    return result


def analyze_unfulfilled_action(prompt, user):
    # A model refusal is text, so no function call reaches Tool Guard. Preserve
    # an explicit BLOCK for clear unauthorized schedule-write requests as well.
    if user.role != "ADMIN" and re.search(
        r"\b(change|modifie|deplace|update|move)\b.{0,100}\b(salle|room|cours|course|schedule|emploi)\b",
        normalize(prompt),
    ):
        return evaluate(
            authorization_denied=True,
            threat="TOOL_ABUSE",
            reason="Authenticated role cannot modify schedules.",
            potential_impact="HIGH",
        )
    return assessment()
