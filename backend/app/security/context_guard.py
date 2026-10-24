from app.security.input_guard import analyze_input
from app.security.risk_engine import assessment


def analyze_context(content):
    if analyze_input(content)["threat_detected"]:
        return assessment(
            "INDIRECT_PROMPT_INJECTION",
            80,
            "Untrusted source contains instructions targeting the assistant.",
        )
    return assessment(reason="External content inspected; it remains untrusted data.")
