def assessment(
    threat=None,
    score=10,
    reason="Request passed deterministic controls.",
    decision=None,
):
    score = max(0, min(100, score))
    level = (
        "CRITICAL"
        if score >= 85
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 30
        else "LOW"
    )
    return {
        "threat_detected": threat is not None,
        "threat_type": threat,
        "risk_score": score,
        "risk_level": level,
        "decision": decision or ("BLOCK" if score >= 60 else "ALLOW"),
        "reason": reason,
    }
