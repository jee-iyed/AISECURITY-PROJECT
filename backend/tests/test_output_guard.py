from app.security.output_guard import inspect_output
from app.security.risk_engine import assessment


def test_secrets():
    message, result = inspect_output(
        "password=demo-secret token=abc123 email: alice@example.com", None
    )
    assert (
        "demo-secret" not in message
        and "abc123" not in message
        and "alice@example.com" not in message
    )
    assert result["decision"] == "REDACT"


def test_confidential():
    assert (
        inspect_output("CONFIDENTIAL private_professor details", None)[1]["decision"]
        == "BLOCK"
    )


def test_normal():
    assert inspect_output("Course at 09:00 in A201", None)[1]["decision"] == "ALLOW"


def test_risk_boundaries():
    assert assessment(score=85)["risk_level"] == "CRITICAL"
    assert assessment(score=60)["risk_level"] == "HIGH"
    assert assessment(score=30)["risk_level"] == "MEDIUM"
    assert assessment(score=-5)["risk_score"] == 0
