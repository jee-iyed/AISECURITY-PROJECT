from app.core.config import DEMO_DATA
from app.security.context_guard import analyze_context


def test_malicious_context():
    result = analyze_context((DEMO_DATA / "malicious_note.txt").read_text())
    assert (
        result["threat_type"] == "INDIRECT_PROMPT_INJECTION"
        and result["decision"] == "BLOCK"
    )


def test_normal_context():
    assert (
        analyze_context((DEMO_DATA / "normal_note.txt").read_text())["decision"]
        == "ALLOW"
    )
