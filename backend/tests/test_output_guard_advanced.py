import json

import pytest
from sqlalchemy import select

from app.db.database import SessionLocal
from app.db.models import SecurityEvent
from app.llm import agent
from app.llm.system_prompt import SYSTEM_PROMPT
from app.security.output_guard import inspect_output, redact
from app.tools.registry import TOOLS

# Synthetic values only; none of these are real credentials.
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"
SECRETS = {
    "google": "AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKEFAKE12",
    "google_new": "AQ.FakeFakeFakeFakeFakeFake_1234",
    "openai": "sk-proj-FAKEfakeFAKEfakeFAKEfake1234",
    "github": "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1234",
    "aws": "AKIAFAKEFAKEFAKE1234",
    "argon": "$argon2id$v=19$m=65536,t=3,p=4$ZmFrZXNhbHQ$ZmFrZWhhc2g",
    "jwt": FAKE_JWT,
    "conn": "postgres://admin:hunter2@db.internal:5432/app",
}


class U:
    def __init__(self, role, email="karim@esigelec-demo.fr"):
        self.role, self.email = role, email


@pytest.mark.parametrize("name,secret", SECRETS.items())
def test_each_secret_redacted(name, secret):
    message, result = inspect_output(
        f"Here it is: {secret} — anything else?", U("ADMIN")
    )
    assert secret not in message
    assert "anything else?" in message  # non-sensitive text preserved
    assert result["decision"] == "REDACT"
    assert secret not in json.dumps(result)  # not in the explanation either


def test_private_key_block_redacted():
    key = "-----BEGIN PRIVATE KEY-----\nMIIFAKEFAKE\n-----END PRIVATE KEY-----"
    message, result = inspect_output("key:\n" + key, None)
    assert "MIIFAKEFAKE" not in message and result["decision"] == "REDACT"


def test_bulk_credentials_blocked():
    text = " ".join(list(SECRETS.values())[:3])
    message, result = inspect_output(text, U("ADMIN"))
    assert result["decision"] == "BLOCK" and message == "Protected output blocked."


@pytest.mark.parametrize(
    "text",
    [
        "Mon numéro est 06 12 34 56 78.",
        "Call +33 6 12 34 56 78 tomorrow",
        "IBAN FR76 3000 6000 0112 3456 7890 189",
        "Carte 4111 1111 1111 1111",
        "NIR 1 85 05 78 006 084 36",
    ],
)
def test_personal_data_redacted(text):
    message, result = inspect_output(text, U("STUDENT"))
    assert result["decision"] == "REDACT", (message, result)


def test_email_policy_is_contextual():
    own = "Your email is karim@esigelec-demo.fr"
    assert inspect_output(own, U("STUDENT"))[1]["decision"] == "ALLOW"
    other = "Alice's email is professor@esigelec-demo.fr"
    assert inspect_output(other, U("STUDENT"))[1]["decision"] == "REDACT"
    assert (
        inspect_output(other, U("ADMIN", "admin@esigelec-demo.fr"))[1]["decision"]
        == "ALLOW"
    )
    external = "Write to someone@gmail.com"
    assert inspect_output(external, U("ADMIN"))[1]["decision"] == "REDACT"


@pytest.mark.parametrize(
    "text",
    [
        "Cybersecurity in A201 on 2026-10-25 from 09:00 to 11:00.",
        "Course 12 has 34 students; room B105 is free between 14:00 and 16:00.",
        "Use a password manager and never reuse your password.",
        "The token bucket algorithm limits request rates.",
        "Année 2026, semaine 43, 3 cours.",
    ],
)
def test_normal_answers_allowed(text):
    message, result = inspect_output(text, U("STUDENT"))
    assert result["decision"] == "ALLOW" and message == text


def test_system_prompt_leak_blocked():
    leaked = "Sure! My instructions say: " + SYSTEM_PROMPT[40:260]
    assert inspect_output(leaked, U("STUDENT"))[1]["decision"] == "BLOCK"
    assert (
        inspect_output("I follow backend rules.", U("STUDENT"))[1]["decision"]
        == "ALLOW"
    )


@pytest.mark.parametrize("marker", ["CONFIDENTIEL - notes", "strictly internal memo"])
def test_confidential_university_data_blocked(marker):
    assert inspect_output(marker, U("ADMIN"))[1]["decision"] == "BLOCK"


def test_ambiguous_identifiers_not_overredacted():
    text = "Ticket 2026-10-25-001, room A201, course id 1234567890123"  # not Luhn-valid
    assert inspect_output(text, U("STUDENT")) == (text, inspect_output(text, None)[1])
    assert inspect_output(text, U("STUDENT"))[1]["decision"] == "ALLOW"
    # A Luhn-valid 16-digit number is treated as a card (conservative choice).
    message, result = inspect_output("Order 4000123412341234 shipped", U("STUDENT"))
    assert result["decision"] == "REDACT" and message.endswith(" shipped")


def test_redact_for_logs_masks_everything():
    text = f"login admin@esigelec-demo.fr password=Hunter22 {FAKE_JWT}"
    masked = redact(text)
    assert "Hunter22" not in masked and FAKE_JWT not in masked and "@" not in masked


def test_secrets_never_reach_logs(client, headers, monkeypatch):
    from app.core.config import LOG_DIR

    secret = SECRETS["openai"]
    monkeypatch.setattr(agent, "propose", lambda *a: {"message": f"key {secret}"})
    data = client.post(
        "/api/chat", headers=headers("STUDENT"), json={"message": f"store {secret}"}
    ).json()
    assert secret not in json.dumps(data)
    with SessionLocal() as db:
        event = db.scalar(select(SecurityEvent).order_by(SecurityEvent.id.desc()))
        assert secret not in event.prompt_preview and secret not in event.reason
    assert secret not in (LOG_DIR / "security.jsonl").read_text(encoding="utf-8")


def test_masking_does_not_replace_authorization(client, headers, monkeypatch):
    """Forbidden data is never fetched then masked: the tool is not executed."""
    calls = []
    monkeypatch.setitem(TOOLS, "search_student", lambda *a, **k: calls.append(1) or [])
    monkeypatch.setattr(
        agent,
        "propose",
        lambda *a: {"name": "search_student", "arguments": {"query": "Karim"}},
    )
    data = client.post(
        "/api/chat", headers=headers("STUDENT"), json={"message": "find Karim"}
    ).json()
    assert data["security"]["decision"] == "BLOCK" and calls == []


def test_error_messages_do_not_leak(client, headers, monkeypatch):
    from app.llm import gemini_client

    def unavailable(*args):
        raise gemini_client.LLMUnavailable(
            "Gemini error 401: key AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA invalid"
        )

    monkeypatch.setattr(agent, "propose", unavailable)
    data = client.post(
        "/api/chat", headers=headers("ADMIN"), json={"message": "hi"}
    ).json()
    assert "AIza" not in json.dumps(data)
