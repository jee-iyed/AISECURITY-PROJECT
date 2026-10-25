from sqlalchemy import create_engine, inspect, text

from app.db.database import Base
from app.db.migrate import upgrade


def test_upgrade_adds_missing_nullable_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE security_events (id INTEGER PRIMARY KEY, timestamp TEXT,"
                " user_id INTEGER, user_name TEXT, role TEXT, prompt_preview TEXT,"
                " threat_type TEXT, risk_score INTEGER, risk_level TEXT, decision TEXT,"
                " tool_name TEXT, reason TEXT)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO security_events VALUES (1, 't', 1, 'u', 'STUDENT', 'p',"
                " NULL, 10, 'LOW', 'ALLOW', NULL, 'r')"
            )
        )
    upgrade(engine, Base.metadata)
    upgrade(engine, Base.metadata)  # idempotent
    columns = {c["name"] for c in inspect(engine).get_columns("security_events")}
    assert {"correlation_id", "policy_rules", "signals", "approval_id"} <= columns
    with engine.connect() as conn:
        assert conn.execute(text("SELECT reason FROM security_events")).scalar() == "r"
