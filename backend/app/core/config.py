import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
DATA = Path(os.getenv("DATA_DIR", "data"))
DATA.mkdir(parents=True, exist_ok=True)
secret_path = DATA / ".jwt-secret"
if not os.getenv("JWT_SECRET") and not secret_path.exists():
    secret_path.write_text(secrets.token_urlsafe(48))
JWT_SECRET = os.getenv("JWT_SECRET") or secret_path.read_text().strip()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/ai_security_gateway.db")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
# Tried in order when the primary model is overloaded (503/5xx/timeout).
GEMINI_FALLBACK_MODELS = [
    m.strip()
    for m in os.getenv(
        "GEMINI_FALLBACK_MODELS",
        "gemini-3.5-flash-lite,gemini-flash-lite-latest,gemini-3.8-flash",
    ).split(",")
    if m.strip()
]
DEMO_DATA = Path(os.getenv("DEMO_DATA_DIR", "../demo-data"))
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
# Human approval: pending requests expire; separation of duties is optional
# because the demo seeds a single administrator.
APPROVAL_TTL_MINUTES = int(os.getenv("APPROVAL_TTL_MINUTES", "30"))
REQUIRE_DISTINCT_APPROVER = (
    os.getenv("REQUIRE_DISTINCT_APPROVER", "false").lower() == "true"
)
GEMINI_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "20"))
# After a provider failure, AI incident analysis is skipped for this long
# instead of retrying (no call loops, quota preserved).
ANALYSIS_COOLDOWN_SECONDS = int(os.getenv("ANALYSIS_COOLDOWN_SECONDS", "60"))
# Keep the fictional demo timetable covering the next 7 days (additive only).
DEMO_SCHEDULE_REFRESH = os.getenv("DEMO_SCHEDULE_REFRESH", "true").lower() == "true"
