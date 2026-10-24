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
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
DEMO_DATA = Path(os.getenv("DEMO_DATA_DIR", "../demo-data"))
LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
