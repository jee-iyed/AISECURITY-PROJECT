from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import approvals, auth, chat, security
from app.core.config import GEMINI_API_KEY
from app.db.database import Base, SessionLocal, engine
from app.db.migrate import upgrade
from app.db.seed import seed


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    upgrade(engine, Base.metadata)
    with SessionLocal() as db:
        seed(db)
    yield


app = FastAPI(title="AI Security Gateway", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
for router in [auth.router, chat.router, security.router, approvals.router]:
    app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/status")
def status():
    return {"mode": "GEMINI" if GEMINI_API_KEY else "DEMO"}
