import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import approvals, auth, chat, security
from app.core import rate_limit
from app.core.config import GEMINI_API_KEY, JWT_SECRET
from app.db.database import Base, SessionLocal, engine
from app.db.migrate import upgrade
from app.db.seed import seed

log = logging.getLogger("gateway")
# Interactive API docs stay on for the local academic demo; set
# EXPOSE_DOCS=false for any shared deployment.
EXPOSE_DOCS = os.getenv("EXPOSE_DOCS", "true").lower() == "true"
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@asynccontextmanager
async def lifespan(app):
    if len(JWT_SECRET) < 32:
        log.warning("JWT_SECRET is shorter than 32 characters; use a longer secret.")
    Base.metadata.create_all(engine)
    upgrade(engine, Base.metadata)
    with SessionLocal() as db:
        seed(db)
    yield


app = FastAPI(
    title="AI Security Gateway",
    lifespan=lifespan,
    docs_url="/docs" if EXPOSE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if EXPOSE_DOCS else None,
)


@app.middleware("http")
async def guard_requests(request: Request, call_next):
    if request.url.path.startswith("/api"):
        try:
            rate_limit.check("api_ip", rate_limit.client_ip(request))
        except rate_limit.RateLimited as exc:
            return JSONResponse(
                {"detail": "Too many requests; slow down."},
                status_code=429,
                headers={"Retry-After": str(exc.retry_after)},
            )
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        if request.url.path.startswith(("/docs", "/openapi")) and name == "Cache-Control":
            continue
        response.headers.setdefault(name, value)
    return response


# Added after the middleware above so CORS wraps it (429s stay readable).
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Never echo submitted values (a malformed login would return the password).
    errors = [
        {"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    return JSONResponse({"detail": errors}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal error"}, status_code=500)


for router in [auth.router, chat.router, security.router, approvals.router]:
    app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/status")
def status():
    return {"mode": "GEMINI" if GEMINI_API_KEY else "DEMO"}
