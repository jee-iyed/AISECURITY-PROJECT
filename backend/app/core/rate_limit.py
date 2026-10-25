"""In-memory sliding-window rate limiting (no external dependency).

Scope: a single backend process, which is how the demo is deployed. Several
workers or replicas would each keep their own counters; a shared store (e.g.
Redis) would then be required. Limits are configurable via environment.
"""

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"


def _limit(name, default):
    return int(os.getenv(f"RATE_LIMIT_{name}", default))


# (max requests, window seconds)
LIMITS = {
    "login_ip": (_limit("LOGIN_PER_IP", 20), 60),
    "login_account": (_limit("LOGIN_PER_ACCOUNT", 5), 60),
    "chat": (_limit("CHAT_PER_USER", 30), 60),
    "analysis": (_limit("ANALYSIS_PER_USER", 10), 60),
    "review": (_limit("REVIEW_PER_USER", 20), 60),
    "api_ip": (_limit("API_PER_IP", 300), 60),
    # Upstream protection: every Gemini call in the process, all users.
    "gemini": (_limit("GEMINI_PER_MINUTE", 60), 60),
}

_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_lock = threading.Lock()


class RateLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


def check(bucket: str, key: str) -> None:
    """Record a hit; raise RateLimited when the bucket is full."""
    if not ENABLED:
        return
    limit, window = LIMITS[bucket]
    now = time.monotonic()
    with _lock:
        hits = _hits[(bucket, key)]
        while hits and hits[0] <= now - window:
            hits.popleft()
        if len(hits) >= limit:
            # A limit of 0 disables the bucket entirely (empty window).
            oldest = hits[0] if hits else now
            raise RateLimited(max(1, int(oldest + window - now) + 1))
        hits.append(now)


def enforce(bucket: str, key: str) -> None:
    """HTTP flavour of ``check``: 429 with Retry-After."""
    try:
        check(bucket, key)
    except RateLimited as exc:
        raise HTTPException(
            429,
            "Too many requests; slow down.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


def client_ip(request: Request) -> str:
    # Direct peer address only: X-Forwarded-For is client-controlled unless a
    # trusted proxy is configured, which this deployment does not have.
    return request.client.host if request.client else "unknown"


def reset() -> None:
    with _lock:
        _hits.clear()
