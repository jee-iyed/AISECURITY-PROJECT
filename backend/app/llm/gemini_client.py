import logging
import re
import threading
import time
from datetime import date

import httpx

from app.core import rate_limit
from app.core.config import (
    GEMINI_API_KEY,
    GEMINI_FALLBACK_MODELS,
    GEMINI_MODEL,
    GEMINI_TIMEOUT_SECONDS,
)
from app.llm.system_prompt import SYSTEM_PROMPT

log = logging.getLogger("gateway.gemini")

# A model that is overloaded or out of its own quota is skipped for a while
# instead of being called again on every request.
BUSY_COOLDOWN_SECONDS = 60
QUOTA_COOLDOWN_DEFAULT = 3600
QUOTA_COOLDOWN_MAX = 24 * 3600
_benched: dict[str, float] = {}
_bench_lock = threading.Lock()


def reset_model_health():
    """Forget benched models (tests, or after changing the configuration)."""
    with _bench_lock:
        _benched.clear()


def _bench(model, seconds):
    with _bench_lock:
        _benched[model] = time.monotonic() + seconds


def _available(model):
    with _bench_lock:
        return _benched.get(model, 0) <= time.monotonic()


class LLMUnavailable(Exception):
    """Provider failure. Never retried here: callers fail closed instead."""

    def __init__(self, message="Gemini unavailable", status_code=None):
        super().__init__(message)
        self.status_code = status_code
        self.unexpected = False
        # Set when a 429 concerns only this model's quota (another model still
        # has its own quota); retry_after comes from the provider's retryDelay.
        self.model_quota = False
        self.retry_after = None

    @property
    def rate_limited(self):
        return self.status_code == 429


def generate(
    contents: list,
    role: str,
    declarations: list | None = None,
    generation_config: dict | None = None,
) -> dict:
    payload = {
        "systemInstruction": {
            "parts": [
                {
                    "text": (
                        SYSTEM_PROMPT
                        + " Authenticated role: "
                        + role
                        + " Current date: "
                        + date.today().isoformat()
                    )
                }
            ]
        },
        "contents": contents,
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 1500,
            **(generation_config or {}),
        },
    }

    if declarations:
        payload["tools"] = [{"functionDeclarations": declarations}]

    # Each configured model is tried at most once per request, never in a loop.
    # Fall through to the next model when this one is busy (503, 5xx,
    # timeout) or out of its *own* quota (free-tier quotas are per model and
    # per day). Project-wide or local rate limits, auth and request errors are
    # not model-specific and fail immediately.
    configured = [GEMINI_MODEL, *(m for m in GEMINI_FALLBACK_MODELS if m != GEMINI_MODEL)]
    models = [m for m in configured if _available(m)]
    if not models:
        raise LLMUnavailable("All Gemini models are temporarily unavailable", 503)
    for index, model in enumerate(models):
        try:
            return _call(model, payload)
        except LLMUnavailable as exc:
            busy = (exc.status_code is None or exc.status_code >= 500) and not exc.unexpected
            if exc.model_quota:
                _bench(model, exc.retry_after or QUOTA_COOLDOWN_DEFAULT)
            elif busy:
                _bench(model, BUSY_COOLDOWN_SECONDS)
            if not (busy or exc.model_quota) or index == len(models) - 1:
                raise
            log.warning("Gemini model %s unavailable; trying %s", model, models[index + 1])


def _quota_error(response):
    """429 details: (model-specific?, retry delay in seconds). Body not logged."""
    # The body is untrusted and may have any shape: never let parsing raise.
    try:
        body = response.json()
    except ValueError:
        return False, None
    error = body.get("error") if isinstance(body, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    per_model, delay = False, None
    for detail in details if isinstance(details, list) else []:
        if not isinstance(detail, dict):
            continue
        violations = detail.get("violations")
        for violation in violations if isinstance(violations, list) else []:
            if isinstance(violation, dict) and "PerModel" in str(violation.get("quotaId", "")):
                per_model = True
        match = re.fullmatch(r"(\d+(?:\.\d+)?)s", str(detail.get("retryDelay", "")))
        if match:
            delay = min(QUOTA_COOLDOWN_MAX, float(match.group(1)))
    return per_model, delay


def _call(model: str, payload: dict) -> dict:
    try:
        # Process-wide budget protects the quota from bursts; exceeding it is
        # handled exactly like a provider 429 (fail closed, no retry).
        rate_limit.check("gemini", "global")
    except rate_limit.RateLimited as exc:
        raise LLMUnavailable("Local Gemini call budget exhausted", 429) from exc

    try:
        response = httpx.post(
            (
                "https://generativelanguage.googleapis.com/"
                f"v1beta/models/{model}:generateContent"
            ),
            headers={"x-goog-api-key": GEMINI_API_KEY},
            json=payload,
            timeout=GEMINI_TIMEOUT_SECONDS,
        )

        if response.status_code >= 400:
            # Provider error bodies can echo request data; log the status only.
            log.warning("Gemini returned HTTP %s for %s", response.status_code, model)
            error = LLMUnavailable(
                f"Gemini error {response.status_code}", response.status_code
            )
            if response.status_code == 429:
                error.model_quota, error.retry_after = _quota_error(response)
            raise error

        data = response.json()

        return data["candidates"][0]["content"]

    except LLMUnavailable:
        raise

    except httpx.TimeoutException as exc:
        log.warning("Gemini request timed out")
        raise LLMUnavailable("Gemini timeout") from exc

    except httpx.HTTPError as exc:
        log.warning("Gemini transport error: %s", type(exc).__name__)
        raise LLMUnavailable("Gemini transport error") from exc

    except (KeyError, IndexError, TypeError, ValueError) as exc:
        log.warning("Gemini returned an unexpected response shape")
        error = LLMUnavailable("Gemini returned an unexpected response.")
        error.unexpected = True  # a malformed reply is not a busy model
        raise error from exc
