import logging
from datetime import date

import httpx

from app.core.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_TIMEOUT_SECONDS
from app.llm.system_prompt import SYSTEM_PROMPT

log = logging.getLogger("gateway.gemini")


class LLMUnavailable(Exception):
    """Provider failure. Never retried here: callers fail closed instead."""

    def __init__(self, message="Gemini unavailable", status_code=None):
        super().__init__(message)
        self.status_code = status_code

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

    try:
        response = httpx.post(
            (
                "https://generativelanguage.googleapis.com/"
                f"v1beta/models/{GEMINI_MODEL}:generateContent"
            ),
            headers={"x-goog-api-key": GEMINI_API_KEY},
            json=payload,
            timeout=GEMINI_TIMEOUT_SECONDS,
        )

        if response.status_code >= 400:
            # Provider error bodies can echo request data; log the status only.
            log.warning("Gemini returned HTTP %s", response.status_code)
            raise LLMUnavailable(
                f"Gemini error {response.status_code}", response.status_code
            )

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
        raise LLMUnavailable("Gemini returned an unexpected response.") from exc
