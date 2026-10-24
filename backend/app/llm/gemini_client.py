from datetime import date

import httpx

from app.core.config import GEMINI_API_KEY, GEMINI_MODEL
from app.llm.system_prompt import SYSTEM_PROMPT


class LLMUnavailable(Exception):
    pass


def generate(
    contents: list,
    role: str,
    declarations: list | None = None,
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
            timeout=30,
        )

        if response.status_code >= 400:
            print("GEMINI STATUS:", response.status_code)
            print("GEMINI ERROR:", response.text)

            raise LLMUnavailable(
                f"Gemini error {response.status_code}: {response.text}"
            )

        data = response.json()

        return data["candidates"][0]["content"]

    except LLMUnavailable:
        raise

    except httpx.HTTPError as exc:
        print("GEMINI HTTP ERROR:", str(exc))
        raise LLMUnavailable(f"Gemini HTTP error: {exc}") from exc

    except (KeyError, IndexError, ValueError) as exc:
        print("GEMINI RESPONSE PARSING ERROR:", str(exc))
        raise LLMUnavailable("Gemini returned an unexpected response.") from exc
