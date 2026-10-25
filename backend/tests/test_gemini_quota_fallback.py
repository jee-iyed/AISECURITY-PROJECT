"""Model fallback on per-model quotas and busy models (Gemini always mocked)."""

import httpx
import pytest

from app.llm import gemini_client

OK = {"candidates": [{"content": {"parts": [{"text": "OK"}]}}]}


def quota_429(quota_id, retry="52050s"):
    return httpx.Response(
        429,
        json={
            "error": {
                "code": 429,
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {"violations": [{"quotaId": quota_id}]},
                    {"retryDelay": retry},
                ],
            }
        },
    )


@pytest.fixture()
def scripted(monkeypatch):
    called = []
    outcomes = {}

    def post(url, headers, json, timeout):
        model = url.split("/models/")[1].split(":")[0]
        called.append(model)
        outcome = outcomes[model]
        if isinstance(outcome, Exception):
            raise outcome
        response = httpx.Response(outcome.status_code, content=outcome.content, headers=outcome.headers)
        response.request = httpx.Request("POST", url)
        return response

    monkeypatch.setattr(gemini_client.httpx, "post", post)
    monkeypatch.setattr(gemini_client, "GEMINI_MODEL", "primary")
    monkeypatch.setattr(gemini_client, "GEMINI_FALLBACK_MODELS", ["backup", "last"])
    return called, outcomes


def test_per_model_daily_quota_falls_back(scripted):
    called, outcomes = scripted
    outcomes.update(
        primary=quota_429("GenerateRequestsPerDayPerProjectPerModel-FreeTier"),
        backup=httpx.Response(200, json=OK),
    )
    assert gemini_client.generate([], "STUDENT")["parts"][0]["text"] == "OK"
    assert called == ["primary", "backup"]


def test_exhausted_model_is_skipped_until_its_retry_delay(scripted, monkeypatch):
    called, outcomes = scripted
    outcomes.update(
        primary=quota_429("GenerateRequestsPerDayPerProjectPerModel-FreeTier", "120s"),
        backup=httpx.Response(200, json=OK),
    )
    gemini_client.generate([], "STUDENT")
    gemini_client.generate([], "STUDENT")
    assert called == ["primary", "backup", "backup"]  # primary not hammered
    clock = gemini_client.time.monotonic()
    monkeypatch.setattr(gemini_client.time, "monotonic", lambda: clock + 121)
    gemini_client.generate([], "STUDENT")
    assert called[-2:] == ["primary", "backup"]  # retried after the delay


@pytest.mark.parametrize(
    "response",
    [
        quota_429("GenerateRequestsPerDayPerProject-FreeTier"),  # project-wide
        httpx.Response(429, json={}),  # no details: assume global
        httpx.Response(429, text="not json"),
    ],
)
def test_project_wide_quota_stops_without_fallback(scripted, response):
    called, outcomes = scripted
    outcomes.update(primary=response, backup=httpx.Response(200, json=OK))
    with pytest.raises(gemini_client.LLMUnavailable) as exc:
        gemini_client.generate([], "STUDENT")
    assert exc.value.rate_limited and called == ["primary"]


def test_busy_model_benched_briefly(scripted):
    called, outcomes = scripted
    outcomes.update(primary=httpx.Response(503, json={}), backup=httpx.Response(200, json=OK))
    gemini_client.generate([], "STUDENT")
    gemini_client.generate([], "STUDENT")
    assert called == ["primary", "backup", "backup"]


def test_all_models_benched_fails_closed_without_network(scripted):
    called, outcomes = scripted
    busy = httpx.Response(503, json={})
    outcomes.update(primary=busy, backup=busy, last=busy)
    with pytest.raises(gemini_client.LLMUnavailable):
        gemini_client.generate([], "STUDENT")
    assert len(called) == 3
    with pytest.raises(gemini_client.LLMUnavailable) as exc:
        gemini_client.generate([], "STUDENT")
    assert len(called) == 3 and exc.value.status_code == 503  # no new call


def test_local_budget_is_never_treated_as_model_quota(scripted, monkeypatch):
    from app.core import rate_limit

    called, outcomes = scripted
    outcomes.update(primary=httpx.Response(200, json=OK), backup=httpx.Response(200, json=OK))
    monkeypatch.setattr(rate_limit, "ENABLED", True)
    monkeypatch.setitem(rate_limit.LIMITS, "gemini", (0, 60))
    with pytest.raises(gemini_client.LLMUnavailable) as exc:
        gemini_client.generate([], "STUDENT")
    assert exc.value.rate_limited and not exc.value.model_quota and called == []


@pytest.mark.parametrize(
    "body",
    [{"error": "quota"}, ["x"], {"error": {"details": "x"}}, {"error": {"details": [1, {"violations": "x"}]}}],
)
def test_malformed_quota_body_never_crashes(scripted, body):
    called, outcomes = scripted
    outcomes.update(primary=httpx.Response(429, json=body))
    with pytest.raises(gemini_client.LLMUnavailable) as exc:
        gemini_client.generate([], "STUDENT")
    assert exc.value.rate_limited and called == ["primary"]
