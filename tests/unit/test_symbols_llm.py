"""The OpenRouter client: waterfall, cache, budget and waits, with a fake HTTP session."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scgraph.symbols.llm import (
    AllModelsFailed,
    BudgetExhausted,
    LLMError,
    OpenRouter,
    extract_json,
    load_env,
)

MODELS = ["m/first:free", "m/second:free"]


class Resp:
    def __init__(self, status: int, body: Any, headers: dict | None = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def ok(content: str) -> Resp:
    return Resp(200, {"choices": [{"message": {"content": content}}]})


class Session:
    """Pops one scripted response per POST and records the model asked."""

    def __init__(self, script: list[Resp], remote_remaining: int = 40):
        self.script = list(script)
        self.asked: list[str] = []
        self.remote_remaining = remote_remaining

    def post(self, url: str, headers: dict, json: dict, timeout: float) -> Resp:
        assert "Authorization" in headers and "HTTP-Referer" not in headers
        self.asked.append(json["model"])
        return self.script.pop(0)

    def get(self, url: str, **kw: Any) -> Resp:
        if url.endswith("/models"):
            return Resp(
                200,
                {"data": [{"id": "m/second:free", "supported_parameters": ["response_format"]}]},
            )
        left = self.remote_remaining
        return Resp(200, {"data": {"free_model_daily_requests": {"remaining": left, "limit": 50}}})


def client(
    tmp_path: Path, script: list[Resp], remote: int = 40, **kw: Any
) -> tuple[OpenRouter, Session, list[float]]:
    s = Session(script, remote)
    slept: list[float] = []
    c = OpenRouter(models=MODELS, api_key="k", root=tmp_path, session=s, sleep=slept.append, **kw)
    return c, s, slept


MSG = [{"role": "user", "content": "pick"}]


def test_first_model_answers_and_the_reply_is_cached(tmp_path: Path) -> None:
    c, s, _ = client(tmp_path, [ok('{"a": 1}')])
    r = c.complete(MSG, kind="t")
    assert r.parsed == {"a": 1} and r.model == "m/first:free" and not r.cached
    again = c.complete(MSG, kind="t")  # no scripted response left: must come from the cache
    assert again.cached and again.parsed == {"a": 1}
    assert s.asked == ["m/first:free"]
    assert c.used_today() == 1


def test_any_failure_routes_to_the_next_model(tmp_path: Path) -> None:
    for bad in [
        Resp(500, {"error": {"code": 500, "message": "upstream"}}),
        ok("I think the answer is C2"),  # not JSON
        ok(""),  # empty
        Resp(200, {"error": {"code": 502, "message": "provider error"}}),
    ]:
        c, s, _ = client(tmp_path / str(id(bad)), [bad, ok('{"ok": true}')])
        r = c.complete(MSG, kind="t")
        assert r.model == "m/second:free" and r.parsed == {"ok": True}
        assert s.asked == MODELS


def test_a_validator_rejection_routes_to_the_next_model(tmp_path: Path) -> None:
    c, _s, _ = client(tmp_path, [ok('{"choice": "C9"}'), ok('{"choice": "C1"}')])
    r = c.complete(MSG, kind="t", validate=lambda d: None if d["choice"] == "C1" else "bad id")
    assert r.parsed == {"choice": "C1"} and r.attempts[0]["status"] == "rejected"


def test_minute_rate_limits_on_every_model_wait_then_retry(tmp_path: Path) -> None:
    limited = Resp(
        429, {"error": {"code": 429, "message": "Rate limit exceeded: free-models-per-min"}}
    )
    c, s, slept = client(tmp_path, [limited, limited, ok('{"x": 2}')])
    r = c.complete(MSG, kind="t")
    assert r.parsed == {"x": 2} and len(slept) == 1 and 5 <= slept[0] <= 120
    assert s.asked == [*MODELS, "m/first:free"]


def test_the_daily_cap_stops_without_burning_the_other_models(tmp_path: Path) -> None:
    capped = Resp(
        429, {"error": {"code": 429, "message": "Rate limit exceeded: free-models-per-day"}}
    )
    c, s, _ = client(tmp_path, [capped])
    with pytest.raises(BudgetExhausted):
        c.complete(MSG, kind="t")
    assert s.asked == ["m/first:free"]
    assert c.remaining(remote=False) == 0  # the marker holds for the rest of the UTC day


def test_the_local_budget_guard_refuses_before_spending(tmp_path: Path) -> None:
    c, s, _ = client(tmp_path, [ok('{"a": 1}')] * 5, remote=3, daily_limit=50, reserve=1)
    c.complete([{"role": "user", "content": "1"}], kind="t")
    c.complete([{"role": "user", "content": "2"}], kind="t")
    with pytest.raises(BudgetExhausted):
        c.complete([{"role": "user", "content": "3"}], kind="t")
    assert len(s.asked) == 2


def test_a_model_that_refuses_the_key_is_skipped_for_a_day(tmp_path: Path) -> None:
    refused = Resp(403, {"error": {"code": 403, "message": "only available on agentic harnesses"}})
    c, s, _ = client(tmp_path, [refused, ok('{"a": 1}'), ok('{"b": 2}')])
    assert c.complete(MSG, kind="t").model == "m/second:free"
    assert list(c.unavailable()) == ["m/first:free"]
    c.complete([{"role": "user", "content": "next"}], kind="t")
    assert s.asked == ["m/first:free", "m/second:free", "m/second:free"]  # not asked again
    assert c.used_today() == 2  # the refusal used no quota


def test_hard_errors_and_exhausted_chains(tmp_path: Path) -> None:
    c, _, _ = client(tmp_path / "a", [Resp(401, {"error": {"code": 401, "message": "bad key"}})])
    with pytest.raises(LLMError, match="authentication"):
        c.complete(MSG, kind="t")
    bad = Resp(500, {"error": {"code": 500, "message": "x"}})
    c, _, _ = client(tmp_path / "b", [bad, bad])
    with pytest.raises(AllModelsFailed):
        c.complete(MSG, kind="t")


def test_offline_mode_only_serves_the_cache(tmp_path: Path) -> None:
    c, _, _ = client(tmp_path, [ok('{"a": 1}')])
    c.complete(MSG, kind="t")
    off = OpenRouter(models=MODELS, api_key="", root=tmp_path, offline=True)
    assert off.complete(MSG, kind="t").parsed == {"a": 1}
    with pytest.raises(LLMError, match="offline"):
        off.complete([{"role": "user", "content": "new"}], kind="t")


def test_payload_uses_only_supported_parameters(tmp_path: Path) -> None:
    c, _, _ = client(tmp_path, [])
    assert "response_format" not in c._payload("m/first:free", MSG, 100)
    assert c._payload("m/second:free", MSG, 100)["response_format"] == {"type": "json_object"}


def test_remaining_takes_the_smaller_of_local_and_remote(tmp_path: Path) -> None:
    c, _, _ = client(tmp_path, [], reserve=2)
    assert c.remaining(remote=True) == 38  # remote says 40 left, minus the reserve


def test_extract_json_handles_fences_think_blocks_and_prose() -> None:
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('<think>hmm {"no": 1}</think>{"a": 2}') == {"a": 2}
    assert extract_json('Here you go: {"a": 3} hope it helps') == {"a": 3}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_load_env_reads_unset_keys_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("# c\nexport FOO_X='bar'\nKEEP_Y=new\n")
    monkeypatch.delenv("FOO_X", raising=False)
    monkeypatch.setenv("KEEP_Y", "old")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert load_env(sub) == tmp_path / ".env"
    import os

    assert os.environ["FOO_X"] == "bar" and os.environ["KEEP_Y"] == "old"
