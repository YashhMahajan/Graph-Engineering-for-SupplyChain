"""An OpenRouter client built for a free tier: a model waterfall, a disk cache, a daily budget.

Free-tier keys get a small number of requests per day (50 at the time of writing), so every
request has to count:

* **Cache first.** A reply is cached under the hash of the prompt (not the model), so a re-run
  of an evaluation or a dataset build spends nothing it has spent before.
* **Waterfall.** Models are tried in order. Any failure moves to the next model: an HTTP
  error, a timeout, an empty reply, a reply that is not JSON, or JSON the caller's validator
  rejects. When every model is rate-limited for the minute, the client waits for the reset and
  tries the chain again (bounded by ``max_wait``). A daily cap or an exhausted credit stops the
  run with ``BudgetExhausted``, because switching models cannot help with it.
* **Budget guard.** Every attempt is logged. Before an attempt, the client checks the requests
  used today (UTC) against the daily limit minus a reserve, and refuses to go over it.

The key is read from ``OPENROUTER_API_KEY``, loaded from the nearest ``.env`` when unset. No
personal or project detail is sent in headers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from .fetch import cache_dir

__all__ = [
    "DEFAULT_MODELS",
    "AllModelsFailed",
    "BudgetExhausted",
    "LLMError",
    "OpenRouter",
    "Reply",
    "extract_json",
    "load_env",
]

DEFAULT_MODELS = (
    "thinkingmachines/inkling-2-small:free",
    "baidu/ernie-5.5-flash-preview:free",
)
API = "https://openrouter.ai/api/v1"
PROMPT_VERSION = "1"
# attempts that reached a model and so may use the free-tier quota (refusals and rate limits
# are rejected before a model runs and do not)
_COUNTED = frozenset({"ok", "invalid_json", "rejected", "empty", "timeout", "http_error"})


class LLMError(RuntimeError):
    pass


class BudgetExhausted(LLMError):  # noqa: N818 (reads as a state, like StopIteration)
    """The daily request budget (or the credit) is used up. Wait for the reset."""


class AllModelsFailed(LLMError):  # noqa: N818
    def __init__(self, attempts: list[dict]):
        super().__init__(
            "every model failed: "
            + "; ".join(f"{a['model']}: {a['status']} {a.get('detail', '')}" for a in attempts)
        )
        self.attempts = attempts


def load_env(start: Path | None = None) -> Path | None:
    """Load KEY=VALUE lines from the nearest ``.env`` (cwd upward) into unset variables."""
    d = (start or Path.cwd()).resolve()
    for p in [d, *d.parents]:
        f = p / ".env"
        if f.is_file():
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip().removeprefix("export ").strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
            return f
    return None


_THINK = re.compile(r"<think>.*?</think>", re.S)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str) -> Any:
    """The JSON object in a model reply: think blocks and code fences removed, then the
    outermost ``{...}``. Raises ``ValueError`` when there is none."""
    t = _THINK.sub("", text or "").strip()
    m = _FENCE.search(t)
    if m:
        t = m.group(1).strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j <= i:
        raise ValueError("no JSON object in the reply")
    try:
        return json.loads(t[i : j + 1])
    except json.JSONDecodeError as e:
        raise ValueError(f"malformed JSON: {e}") from e


@dataclass
class Reply:
    content: str
    parsed: Any
    model: str
    cached: bool
    prompt_hash: str
    attempts: list[dict] = field(default_factory=list)


def _today(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")


class OpenRouter:
    def __init__(
        self,
        models: Sequence[str] = DEFAULT_MODELS,
        api_key: str | None = None,
        root: Path | None = None,
        daily_limit: int = 50,
        reserve: int = 2,
        max_wait: float = 900.0,
        timeout: float = 240.0,
        max_attempts: int = 6,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        offline: bool = False,
        reasoning: str | int = 6000,
        temperature: float = 0.6,
    ):
        self.reasoning = reasoning
        self.temperature = temperature
        if api_key is None:
            load_env()
            api_key = os.environ.get("OPENROUTER_API_KEY", "")
        self.api_key = api_key
        self.models = list(models)
        self.root = (root or cache_dir()) / "llm"
        self.root.mkdir(parents=True, exist_ok=True)
        self.daily_limit = daily_limit
        self.reserve = reserve
        self.max_wait = max_wait
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.session = session or requests.Session()
        self.sleep = sleep
        self.clock = clock
        self.offline = offline
        self._caps: dict[str, set[str]] | None = None
        self._baseline: tuple[int, int, str] | None = None

    # ------------------------------------------------------------------ budget
    @property
    def usage_log(self) -> Path:
        return self.root / "usage.jsonl"

    def _log(self, model: str, status: str, kind: str, detail: str = "") -> None:
        rec = {"ts": self.clock(), "model": model, "status": status, "kind": kind}
        if detail:
            rec["detail"] = detail[:200]
        with self.usage_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def used_today(self) -> int:
        if not self.usage_log.exists():
            return 0
        today = _today(self.clock())
        n = 0
        for line in self.usage_log.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _today(rec.get("ts", 0)) == today and rec.get("status") in _COUNTED:
                n += 1
        return n

    def _exhausted_marker(self) -> Path:
        return self.root / f"exhausted-{_today(self.clock())}"

    def remote_status(self) -> dict | None:
        """The key's own view of today's free-model requests (a free endpoint)."""
        if not self.api_key or self.offline:
            return None
        try:
            r = self.session.get(
                f"{API}/key", headers={"Authorization": f"Bearer {self.api_key}"}, timeout=30
            )
            d = r.json().get("data") or {}
        except (requests.RequestException, ValueError):
            return None
        return d.get("free_model_daily_requests")

    def remaining(self, remote: bool = True) -> int:
        """Requests this client will still make today (the reserve held back). The key's own
        count is the authority when it can be read; attempts since then are subtracted."""
        if self._exhausted_marker().exists():
            return 0
        used = self.used_today()
        if remote and self._baseline is None:
            st = self.remote_status()
            if st and isinstance(st.get("remaining"), int):
                self._baseline = (st["remaining"], used, _today(self.clock()))
        if self._baseline is not None and self._baseline[2] == _today(self.clock()):
            left = self._baseline[0] - (used - self._baseline[1])
        else:
            left = self.daily_limit - used
        return max(0, left - self.reserve)

    # ------------------------------------------------------------------ availability
    def _unavailable_path(self) -> Path:
        return self.root / "unavailable.json"

    def unavailable(self) -> dict[str, float]:
        p = self._unavailable_path()
        if not p.exists():
            return {}
        d = json.loads(p.read_text(encoding="utf-8"))
        now = self.clock()
        return {m: t for m, t in d.items() if now - t < 86400}

    def _mark_unavailable(self, model: str) -> None:
        d = self.unavailable()
        d[model] = self.clock()
        self._unavailable_path().write_text(json.dumps(d), encoding="utf-8")

    # ------------------------------------------------------------------ cache
    @staticmethod
    def prompt_hash(kind: str, messages: list[dict]) -> str:
        blob = json.dumps(
            {"v": PROMPT_VERSION, "kind": kind, "messages": messages},
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(blob.encode()).hexdigest()

    def _cache_path(self, h: str) -> Path:
        return self.root / "cache" / h[:2] / f"{h}.json"

    def cached(self, kind: str, messages: list[dict]) -> Reply | None:
        h = self.prompt_hash(kind, messages)
        p = self._cache_path(h)
        if not p.exists():
            return None
        d = json.loads(p.read_text(encoding="utf-8"))
        return Reply(d["content"], d["parsed"], d["model"], True, h)

    # ------------------------------------------------------------------ models
    def _capabilities(self) -> dict[str, set[str]]:
        if self._caps is not None:
            return self._caps
        p = self.root / "models.json"
        data = None
        if p.exists() and self.clock() - p.stat().st_mtime < 86400:
            data = json.loads(p.read_text(encoding="utf-8"))
        elif not self.offline:
            try:
                data = self.session.get(f"{API}/models", timeout=30).json().get("data")
                p.write_text(json.dumps(data), encoding="utf-8")
            except (requests.RequestException, ValueError):
                data = None
        self._caps = {
            m["id"]: set(m.get("supported_parameters") or []) for m in (data or []) if "id" in m
        }
        return self._caps

    def _payload(self, model: str, messages: list[dict], max_tokens: int) -> dict:
        caps = self._capabilities().get(model, set())
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            # greedy decoding makes reasoning models loop on long inputs; the prompt-hash cache,
            # not the sampler, is what makes a re-run reproducible
            "temperature": self.temperature,
        }
        if "top_p" in caps:
            body["top_p"] = 0.95
        if "response_format" in caps:
            body["response_format"] = {"type": "json_object"}
        if "reasoning" in caps:  # the trace shares max_tokens with the answer
            r = self.reasoning
            if r == "none":
                body["reasoning"] = {"enabled": False}
            elif isinstance(r, int):  # a cap on the trace, for models that ignore effort
                body["reasoning"] = {"max_tokens": r, "exclude": True}
            else:
                body["reasoning"] = {"effort": r, "exclude": True}
        if "seed" in caps:
            body["seed"] = 7
        return body

    # ------------------------------------------------------------------ call
    def complete(
        self,
        messages: list[dict],
        *,
        kind: str,
        validate: Callable[[Any], str | None] | None = None,
        max_tokens: int = 32000,
    ) -> Reply:
        """One answer for ``messages``: from the cache, else from the first model that returns
        valid JSON. ``validate`` returns an error string to reject a parsed reply."""
        hit = self.cached(kind, messages)
        if hit is not None:
            return hit
        if self.offline:
            raise LLMError("offline: no cached reply for this prompt")
        if not self.api_key:
            raise LLMError("OPENROUTER_API_KEY is not set (put it in .env)")
        h = self.prompt_hash(kind, messages)
        attempts: list[dict] = []
        waited = 0.0
        while True:
            reset_at: list[float] = []
            round_attempts = 0
            skip = self.unavailable()
            live = [m for m in self.models if m not in skip]
            if not live:
                raise AllModelsFailed(
                    attempts or [{"model": m, "status": "unavailable"} for m in self.models]
                )
            for model in live:
                if len(attempts) >= self.max_attempts:
                    raise AllModelsFailed(attempts)
                if self.remaining(remote=self._baseline is None) <= 0:
                    raise BudgetExhausted(
                        f"daily budget reached ({self.used_today()} requests used today, "
                        f"limit {self.daily_limit}, reserve {self.reserve})"
                    )
                round_attempts += 1
                status, detail, content, reset = self._attempt(model, messages, max_tokens)
                self._log(model, status, kind, detail)
                att = {"model": model, "status": status, "detail": detail}
                attempts.append(att)
                if status == "daily_cap":
                    self._exhausted_marker().write_text(detail)
                    raise BudgetExhausted(f"{model}: {detail}")
                if status == "auth":
                    raise LLMError(f"{model}: authentication failed: {detail}")
                if status == "unavailable":
                    self._mark_unavailable(model)
                if status == "rate_limited" and reset:
                    reset_at.append(reset)
                if status != "ok":
                    continue
                try:
                    parsed = extract_json(content)
                except ValueError as e:
                    att["status"] = "invalid_json"
                    att["detail"] = str(e)
                    continue
                err = validate(parsed) if validate else None
                if err:
                    att["status"] = "rejected"
                    att["detail"] = err
                    continue
                p = self._cache_path(h)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(
                    json.dumps(
                        {
                            "content": content,
                            "parsed": parsed,
                            "model": model,
                            "kind": kind,
                            "ts": self.clock(),
                            "messages": messages,
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                return Reply(content, parsed, model, False, h, attempts)
            statuses = {a["status"] for a in attempts[-round_attempts:]}
            if statuses == {"rate_limited"} and waited < self.max_wait:
                now = self.clock()
                wait = min(reset_at) - now if reset_at else 30.0
                wait = max(5.0, min(wait + 1.0, 120.0, self.max_wait - waited))
                self.sleep(wait)
                waited += wait
                continue
            raise AllModelsFailed(attempts)

    def _attempt(
        self, model: str, messages: list[dict], max_tokens: int
    ) -> tuple[str, str, str, float | None]:
        """(status, detail, content, rate-limit reset epoch seconds)."""
        try:
            r = self.session.post(
                f"{API}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=self._payload(model, messages, max_tokens),
                timeout=self.timeout,
            )
        except requests.Timeout:
            return "timeout", "", "", None
        except requests.RequestException as e:
            return "network", type(e).__name__, "", None
        try:
            body = r.json()
        except ValueError:
            body = {}
        err = body.get("error") if isinstance(body, dict) else None
        msg = ""
        if isinstance(err, dict):
            msg = str(err.get("message") or "")
            raw = (err.get("metadata") or {}).get("raw")
            if raw:
                msg = f"{msg} {raw}"
        code = r.status_code if not err else int(err.get("code") or r.status_code or 500)
        if code == 429 or "rate limit" in msg.lower():
            reset = None
            hdr = r.headers.get("X-RateLimit-Reset") or (
                ((err or {}).get("metadata") or {}).get("headers") or {}
            ).get("X-RateLimit-Reset")
            if hdr:
                try:
                    v = float(hdr)
                    reset = v / 1000.0 if v > 1e11 else v
                except ValueError:
                    reset = None
            low = msg.lower()
            if "per-day" in low or "per day" in low or "daily" in low:
                return "daily_cap", msg[:200], "", reset
            return "rate_limited", msg[:200], "", reset
        if code == 402:
            return "daily_cap", "insufficient credits", "", None
        if code == 401:
            return "auth", msg[:200], "", None
        if code == 403 and "moderat" not in msg.lower():
            return "unavailable", msg[:200], "", None  # this model refuses this key
        if err or r.status_code != 200:
            return "http_error", f"{code} {msg[:160]}", "", None
        try:
            choice = body["choices"][0]
            content = choice["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return "http_error", "no choices in reply", "", None
        usage = body.get("usage") or {}
        rt = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        tokens = (
            f"prompt={usage.get('prompt_tokens')} "
            f"completion={usage.get('completion_tokens')} reasoning={rt}"
        )
        if not content.strip():
            return "empty", f"finish={choice.get('finish_reason')} {tokens}", "", None
        return "ok", tokens, content, None
