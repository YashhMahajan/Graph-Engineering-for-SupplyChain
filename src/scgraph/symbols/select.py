"""The LLM step: choose one candidate per advisory, many advisories per request.

The model never names a function. It answers with an option id from a list the code built
(or ``none``), ranks the plausible options, and quotes the line of the excerpt that shows the
flaw or the fix. The quote is checked against the excerpt the model was given; a quote that
is not in it is flagged, and the answer is still subject to the verifier against released
source. Free-tier budgets are small, so tasks are packed into as few requests as the prompt
size allows, and a task the model skipped is retried in a later request, not the same one.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .llm import BudgetExhausted, LLMError, OpenRouter

__all__ = ["Choice", "Option", "Task", "choose", "messages_for"]


@dataclass
class Option:
    oid: str  # "C1", "C2", ...
    symbol: str
    facts: str  # one line of model-free facts (changed lines, flags)
    excerpt: str  # the diff hunk or the function source the model may quote from


@dataclass
class Task:
    tid: str  # the advisory id
    package: str
    text: str  # advisory summary + details
    options: list[Option]
    mode: str = "fix"  # "fix" (options come from a fix diff) | "search" (from the package)


@dataclass
class Choice:
    tid: str
    symbol: str | None  # None: the model answered "none"
    ranked: list[str] = field(default_factory=list)  # symbols, best first
    confidence: float = 0.0
    evidence: str = ""
    evidence_found: bool = False
    reason: str = ""
    model: str = ""
    prompt_hash: str = ""
    cached: bool = False


SYSTEM = """You are a software security analyst. Each task gives one security advisory and a \
numbered list of candidate functions that static analysis extracted, either from the commit \
that fixed the advisory (mode "fix") or from the affected package's source (mode "search").

For each task, choose the candidate that IS the vulnerable function: the function whose own \
code contains the flaw the advisory describes. If the fix only added a new helper, choose the \
existing function that the fix made call it. Prefer the function where the flaw lives over a \
caller that only reaches it, unless the advisory names the caller.

Rules:
- Answer only with option ids from that task's list, or "none" when no candidate matches the \
advisory (for example the change is unrelated refactoring, or the list misses the function).
- "ranked" lists every plausible option id, best first (at most 4).
- "evidence" is one line copied exactly from that option's excerpt that shows the flaw or the \
fix. Leave it empty if you answered "none".
- "confidence" is your probability (0 to 1) that "choice" is correct.
- Think briefly: a few sentences per task are enough. The candidates and excerpts are all \
the evidence there is.
- Reply with one JSON object and nothing else:
{"results": [{"task": "T1", "choice": "C2", "ranked": ["C2", "C1"], "confidence": 0.8, \
"evidence": "if not scheme.startswith('https') and username and password:", \
"reason": "at most 25 words"}]}"""


def _clip(s: str, n: int) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 3].rstrip() + "..."


def render_task(i: int, t: Task) -> str:
    lines = [
        f"### Task T{i} (mode: {t.mode})",
        f"Advisory {t.tid} for package {t.package}:",
        _clip(t.text, 1500),
        "",
        "Candidates:",
    ]
    for o in t.options:
        lines.append(f"[{o.oid}] {o.symbol}  ({o.facts})")
        if o.excerpt:
            lines.append("```")
            lines.append(_clip(o.excerpt, 1800))
            lines.append("```")
    return "\n".join(lines)


def messages_for(tasks: Sequence[Task]) -> list[dict]:
    body = "\n\n".join(render_task(i + 1, t) for i, t in enumerate(tasks))
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"{len(tasks)} tasks follow.\n\n{body}"},
    ]


def _validator(tasks: Sequence[Task]):
    ids = {f"T{i + 1}": {o.oid for o in t.options} for i, t in enumerate(tasks)}

    def check(d: Any) -> str | None:
        if not isinstance(d, dict) or not isinstance(d.get("results"), list):
            return "expected an object with a 'results' list"
        good = 0
        for r in d["results"]:
            if not isinstance(r, dict) or r.get("task") not in ids:
                continue
            c = r.get("choice")
            if c == "none" or c in ids[r["task"]]:
                good += 1
        return None if good else "no result names a valid task and option id"

    return check


_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s.replace("\\n", " ")).strip().lstrip("+- ").strip()


def _evidence_in(evidence: str, excerpt: str) -> bool:
    e = _norm(evidence)
    if len(e) < 6:
        return False
    return e in _norm(excerpt) or any(e == _norm(ln) for ln in excerpt.splitlines() if ln.strip())


def _parse(
    tasks: Sequence[Task], parsed: dict, model: str, h: str, cached: bool
) -> dict[str, Choice]:
    out: dict[str, Choice] = {}
    for r in parsed.get("results", []):
        if not isinstance(r, dict):
            continue
        tid = r.get("task")
        if not isinstance(tid, str) or not tid.startswith("T") or not tid[1:].isdigit():
            continue
        k = int(tid[1:]) - 1
        if not 0 <= k < len(tasks):
            continue
        t = tasks[k]
        opts = {o.oid: o for o in t.options}
        c = r.get("choice")
        if c != "none" and c not in opts:
            continue
        ranked = [opts[x].symbol for x in r.get("ranked") or [] if x in opts]
        sym = None if c == "none" else opts[c].symbol
        if sym and sym not in ranked:
            ranked.insert(0, sym)
        try:
            conf = float(r.get("confidence") or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        ev = str(r.get("evidence") or "")[:300]
        out[t.tid] = Choice(
            tid=t.tid,
            symbol=sym,
            ranked=ranked[:4],
            confidence=max(0.0, min(1.0, conf)),
            evidence=ev,
            evidence_found=bool(sym) and _evidence_in(ev, opts[c].excerpt) if sym else False,
            reason=str(r.get("reason") or "")[:300],
            model=model,
            prompt_hash=h,
            cached=cached,
        )
    return out


def _batches(tasks: Sequence[Task], size: int, max_chars: int) -> list[list[Task]]:
    out: list[list[Task]] = []
    cur: list[Task] = []
    chars = 0
    for t in tasks:
        n = len(render_task(1, t))
        if cur and (len(cur) >= size or chars + n > max_chars):
            out.append(cur)
            cur, chars = [], 0
        cur.append(t)
        chars += n
    if cur:
        out.append(cur)
    return out


SYSTEM_SIG = hashlib.sha256(SYSTEM.encode()).hexdigest()[:12]
_SECTION = re.compile(r"(?m)^(?=### Task T\d+ )")
_HEAD = re.compile(r"^### Task T\d+ ")


def task_key(t: Task) -> str:
    """Identity of one task's prompt text, independent of the batch it is sent in."""
    return hashlib.sha256(f"{SYSTEM_SIG}\n{render_task(0, t)}".encode()).hexdigest()


def _remember(
    client: OpenRouter, batch: Sequence[Task], parsed: dict, got: dict, model: str, h: str
):
    for r in parsed.get("results", []):
        tid = r.get("task") if isinstance(r, dict) else None
        if isinstance(tid, str) and tid[1:].isdigit() and 0 < int(tid[1:]) <= len(batch):
            t = batch[int(tid[1:]) - 1]
            if t.tid in got:
                raw = {k: v for k, v in r.items() if k != "task"}
                client.task_put(task_key(t), {"raw": raw, "model": model, "prompt_hash": h})


def _from_cache(t: Task, entry: dict) -> Choice | None:
    try:
        raw = {**entry["raw"], "task": "T1"}
        return _parse([t], {"results": [raw]}, entry["model"], entry["prompt_hash"], True).get(
            t.tid
        )
    except (KeyError, TypeError):
        return None


def ingest_legacy(client: OpenRouter) -> int:
    """Split whole-reply cache entries into per-task entries, so answers paid for under one
    batching are reused under any other. Only replies to the current system prompt count."""
    n = 0
    root = client.root / "cache"
    if not root.exists():
        return 0
    for f in root.glob("*/*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            msgs = d["messages"]
            if d.get("kind") != "select" or msgs[0]["content"] != SYSTEM:
                continue
            sections = [x for x in _SECTION.split(msgs[1]["content"]) if x.startswith("### Task T")]
            for r in d["parsed"].get("results", []):
                tid = r.get("task")
                if not (isinstance(tid, str) and tid[1:].isdigit()):
                    continue
                k = int(tid[1:]) - 1
                if not 0 <= k < len(sections) or r.get("choice") is None:
                    continue
                text = _HEAD.sub("### Task T0 ", sections[k].rstrip("\n"), count=1)
                key = hashlib.sha256(f"{SYSTEM_SIG}\n{text}".encode()).hexdigest()
                if client.task_get(key) is None:
                    raw = {a: b for a, b in r.items() if a != "task"}
                    client.task_put(key, {"raw": raw, "model": d["model"], "prompt_hash": f.stem})
                    n += 1
        except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
            continue
    return n


def choose(
    client: OpenRouter,
    tasks: Sequence[Task],
    batch_size: int = 6,
    max_chars: int = 40_000,
    max_requests: int | None = None,
    retry_missing: bool = True,
    log=None,
) -> tuple[dict[str, Choice], dict]:
    """Choices for as many tasks as the budget allows, and a report of what was spent.

    Order of spending: the per-task cache first (free), then batches of the tasks still open.
    A batch that fails (a reasoning loop, a timeout) is split in half and retried, so one bad
    task costs a few requests and not the whole batch. A single task that fails alone is
    dropped for this run. Stops cleanly, keeping every answer, at the request cap or the
    daily budget; the budget is checked before every request."""
    todo = [t for t in tasks if t.options]
    if not getattr(client, "_legacy_done", False):  # reuse replies cached under old batching
        ingest_legacy(client)
        client._legacy_done = True  # type: ignore[attr-defined]
    out: dict[str, Choice] = {}
    report: dict[str, Any] = {
        "requests": 0,
        "cached": 0,
        "task_cache_hits": 0,
        "tasks": len(todo),
        "answered": 0,
        "failed": 0,
        "split": 0,
        "stopped": "",
    }
    for t in todo:
        entry = client.task_get(task_key(t))
        ch = _from_cache(t, entry) if entry else None
        if ch is not None:
            out[t.tid] = ch
            report["task_cache_hits"] += 1
    used0 = client.used_today()
    dead: set[str] = set()

    def spent() -> int:
        return client.used_today() - used0

    for _ in range(2 if retry_missing else 1):
        pending = [t for t in todo if t.tid not in out and t.tid not in dead]
        if not pending:
            break
        queue = deque(_batches(pending, batch_size, max_chars))
        while queue:
            batch = queue.popleft()
            msgs = messages_for(batch)
            if (
                client.cached("select", msgs) is None
                and max_requests is not None
                and spent() >= max_requests
            ):
                report["stopped"] = "max_requests"
                break
            try:
                reply = client.complete(
                    msgs, kind="select", validate=_validator(batch), max_tokens=48000
                )
            except BudgetExhausted as e:
                report["stopped"] = f"budget: {e}"
                break
            except LLMError as e:
                if client.offline:  # cache-only replay: skip what was never answered
                    continue
                report["failed"] += 1
                if log:
                    log(f"batch of {len(batch)} failed: {e}")
                attempts = getattr(e, "attempts", None)
                if attempts is None or all(
                    a["status"] in ("unavailable", "auth") for a in attempts
                ):
                    report["stopped"] = f"no usable model: {e}"
                    break
                if len(batch) > 1:
                    mid = len(batch) // 2
                    queue.appendleft(batch[mid:])
                    queue.appendleft(batch[:mid])
                    report["split"] += 1
                else:
                    dead.add(batch[0].tid)
                continue
            report["cached" if reply.cached else "requests"] += 1
            got = _parse(batch, reply.parsed, reply.model, reply.prompt_hash, reply.cached)
            _remember(client, batch, reply.parsed, got, reply.model, reply.prompt_hash)
            out.update(got)
            if log:
                left = client.remaining(remote=False)
                log(
                    f"{'cache' if reply.cached else reply.model}: {len(got)}/{len(batch)} "
                    f"answered, {left} requests left today"
                )
        if report["stopped"]:
            break
    report["requests"] = spent()
    report["answered"] = len(out)
    return out, report


def dumps(choices: dict[str, Choice]) -> str:
    return json.dumps({k: vars(v) for k, v in choices.items()}, indent=1, sort_keys=True)
