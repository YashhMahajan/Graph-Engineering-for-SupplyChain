"""The LLM selector: ids only, evidence checked, many tasks per request, budget respected."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scgraph.symbols.llm import OpenRouter
from scgraph.symbols.select import Option, Task, choose, messages_for

EXCERPT = (
    "@@ -324,7 +324,9 @@\n-        if username and password:\n"
    "+        if not scheme.startswith('https') and username and password:\n"
)


def task(tid: str, n: int = 2) -> Task:
    opts = [Option("C1", f"{tid}.pkg.patched", "+3 -1", EXCERPT)]
    opts += [Option(f"C{i}", f"{tid}.pkg.other{i}", "+1", "+    x = 1") for i in range(2, n + 1)]
    return Task(tid=tid, package="requests", text="Proxy-Authorization leak", options=opts)


class _Resp:
    status_code = 200

    def __init__(self, body: dict):
        self.body = body
        self.headers: dict = {}

    def json(self) -> dict:
        return self.body


class Fake:
    """A stand-in for the HTTP session: answers each request with a scripted payload."""

    def __init__(self, answers: list[Any]):
        self.answers = list(answers)
        self.prompts: list[str] = []

    def post(self, url: str, headers: dict, json: dict, timeout: float):
        self.prompts.append(json["messages"][1]["content"])
        payload = self.answers.pop(0)

        return _Resp({"choices": [{"message": {"content": payload}}]})

    def get(self, url: str, **kw: Any):
        return _Resp({"data": []})


def client(tmp: Path, answers: list[Any], **kw: Any) -> tuple[OpenRouter, Fake]:
    f = Fake(answers)
    return OpenRouter(models=["a:free", "b:free"], api_key="k", root=tmp, session=f, **kw), f


def test_one_request_answers_a_whole_batch_and_checks_the_quote(tmp_path: Path) -> None:
    ans = json.dumps(
        {
            "results": [
                {
                    "task": "T1",
                    "choice": "C1",
                    "ranked": ["C1", "C2"],
                    "confidence": 0.9,
                    "evidence": "+        if not scheme.startswith('https') and username and password:",
                },
                {"task": "T2", "choice": "C2", "confidence": 0.4, "evidence": "invented line"},
                {"task": "T3", "choice": "none"},
                {"task": "T9", "choice": "C1"},  # unknown task: ignored
                {"task": "T1", "choice": "C7"},  # unknown option: ignored
            ]
        }
    )
    c, f = client(tmp_path, [ans])
    out, rep = choose(c, [task("A"), task("B"), task("C")], batch_size=10)
    assert rep["requests"] == 1 and rep["answered"] == 3 and len(f.prompts) == 1
    assert out["A"].symbol == "A.pkg.patched" and out["A"].evidence_found
    assert out["A"].ranked == ["A.pkg.patched", "A.pkg.other2"]
    assert out["B"].symbol == "B.pkg.other2" and not out["B"].evidence_found
    assert out["C"].symbol is None
    assert out["A"].model == "a:free" and out["A"].prompt_hash


def test_skipped_tasks_are_retried_in_a_later_request(tmp_path: Path) -> None:
    first = json.dumps({"results": [{"task": "T1", "choice": "C1"}]})
    second = json.dumps({"results": [{"task": "T1", "choice": "C2"}]})
    c, f = client(tmp_path, [first, second])
    out, rep = choose(c, [task("A"), task("B")], batch_size=10)
    assert rep["requests"] == 2 and out["B"].symbol == "B.pkg.other2"
    assert "Advisory B" in f.prompts[1] and "Advisory A" not in f.prompts[1]


def test_batches_split_by_size_and_a_request_cap_stops_cleanly(tmp_path: Path) -> None:
    ans = json.dumps({"results": [{"task": f"T{i}", "choice": "C1"} for i in range(1, 4)]})
    c, _ = client(tmp_path, [ans, ans, ans])
    out, rep = choose(c, [task(x) for x in "ABCDEFG"], batch_size=3, max_requests=2)
    assert rep["requests"] == 2 and rep["stopped"] == "max_requests" and len(out) == 6


def test_a_budget_stop_keeps_what_was_answered(tmp_path: Path) -> None:
    ans = json.dumps({"results": [{"task": "T1", "choice": "C1"}]})
    c, _ = client(tmp_path, [ans, ans], daily_limit=2, reserve=1)
    out, rep = choose(c, [task("A"), task("B")], batch_size=1)
    assert list(out) == ["A"] and rep["stopped"].startswith("budget")


def test_prompt_lists_ids_symbols_and_excerpts() -> None:
    m = messages_for([task("A", 3)])
    assert m[0]["role"] == "system" and "option ids" in m[0]["content"]
    assert "[C1] A.pkg.patched" in m[1]["content"] and "[C3] A.pkg.other3" in m[1]["content"]
    assert "scheme.startswith('https')" in m[1]["content"]


def test_answers_are_reused_under_a_different_batching(tmp_path: Path) -> None:
    ans = json.dumps({"results": [{"task": f"T{i}", "choice": "C1"} for i in range(1, 5)]})
    c, f = client(tmp_path, [ans])
    tasks = [task(x) for x in "ABCD"]
    out, rep = choose(c, tasks, batch_size=4)
    assert rep["requests"] == 1 and len(out) == 4
    # a different batch size and order would change every prompt: the per-task cache still hits
    again, rep2 = choose(c, list(reversed(tasks)), batch_size=1)
    assert rep2["requests"] == 0 and rep2["task_cache_hits"] == 4 and len(again) == 4
    assert again["A"].symbol == "A.pkg.patched" and again["A"].cached
    assert len(f.prompts) == 1


def test_a_failed_batch_is_split_and_the_good_half_is_kept(tmp_path: Path) -> None:
    good = json.dumps({"results": [{"task": "T1", "choice": "C1"}, {"task": "T2", "choice": "C1"}]})
    c, f = client(tmp_path, ["", good, "", "", ""], max_attempts=1)  # C and D loop, even alone
    out, rep = choose(c, [task(x) for x in "ABCD"], batch_size=4, max_requests=10)
    assert rep["split"] >= 1 and rep["failed"] >= 1
    assert set(out) == {"A", "B"}  # the first half answered; the second half looped alone
    assert len(f.prompts) == 5  # whole, A+B, C+D, C, D


def test_legacy_whole_reply_cache_is_split_into_task_entries(tmp_path: Path) -> None:
    from scgraph.symbols.select import ingest_legacy, task_key

    ans = json.dumps({"results": [{"task": "T1", "choice": "C1"}, {"task": "T2", "choice": "C2"}]})
    c, _ = client(tmp_path, [ans])
    tasks = [task("A"), task("B")]
    choose(c, tasks, batch_size=2)
    for t in tasks:  # forget the per-task entries; only the old whole-reply cache remains
        c._task_path(task_key(t)).unlink()
    assert ingest_legacy(c) == 2
    out, rep = choose(c, [tasks[1], tasks[0]], batch_size=1)
    assert rep["requests"] == 0 and out["B"].symbol == "B.pkg.other2"
