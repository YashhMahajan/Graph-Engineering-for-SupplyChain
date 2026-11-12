"""Engine B: no fix link, so search the affected release for the function the advisory means.

This is the retrieval step of retrieval-augmented generation, done over code instead of
documents. Each function of the last affected release becomes a document (its name tokens,
weighted three times, its module path, docstring and body identifiers), and the advisory
text is the query, scored with BM25. A second, model-free signal comes from the releases
themselves: a function that changed between the last affected and the first fixed version
is much more likely to be the fix site. The LLM then re-ranks a short list and may answer
"none"; the verifier still decides.
"""

from __future__ import annotations

import math
import sys
from collections import Counter
from dataclasses import dataclass

from .candidates import _advisory_tokens
from .code import Func, identifier_tokens
from .source import Release
from .verify import release_diff

__all__ = ["FunctionIndex", "Hit", "engine_b_eval", "search"]

_K1, _B = 1.2, 0.75


@dataclass
class Hit:
    module: str
    path: str
    func: Func
    bm25: float
    changed: bool
    score: float = 0.0
    rank: int = 0

    @property
    def symbol(self) -> str:
        return f"{self.module}.{self.func.qualname}"

    def excerpt(self, release: Release, max_lines: int = 25) -> str:
        lines = release.files.get(self.path, "").splitlines()[self.func.start - 1 : self.func.end]
        if len(lines) > max_lines:
            lines = [*lines[:max_lines], "..."]
        return "\n".join(lines)


class FunctionIndex:
    def __init__(self, release: Release):
        self.release = release
        self.items: list[tuple[str, str, Func]] = release.functions()
        self.tf: list[Counter[str]] = []
        self.len: list[int] = []
        df: Counter[str] = Counter()
        for mod, path, f in self.items:
            body = release.files.get(path, "").splitlines()[f.start - 1 : min(f.end, f.start + 60)]
            toks = identifier_tokens(f.qualname) * 3
            toks += identifier_tokens(mod.replace("/", ".").split(".", 2)[-1])
            toks += identifier_tokens(f.doc)
            toks += identifier_tokens(" ".join(body))
            c = Counter(t for t in toks if len(t) > 2)
            self.tf.append(c)
            self.len.append(sum(c.values()))
            df.update(c.keys())
        n = max(1, len(self.items))
        self.idf = {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}
        self.avg = sum(self.len) / n if self.len else 1.0

    def scores(self, query: set[str]) -> list[float]:
        out = []
        for c, ln in zip(self.tf, self.len):
            s = 0.0
            for t in query:
                f = c.get(t)
                if f:
                    s += self.idf[t] * f * (_K1 + 1) / (f + _K1 * (1 - _B + _B * ln / self.avg))
            out.append(s)
        return out


def search(
    text: str, affected: Release, fixed: Release | None = None, k: int = 8
) -> tuple[list[Hit], dict]:
    """The top ``k`` functions for the advisory ``text``, and what the search saw."""
    idx = FunctionIndex(affected)
    q = _advisory_tokens(text)
    bm = idx.scores(q)
    diff = release_diff(affected, fixed) if fixed is not None else set()
    n_changed = len(diff)
    # a small release diff is a strong signal; a major release changes too much to trust
    w = 0.0 if not diff else 1.0 if n_changed <= 50 else 0.5 if n_changed <= 300 else 0.2
    top = max(bm) if bm else 0.0
    hits = []
    for (mod, path, f), s in zip(idx.items, bm):
        ch = (mod, f.qualname) in diff
        if s <= 0 and not ch:
            continue
        norm = s / top if top > 0 else 0.0
        hits.append(Hit(mod, path, f, s, ch, norm + w * ch + 0.1 * f.public))
    hits.sort(key=lambda h: (-h.score, h.symbol))
    for i, h in enumerate(hits, 1):
        h.rank = i
    return hits[:k], {"functions": len(idx.items), "release_diff": n_changed, "query_terms": len(q)}


def engine_b_eval(sample: list[dict], llm_requests: int = 0, k: int = 8, log=None) -> dict:
    """Engine B on Go advisories as if no fix link existed (the cache must hold releases)."""
    from .evaluate import match, metrics
    from .fetch import Fetcher
    from .fixcommit import advisory_text
    from .source import bracket, go_release, go_versions

    f = Fetcher(offline=True)
    prepared = []
    for x in sample:
        mod = x["module"]
        last, fixed = bracket(x["record"], "Go", mod, go_versions(f, mod))
        aff = go_release(f, mod, last) if last else None
        fix = go_release(f, mod, fixed) if fixed else None
        hits, info = search(advisory_text(x["record"]), aff, fix, k=k) if aff else ([], {})
        prepared.append((x, aff, hits, info))
    golds = [x["gold"] for x, *_ in prepared]
    bm25_only = [
        [(h.module, h.func.qualname) for h in sorted(hits, key=lambda h: -h.bm25)]
        for _, _, hits, _ in prepared
    ]
    combined = [[(h.module, h.func.qualname) for h in hits] for _, _, hits, _ in prepared]
    out: dict = {
        "n": len(sample),
        "with_releases": sum(a is not None for _, a, _, _ in prepared),
        "k": k,
        "bm25": metrics(bm25_only, golds).as_dict(),
        "bm25+release_diff": metrics(combined, golds).as_dict(),
    }
    if llm_requests > 0:
        from .llm import OpenRouter
        from .select import Option, Task, choose

        tasks = []
        for x, aff, hits, _ in prepared:
            if not hits or aff is None:
                continue
            opts = [
                Option(
                    f"C{i}",
                    h.symbol,
                    f"search rank {h.rank}, {'changed' if h.changed else 'unchanged'} in the "
                    f"fixed release, {'public' if h.func.public else 'private'}",
                    h.excerpt(aff),
                )
                for i, h in enumerate(hits, 1)
            ]
            tasks.append(
                Task(x["id"], x["module"], advisory_text(x["record"]), opts, mode="search")
            )
        choices, rep = choose(
            OpenRouter(),
            tasks,
            batch_size=8,
            max_requests=llm_requests,
            log=log or (lambda m: print(m, file=sys.stderr)),
        )
        reranked = []
        for (x, _aff, hits, _), base in zip(prepared, combined):
            ch = choices.get(x["id"])
            if ch is None:
                reranked.append(base)
                continue
            by = {h.symbol: (h.module, h.func.qualname) for h in hits}
            front = [by[s] for s in ch.ranked if s in by]
            reranked.append(
                front
                if ch.symbol is None and not front
                else front + [p for p in base if p not in front]
            )
        answered = [x for x, *_ in prepared if x["id"] in choices]
        out["bm25+release_diff+llm"] = metrics(reranked, golds).as_dict()
        out["llm"] = {
            **rep,
            "answered_none": sum(c.symbol is None for c in choices.values()),
            "none_when_gold_missing": sum(
                1
                for x, _a, hits, _ in prepared
                if x["id"] in choices
                and choices[x["id"]].symbol is None
                and not any(match((h.module, h.func.qualname), x["gold"]) for h in hits)
            ),
            "answered_ids": len(answered),
        }
    return out
