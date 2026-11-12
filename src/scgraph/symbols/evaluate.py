"""Scoring symbol predictions against labelled advisories (the Go vulnerability database).

A prediction is a ranked list of (package path, symbol). It is correct at rank k when one of
the first k items matches a gold pair. Go labels list both the patched function and the
exported functions that reach it, so a match against either counts; the report also gives the
share of advisories whose gold set contains a function the fix itself changed.

Every rate is reported over *all* advisories in the split, so an advisory with no fix diff or
no candidates counts as a miss, never as an exclusion.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = ["Metrics", "match", "metrics", "pkg_match"]


def pkg_match(pred_pkg: str, gold_pkg: str) -> bool:
    """Exact package path, or the same final directory (repositories whose module root is
    not the repository root shift the prefix but not the package directory)."""
    if pred_pkg == gold_pkg:
        return True
    a, b = _strip_major(pred_pkg), _strip_major(gold_pkg)
    return a == b or posixpath.basename(a) == posixpath.basename(b)


_MAJOR = re.compile(r"/v\d+(?=/|$)")


def _strip_major(pkg: str) -> str:
    """``github.com/x/y/v2/sub`` -> ``github.com/x/y/sub`` (Go major-version suffixes)."""
    return _MAJOR.sub("", pkg)


def match(pred: tuple[str, str], gold: Sequence[Sequence[str]]) -> bool:
    pkg, sym = pred
    return any(sym == g[1] and pkg_match(pkg, g[0]) for g in gold)


@dataclass
class Metrics:
    n: int
    top1: float
    top3: float
    mrr: float
    abstain: float  # share with no prediction at all
    coverage: float  # share where some candidate matches (the ceiling for any ranker)

    def as_dict(self) -> dict:
        return {k: round(v, 4) if isinstance(v, float) else v for k, v in vars(self).items()}


def metrics(
    preds: Sequence[Sequence[tuple[str, str]]],
    golds: Sequence[Sequence[Sequence[str]]],
    pools: Sequence[Sequence[tuple[str, str]]] | None = None,
) -> Metrics:
    """``preds[i]`` ranked predictions for advisory i (empty = abstain), ``golds[i]`` its
    gold pairs, ``pools[i]`` every candidate considered (for the coverage ceiling)."""
    n = len(golds)
    if n == 0:
        return Metrics(0, 0.0, 0.0, 0.0, 0.0, 0.0)
    t1 = t3 = 0
    rr = 0.0
    ab = 0
    cov = 0
    for i, gold in enumerate(golds):
        p = list(preds[i])
        if not p:
            ab += 1
        hit = next((r for r, x in enumerate(p, 1) if match(x, gold)), None)
        if hit is not None:
            t1 += hit == 1
            t3 += hit <= 3
            rr += 1.0 / hit
        pool = pools[i] if pools is not None else p
        cov += any(match(x, gold) for x in pool)
    return Metrics(n, t1 / n, t3 / n, rr / n, ab / n, cov / n)
