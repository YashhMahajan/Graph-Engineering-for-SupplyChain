"""How well does (top symbol + its entry points) reproduce the Go database's symbol set?

Reachability matches project code against the whole set, so set recall is what decides
whether a real call is seen. Offline: needs the fix-diff and release caches.

    python scripts/symbols/eval_entry.py      # writes results/metrics/symbols_entry.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from scgraph.symbols.entry import entry_points
from scgraph.symbols.evaluate import match
from scgraph.symbols.fetch import Fetcher
from scgraph.symbols.fixcommit import engine_a
from scgraph.symbols.rank import HEURISTIC, Ranker, rank
from scgraph.symbols.source import bracket, go_release, go_versions

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args()
    rows = [
        json.loads(line) for line in (ROOT / "data/symbols/go_eval.jsonl").read_text().splitlines()
    ]
    test = [r for r in rows if r["split"] == "test"]
    f = Fetcher(offline=True)
    heur = Ranker(weights=dict(HEURISTIC))
    n = with_rel = 0
    rec_top, rec_set, prec_set, any_top, any_set, sizes = [], [], [], 0, 0, []
    for x in test:
        n += 1
        res = engine_a(x["record"], f, x["module"], workers=1)
        if not res.cands:
            rec_top.append(0.0)
            rec_set.append(0.0)
            continue
        best = rank(res.cands.candidates, heur)[0]
        last, _fixed = bracket(x["record"], "Go", x["module"], go_versions(f, x["module"]))
        rel = go_release(f, x["module"], last) if last else None
        gold = x["gold"]
        top = [(best.module, best.qualname)]
        hit_top = [g for g in gold if match(top[0], [g])]
        rec_top.append(len(hit_top) / len(gold))
        any_top += bool(hit_top)
        if rel is None:
            rec_set.append(rec_top[-1])
            any_set += bool(hit_top)
            continue
        with_rel += 1
        eps = entry_points(rel, best.module, best.qualname, depth=a.depth, cap=150)
        pred = top + [p for p in eps if p != top[0]]
        sizes.append(len(pred))
        covered = [g for g in gold if any(match(p, [g]) for p in pred)]
        rec_set.append(len(covered) / len(gold))
        prec_set.append(sum(any(match(p, [g]) for g in gold) for p in pred) / len(pred))
        any_set += bool(covered)
    out = {
        "n_test": n,
        "with_affected_release": with_rel,
        "ranker": "heuristic (chosen on validation)",
        "depth": a.depth,
        "gold_symbol_recall": {
            "top_symbol_only": round(sum(rec_top) / n, 4),
            "top_symbol_plus_entry_points": round(sum(rec_set) / n, 4),
        },
        "any_gold_symbol_hit": {
            "top_symbol_only": round(any_top / n, 4),
            "top_symbol_plus_entry_points": round(any_set / n, 4),
        },
        "set_precision_mean": round(sum(prec_set) / max(1, len(prec_set)), 4),
        "set_size_median": sorted(sizes)[len(sizes) // 2] if sizes else 0,
        "generated": time.strftime("%Y-%m-%d"),
    }
    if not a.no_write:
        (ROOT / "results/metrics/symbols_entry.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
