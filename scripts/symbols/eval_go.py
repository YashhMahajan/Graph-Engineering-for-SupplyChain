"""Evaluate vulnerable-symbol inference on the Go vulnerability database (temporal split).

Stages, each reported separately so the gain of every step is measured:

  largest      rank changed functions by changed lines (the obvious baseline, no learning)
  heuristic    the hand-set ranker weights
  ranker       logistic regression trained on the train split (saved as the packaged model)
  ranker+llm   the LLM chooses among the ranker's top candidates where the ranker is unsure
               (spends free-tier requests; capped by --llm-requests, cached for re-runs)
  search       Engine B: no fix diff; BM25 over the affected release's functions plus the
               release diff, optionally re-ranked by the LLM (--engine-b N advisories)

    python scripts/symbols/eval_go.py                       # model-free stages, offline
    python scripts/symbols/eval_go.py --llm-requests 12     # adds ranker+llm on the test split
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

from scgraph.symbols.evaluate import match, metrics
from scgraph.symbols.fetch import Fetcher
from scgraph.symbols.fixcommit import engine_a
from scgraph.symbols.rank import HEURISTIC, Ranker, rank, save

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/metrics/symbols_eval.json"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pairs(cands) -> list[tuple[str, str]]:
    return [(c.module, c.qualname) for c in cands]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default=str(ROOT / "data/symbols/go_eval.jsonl"))
    ap.add_argument("--llm-requests", type=int, default=0)
    ap.add_argument("--llm-top", type=int, default=6)
    ap.add_argument("--llm-batch", type=int, default=10)
    ap.add_argument(
        "--uncertain",
        type=float,
        default=0.25,
        help="ask the LLM when the top-2 score margin is below this",
    )
    ap.add_argument("--engine-b", type=int, default=0, help="Engine B on N test advisories")
    ap.add_argument("--engine-b-llm-requests", type=int, default=0)
    ap.add_argument("--save-ranker", action="store_true")
    ap.add_argument(
        "--llm-cache-only",
        action="store_true",
        help="replay cached LLM answers only (spends nothing)",
    )
    a = ap.parse_args()

    data = load(Path(a.set))
    fetcher = Fetcher(offline=True)  # the prefetch filled the cache; no network here
    rows = []
    for x in data:
        res = engine_a(x["record"], fetcher, x["module"], workers=1)
        cands = res.cands.candidates if res.cands else []
        rows.append({"x": x, "res": res, "cands": cands})
    train = [r for r in rows if r["x"]["split"] == "train"]
    test = [r for r in rows if r["x"]["split"] == "test"]
    report: dict = {
        "dataset": "Go vulnerability database (OSV snapshot), advisories with labelled symbols "
        "and a GitHub fix commit or pull request",
        "n_train": len(train),
        "n_test": len(test),
        "split": "temporal: oldest 70% train, newest 30% test",
        "generated": time.strftime("%Y-%m-%d"),
    }

    # how often is the gold symbol among the changed functions at all? (VFArche's 26% question)
    def share(rs, pred):
        hit = [r for r in rs if r["cands"]]
        return sum(
            any(match((c.module, c.qualname), r["x"]["gold"]) for c in r["cands"] if pred(c))
            for r in hit
        ) / max(1, len(rs))

    report["candidate_coverage"] = {
        "changed_functions_only": round(share(test, lambda c: not c.via_caller), 4),
        "with_callers": round(share(test, lambda c: True), 4),
        "no_candidates": round(sum(not r["cands"] for r in test) / max(1, len(test)), 4),
    }

    stages: dict = {}

    def evaluate(rs, ordering):
        preds, golds, pools = [], [], []
        for r in rs:
            ranked = ordering(r["cands"]) if r["cands"] else []
            preds.append(pairs(ranked))
            golds.append(r["x"]["gold"])
            pools.append(pairs(r["cands"]))
        return metrics(preds, golds, pools)

    largest = lambda cs: sorted(cs, key=lambda c: (c.via_caller, -c.changed, c.qualname))  # noqa: E731
    stages["largest"] = evaluate(test, largest).as_dict()
    heur = Ranker(weights=dict(HEURISTIC))
    stages["heuristic"] = evaluate(test, lambda cs: rank(cs, heur)).as_dict()

    groups = [r["cands"] for r in train if r["cands"]]
    labels = [
        [match((c.module, c.qualname), r["x"]["gold"]) for c in r["cands"]]
        for r in train
        if r["cands"]
    ]
    learned = Ranker.fit(
        groups, labels, C=0.5, trained_on=f"go-vulndb train split, {len(groups)} advisories"
    )
    stages["ranker"] = evaluate(test, lambda cs: rank(cs, learned)).as_dict()
    stages["ranker_train_fit"] = evaluate(train, lambda cs: rank(cs, learned)).as_dict()
    report["ranker_weights"] = {
        k: round(v, 3) for k, v in sorted(learned.weights.items(), key=lambda kv: -abs(kv[1]))
    }
    # choose the ranker on a validation slice (newest 20% of train), never on the test split
    cut = int(len(train) * 0.8)
    fit_rows, val_rows = train[:cut], train[cut:]
    fit_g = [r["cands"] for r in fit_rows if r["cands"]]
    fit_l = [
        [match((c.module, c.qualname), r["x"]["gold"]) for c in r["cands"]]
        for r in fit_rows
        if r["cands"]
    ]
    val_model = Ranker.fit(fit_g, fit_l, C=0.5)
    val = {
        "heuristic": evaluate(val_rows, lambda cs: rank(cs, heur)).as_dict(),
        "ranker": evaluate(val_rows, lambda cs: rank(cs, val_model)).as_dict(),
    }
    winner = max(val, key=lambda k: (val[k]["mrr"], val[k]["top1"]))
    chosen = learned if winner == "ranker" else heur
    report["validation"] = {**val, "chosen": winner, "n": len(val_rows)}
    if a.save_ranker and winner == "ranker":
        save(learned, ROOT / "src/scgraph/symbols/ranker.json")

    if a.llm_requests > 0 or a.llm_cache_only:
        from scgraph.symbols.llm import OpenRouter
        from scgraph.symbols.pipeline import llm_rerank

        client = OpenRouter(offline=a.llm_cache_only)
        print(f"LLM budget: {client.remaining()} requests left today", file=sys.stderr)
        ranked_by = {r["x"]["id"]: rank(r["cands"], chosen) for r in test if r["cands"]}
        llm_out, llm_report, asked = llm_rerank(
            client,
            [
                (r["x"]["record"], r["res"].cands, ranked_by[r["x"]["id"]], r["x"]["module"])
                for r in test
                if r["cands"]
            ],
            top=a.llm_top,
            uncertain=a.uncertain,
            batch_size=a.llm_batch,
            max_requests=a.llm_requests or None,
            log=lambda m: print(m, file=sys.stderr),
        )

        def with_llm(cs, rid):
            base = ranked_by.get(rid, [])
            ch = llm_out.get(rid)
            if ch is None or (ch.symbol is None and not ch.ranked):
                return base
            front = [c for s in ch.ranked for c in base if c.symbol == s]
            return front + [c for c in base if c not in front]

        preds, golds, pools = [], [], []
        for r in test:
            preds.append(pairs(with_llm(r["cands"], r["x"]["id"])) if r["cands"] else [])
            golds.append(r["x"]["gold"])
            pools.append(pairs(r["cands"]))
        stages["ranker+llm"] = metrics(preds, golds, pools).as_dict()
        # the same metric restricted to the advisories the LLM was asked about
        sub = [r for r in test if r["x"]["id"] in llm_out]  # answered, not merely asked
        stages["ranker_on_llm_answered"] = evaluate(sub, lambda cs: rank(cs, chosen)).as_dict()
        sp, sg, spool = [], [], []
        for r in sub:
            sp.append(pairs(with_llm(r["cands"], r["x"]["id"])))
            sg.append(r["x"]["gold"])
            spool.append(pairs(r["cands"]))
        stages["ranker+llm_on_llm_answered"] = metrics(sp, sg, spool).as_dict()
        ev = [c for c in llm_out.values() if c.symbol]
        # paired comparison on the answered advisories: does the LLM fix or break the top pick?
        fixes = breaks = both = neither = 0
        for r in sub:
            base = ranked_by[r["x"]["id"]]
            h = match((base[0].module, base[0].qualname), r["x"]["gold"])
            top = with_llm(r["cands"], r["x"]["id"])
            m = bool(top) and match((top[0].module, top[0].qualname), r["x"]["gold"])
            fixes += m and not h
            breaks += h and not m
            both += h and m
            neither += not h and not m
        k = fixes + breaks
        tail = sum(math.comb(k, j) for j in range(max(fixes, breaks), k + 1)) / 2**k if k else 0.5
        paired = {
            "llm_fixes": fixes,
            "llm_breaks": breaks,
            "both_right": both,
            "both_wrong": neither,
            "mcnemar_exact_p": round(min(1.0, 2 * tail), 3),
        }
        report["llm"] = {
            **llm_report,
            "asked": len(asked),
            "answered_none": sum(c.symbol is None for c in llm_out.values()),
            "evidence_found_rate": round(sum(c.evidence_found for c in ev) / max(1, len(ev)), 4),
            "models": sorted({c.model for c in llm_out.values()}),
            "paired_on_answered": paired,
        }

    if a.engine_b > 0:
        from scgraph.symbols.retrieve import engine_b_eval

        sample = [r["x"] for r in test]
        random.Random(7).shuffle(sample)
        report["engine_b"] = engine_b_eval(
            sample[: a.engine_b],
            llm_requests=a.engine_b_llm_requests,
            log=lambda m: print(m, file=sys.stderr),
            cache_only=a.llm_cache_only,
        )

    report["stages"] = stages
    old = json.loads(OUT.read_text()) if OUT.exists() else {}
    for k in ("llm", "engine_b"):  # keep earlier paid results when this run skipped them
        if k not in report and k in old:
            report[k] = old[k]
    for k in ("ranker+llm", "ranker_on_llm_answered", "ranker+llm_on_llm_answered"):
        if k not in stages and k in old.get("stages", {}):
            stages[k] = old["stages"][k]
    OUT.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps({k: report[k] for k in ("candidate_coverage", "stages")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
