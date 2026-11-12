"""Build the inferred-symbol dataset for PyPI advisories.

    python scripts/symbols/build_pypi.py --fix 200 --search 50 --llm-requests 12

1. select the newest advisories (MAL- records and withdrawn ones skipped, GHSA / PYSEC / CVE
   duplicates of one issue merged), ``--fix`` of them with a linked fix, ``--search`` without
2. prepare each in parallel (fix diff or code search, both releases; no model)
3. send the uncertain ones to the LLM together, six per request, at most ``--llm-requests``
4. verify against released source, add entry points, write the dataset and a build report

The dataset lands in ``src/scgraph/symbols/data/pypi.jsonl`` (packaged, read offline by
``scgraph scan --reachability``); the report in ``results/metrics/symbols_pypi_build.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scgraph.symbols.dataset import write
from scgraph.symbols.fetch import Fetcher, fix_refs
from scgraph.symbols.pipeline import Prepared, finalize, prepare, task_for
from scgraph.symbols.select import choose

ROOT = Path(__file__).resolve().parents[2]


def select(osv_zip: Path, n_fix: int, n_search: int) -> list[tuple[dict, str]]:
    groups: dict[str, dict] = {}
    with zipfile.ZipFile(osv_zip) as z:
        for name in z.namelist():
            r = json.loads(z.read(name))
            if r.get("withdrawn") or r["id"].startswith("MAL-"):
                continue
            pkgs = [
                (a.get("package") or {}).get("name")
                for a in r.get("affected") or []
                if (a.get("package") or {}).get("ecosystem") == "PyPI"
            ]
            if not pkgs or not pkgs[0]:
                continue
            ids = sorted({r["id"], *r.get("aliases", [])})
            key = next((i for i in ids if i.startswith("CVE-")), r["id"]) + "|" + pkgs[0].lower()
            cur = groups.get(key)
            # keep the record with the most fix links, then the GHSA one
            score = (len(fix_refs(r)), r["id"].startswith("GHSA"))
            if cur is None or score > cur["score"]:
                groups[key] = {"record": r, "package": pkgs[0], "score": score}
    rows = sorted(groups.values(), key=lambda g: g["record"].get("published", ""), reverse=True)
    with_fix = [g for g in rows if g["score"][0] > 0][:n_fix]
    without = [g for g in rows if g["score"][0] == 0][:n_search]
    return [(g["record"], g["package"]) for g in with_fix + without]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv", default=str(ROOT / "data/raw/osv/pypi.zip"))
    ap.add_argument("--fix", type=int, default=200)
    ap.add_argument("--search", type=int, default=50)
    ap.add_argument("--llm-requests", type=int, default=0)
    ap.add_argument("--llm-batch", type=int, default=6)
    ap.add_argument("--uncertain", type=float, default=0.25)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument(
        "--search-needs-llm",
        action="store_true",
        help="keep a code-search record only when the LLM confirmed it",
    )
    ap.add_argument("--out", default=str(ROOT / "src/scgraph/symbols/data/pypi.jsonl"))
    a = ap.parse_args()

    chosen = select(Path(a.osv), a.fix, a.search)
    print(f"{len(chosen)} advisories selected", flush=True)
    f = Fetcher()
    preps: list[Prepared] = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(prepare, r, "PyPI", pkg, f): r["id"] for r, pkg in chosen}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                preps.append(fut.result())
            except Exception as e:  # a broken release must not stop the build
                print(f"{futs[fut]}: {type(e).__name__}: {e}", file=sys.stderr)
            if i % 25 == 0:
                print(f"prepared {i}/{len(chosen)} ({f.requests_made} HTTP requests)", flush=True)

    asked = [p for p in preps if p.mode != "none" and p.margin() < a.uncertain]
    # the riskiest first: code-search records, then the smallest ranker margins
    asked.sort(key=lambda p: (p.mode != "search", p.margin(), p.id))
    choices: dict = {}
    llm_report: dict = {"requests": 0, "tasks": len(asked)}
    if a.llm_requests > 0 and asked:
        from scgraph.symbols.llm import OpenRouter

        client = OpenRouter()
        print(
            f"LLM: {len(asked)} uncertain advisories, {client.remaining()} requests left today",
            flush=True,
        )
        tasks = [t for t in (task_for(p) for p in asked) if t is not None]
        choices, llm_report = choose(
            client,
            tasks,
            batch_size=a.llm_batch,
            max_requests=a.llm_requests,
            log=lambda m: print(m, flush=True),
        )

    records = []
    reasons: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    for p in preps:
        if p.mode == "none":
            reasons[p.reason.split(";")[0]] += 1
            continue
        rec = finalize(p, choices.get(p.id))
        if rec is not None and a.search_needs_llm and rec.method == "search":
            reasons["search: not confirmed by the LLM"] += 1
            continue
        if rec is None:
            reasons[f"{p.mode}: no candidate verified"] += 1
            continue
        statuses[rec.verified] += 1
        records.append(rec.to_dict())

    manifest = write(records, Path(a.out), generator="scripts/symbols/build_pypi.py")
    by_method = Counter(r["method"] for r in records)
    report = {
        "generated": time.strftime("%Y-%m-%d"),
        "selected": len(chosen),
        "selected_with_fix_link": sum(bool(fix_refs(r)) for r, _ in chosen),
        "prepared": {m: sum(p.mode == m for p in preps) for m in ("fix", "search", "none")},
        "records": len(records),
        "by_method": dict(by_method),
        "verifier": dict(statuses),
        "abstained": dict(reasons.most_common()),
        "with_entry_points": sum(bool(r["entry_points"]) for r in records),
        "llm": {**llm_report, "answered": len(choices)},
        "search_needs_llm": a.search_needs_llm,
        "manifest": manifest,
    }
    out = ROOT / "results/metrics/symbols_pypi_build.json"
    out.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
