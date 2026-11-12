"""Build the inferred-symbol dataset for PyPI or npm advisories.

    python scripts/symbols/build_dataset.py --ecosystem pypi --popular 2000 --fix 600 --search 100
    python scripts/symbols/build_dataset.py --ecosystem npm  --popular 1500 --fix 400 --search 60
    ... --llm-requests 6        # spend at most this many free-tier requests, most-downloaded first

1. select advisories (MAL- records and withdrawn ones skipped, GHSA / PYSEC / CVE duplicates of
   one issue merged): of the most downloaded packages with ``--popular``, else the newest
2. prepare each in parallel (fix diff or code search, both releases; no model)
3. send the uncertain ones to the LLM together, at most ``--llm-requests`` requests; answers
   already paid for come from the per-task cache and cost nothing
4. verify against released source, add entry points, write the dataset and a build report

The dataset lands in ``src/scgraph/symbols/data/<ecosystem>.jsonl`` (packaged, read offline by
``scgraph scan --reachability``); the report in ``results/metrics/symbols_<ecosystem>_build.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

from scgraph.symbols.dataset import write
from scgraph.symbols.fetch import Fetcher, fix_refs
from scgraph.symbols.pipeline import Prepared, finalize, prepare, task_for
from scgraph.symbols.select import choose

ROOT = Path(__file__).resolve().parents[2]
TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
OSV_NAME = {"pypi": "PyPI", "npm": "npm"}


def norm(name: str, eco: str = "pypi") -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name


def pypi_rank(fetcher: Fetcher, top: int, candidates: set[str]) -> dict[str, int]:
    """Package -> download rank (1 = most downloaded) from the public top-packages list."""
    d = fetcher.json(TOP_PYPI) or {}
    return {r["project"]: i for i, r in enumerate((d.get("rows") or [])[:top], 1)}


def npm_rank(fetcher: Fetcher, top: int, candidates: set[str]) -> dict[str, int]:
    """Package -> rank by last-month downloads, for the packages that have advisories. The
    npm API takes up to 128 unscoped names per call; scoped names are asked one by one."""
    counts: dict[str, int] = {}
    plain = sorted(c for c in candidates if not c.startswith("@"))
    for i in range(0, len(plain), 100):
        chunk = plain[i : i + 100]
        d = fetcher.json(
            "https://api.npmjs.org/downloads/point/last-month/"
            + ",".join(quote(c, safe="") for c in chunk)
        )
        if isinstance(d, dict):
            if "downloads" in d and len(chunk) == 1:  # a single name answers without the map
                counts[chunk[0]] = int(d["downloads"])
            for k, v in d.items():
                if isinstance(v, dict) and "downloads" in v:
                    counts[k] = int(v["downloads"])
    for c in sorted(c for c in candidates if c.startswith("@"))[:400]:
        d = fetcher.json(f"https://api.npmjs.org/downloads/point/last-month/{quote(c, safe='@')}")
        if isinstance(d, dict) and "downloads" in d:
            counts[c] = int(d["downloads"])
    ranked = sorted(counts, key=lambda k: -counts[k])[:top]
    return {k: i for i, k in enumerate(ranked, 1)}


def select(
    osv_zip: Path,
    eco: str,
    n_fix: int,
    n_search: int,
    rank_fn=None,
    top: int = 0,
    fetcher: Fetcher | None = None,
) -> tuple[list[tuple[dict, str]], dict[str, int]]:
    """Advisories to build records for. Without ``top``: the newest. With it: advisories of the
    most downloaded packages (package rank first, then newest), because real projects pin
    popular packages, often at old versions, and the newest advisories do not cover them."""
    groups: dict[str, dict] = {}
    with zipfile.ZipFile(osv_zip) as z:
        for name in z.namelist():
            r = json.loads(z.read(name))
            if r.get("withdrawn") or r["id"].startswith("MAL-"):
                continue
            pkgs = [
                (a.get("package") or {}).get("name")
                for a in r.get("affected") or []
                if (a.get("package") or {}).get("ecosystem") == OSV_NAME[eco]
            ]
            if not pkgs or not pkgs[0]:
                continue
            ids = sorted({r["id"], *r.get("aliases", [])})
            key = next((i for i in ids if i.startswith("CVE-")), r["id"]) + "|" + pkgs[0].lower()
            cur = groups.get(key)
            score = (len(fix_refs(r)), r["id"].startswith("GHSA"))  # most fix links, then GHSA
            if cur is None or score > cur["score"]:
                groups[key] = {"record": r, "package": pkgs[0], "score": score}
    rank: dict[str, int] = {}
    if top and rank_fn is not None and fetcher is not None:
        with_fix = {g["package"] for g in groups.values() if g["score"][0] > 0}
        rank = rank_fn(
            fetcher, top, {norm(p, eco) for p in with_fix} if eco == "pypi" else with_fix
        )
        groups = {k: g for k, g in groups.items() if norm(g["package"], eco) in rank}
    rows = sorted(groups.values(), key=lambda g: g["record"].get("published", ""), reverse=True)
    if rank:  # stable: package rank first, newest first within a package
        rows.sort(key=lambda g: rank[norm(g["package"], eco)])
    with_fix_rows = [g for g in rows if g["score"][0] > 0][:n_fix]
    without = [g for g in rows if g["score"][0] == 0][:n_search]
    return [(g["record"], g["package"]) for g in with_fix_rows + without], rank


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    ap.add_argument("--osv", help="OSV all.zip (default: data/raw/osv/<ecosystem>.zip)")
    ap.add_argument("--fix", type=int, default=200)
    ap.add_argument("--search", type=int, default=50)
    ap.add_argument(
        "--popular",
        type=int,
        default=0,
        metavar="N",
        help="only advisories of the N most downloaded packages, most downloaded first",
    )
    ap.add_argument("--llm-requests", type=int, default=0)
    ap.add_argument("--llm-batch", type=int, default=6)
    ap.add_argument("--uncertain", type=float, default=0.25)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument(
        "--merge",
        action="store_true",
        help="keep existing records for advisories this run did not select",
    )
    ap.add_argument(
        "--search-needs-llm",
        action="store_true",
        help="keep a code-search record only when the LLM confirmed it",
    )
    ap.add_argument("--out", help="default: src/scgraph/symbols/data/<ecosystem>.jsonl")
    a = ap.parse_args()
    eco = a.ecosystem
    osv = Path(a.osv or ROOT / f"data/raw/osv/{eco}.zip")
    out_path = Path(a.out or ROOT / f"src/scgraph/symbols/data/{eco}.jsonl")

    f = Fetcher()
    rank_fn = pypi_rank if eco == "pypi" else npm_rank
    chosen, rank = select(osv, eco, a.fix, a.search, rank_fn, a.popular, f)
    print(f"{len(chosen)} advisories selected", flush=True)
    preps: list[Prepared] = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(prepare, r, OSV_NAME[eco], pkg, f): r["id"] for r, pkg in chosen}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                preps.append(fut.result())
            except Exception as e:  # a broken release must not stop the build
                print(f"{futs[fut]}: {type(e).__name__}: {e}", file=sys.stderr)
            if i % 25 == 0:
                print(f"prepared {i}/{len(chosen)} ({f.requests_made} HTTP requests)", flush=True)

    asked = [p for p in preps if p.mode != "none" and p.margin() < a.uncertain]
    # most downloaded packages first, then code-search records, then the smallest margins
    asked.sort(
        key=lambda p: (
            rank.get(norm(p.package, eco), 10**6) if rank else 0,
            p.mode != "search",
            p.margin(),
            p.id,
        )
    )
    choices: dict = {}
    llm_report: dict = {"requests": 0, "tasks": len(asked)}
    if (a.llm_requests > 0 or asked) and asked:
        from scgraph.symbols.llm import OpenRouter

        client = OpenRouter(offline=a.llm_requests <= 0)  # no budget: replay the cache only
        print(
            f"LLM: {len(asked)} uncertain advisories, {client.remaining()} requests left today",
            flush=True,
        )
        tasks = [t for t in (task_for(p) for p in asked) if t is not None]
        choices, llm_report = choose(
            client,
            tasks,
            batch_size=a.llm_batch,
            max_requests=max(a.llm_requests, 0) or None,
            log=lambda m: print(m, flush=True),
        )

    records = []
    reasons: Counter[str] = Counter()
    statuses: Counter[str] = Counter()

    def one(p: Prepared):
        """Verify one advisory. It can download other affected releases, so it runs in a pool."""
        if p.mode == "none":
            return p, "none", None
        try:
            return p, "ok", finalize(p, choices.get(p.id))
        except Exception as e:  # one broken release must not stop the build
            return p, f"error: {type(e).__name__}", None

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(one, p) for p in preps]
        for i, fut in enumerate(as_completed(futs), 1):
            p, state, rec = fut.result()
            if state == "none":
                reasons[p.reason.split(";")[0]] += 1
            elif state != "ok":
                reasons[state] += 1
            elif rec is not None and a.search_needs_llm and rec.method == "search":
                reasons["search: not confirmed by the LLM"] += 1
            elif rec is None:
                reasons[f"{p.mode}: no candidate verified"] += 1
            else:
                statuses[rec.verified] += 1
                records.append(rec.to_dict())
            if i % 50 == 0:
                print(f"verified {i}/{len(preps)} ({len(records)} records)", flush=True)

    if a.merge and out_path.exists():
        from scgraph.symbols.dataset import load

        mine = {r["id"] for r in records} | {p.id for p in preps}
        records += [r for r in load(out_path).rows if r["id"] not in mine]
    manifest = write(records, out_path, generator="scripts/symbols/build_dataset.py")
    by_method = Counter(r["method"] for r in records)
    report = {
        "ecosystem": eco,
        "generated": time.strftime("%Y-%m-%d"),
        "selected": len(chosen),
        "selected_with_fix_link": sum(bool(fix_refs(r)) for r, _ in chosen),
        "packages": len({norm(p, eco) for _, p in chosen}),
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
    (ROOT / f"results/metrics/symbols_{eco}_build.json").write_text(
        json.dumps(report, indent=1) + "\n"
    )
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
