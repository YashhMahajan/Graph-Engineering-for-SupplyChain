"""Build the Go evaluation set: advisories whose symbols are labelled and whose fix is linked.

The Go vulnerability database is the only large source of advisory -> vulnerable-symbol labels.
Each row keeps the record, the gold (package path, symbol) pairs and the publication date; the
split is temporal (oldest 70% train, newest 30% test) so nothing learned from the future leaks
into the past.

    python scripts/symbols/go_eval_set.py              # writes data/symbols/go_eval.jsonl
    python scripts/symbols/go_eval_set.py --prefetch   # also caches every fix diff and file
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scgraph.symbols.fetch import Fetcher, fix_refs
from scgraph.symbols.fixcommit import engine_a

ROOT = Path(__file__).resolve().parents[2]


def rows(osv_zip: Path) -> list[dict]:
    out = []
    with zipfile.ZipFile(osv_zip) as z:
        for name in z.namelist():
            r = json.loads(z.read(name))
            if r.get("withdrawn"):
                continue
            gold = []
            modules = []
            for a in r.get("affected") or []:
                pkg = (a.get("package") or {}).get("name") or ""
                if pkg in ("stdlib", "toolchain"):
                    continue
                modules.append(pkg)
                for imp in (a.get("ecosystem_specific") or {}).get("imports") or []:
                    for s in imp.get("symbols") or []:
                        gold.append([imp.get("path") or pkg, s])
            if not gold or not modules or not fix_refs(r):
                continue
            out.append(
                {
                    "id": r["id"],
                    "published": r.get("published", ""),
                    "module": modules[0],
                    "gold": gold,
                    "record": r,
                }
            )
    out.sort(key=lambda x: (x["published"], x["id"]))
    cut = int(len(out) * 0.7)
    for i, x in enumerate(out):
        x["split"] = "train" if i < cut else "test"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv", default=str(ROOT / "data/raw/osv/go.zip"))
    ap.add_argument("--out", default=str(ROOT / "data/symbols/go_eval.jsonl"))
    ap.add_argument("--prefetch", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    data = rows(Path(a.osv))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with Path(a.out).open("w") as f:
        for x in data:
            f.write(json.dumps(x, sort_keys=True) + "\n")
    n_train = sum(x["split"] == "train" for x in data)
    print(f"{len(data)} advisories ({n_train} train, {len(data) - n_train} test) -> {a.out}")
    if not a.prefetch:
        return 0
    fetcher = Fetcher()
    done = ok = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(engine_a, x["record"], fetcher, x["module"], 2): x for x in data}
        for fut in as_completed(futs):
            done += 1
            try:
                ok += fut.result().cands is not None
            except Exception as e:  # keep going; the evaluation reports the gap
                print(f"{futs[fut]['id']}: {type(e).__name__}: {e}", file=sys.stderr)
            if done % 50 == 0:
                print(
                    f"{done}/{len(data)} fetched, {ok} with candidates, "
                    f"{fetcher.requests_made} HTTP requests",
                    flush=True,
                )
    print(f"done: {ok}/{len(data)} with candidates, {fetcher.requests_made} HTTP requests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
