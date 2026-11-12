"""Cache the last affected and first fixed release of each advisory in an eval set.

python scripts/symbols/prefetch_releases.py --split test
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scgraph.symbols.fetch import Fetcher
from scgraph.symbols.source import bracket, go_release, go_versions

ROOT = Path(__file__).resolve().parents[2]


def one(f: Fetcher, x: dict) -> tuple[str, bool, bool]:
    mod = x["module"]
    last, fixed = bracket(x["record"], "Go", mod, go_versions(f, mod))
    a = bool(last) and go_release(f, mod, last) is not None
    b = bool(fixed) and go_release(f, mod, fixed) is not None
    return x["id"], a, b


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default=str(ROOT / "data/symbols/go_eval.jsonl"))
    ap.add_argument("--split", default="test")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    rows = [json.loads(line) for line in Path(a.set).read_text().splitlines()]
    rows = [r for r in rows if r["split"] == a.split]
    f = Fetcher()
    both = done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for fut in as_completed([ex.submit(one, f, r) for r in rows]):
            done += 1
            try:
                _, x, y = fut.result()
                both += x and y
            except Exception as e:
                print(f"error: {type(e).__name__}: {e}")
            if done % 25 == 0:
                print(
                    f"{done}/{len(rows)}: {both} with both releases, {f.requests_made} requests",
                    flush=True,
                )
    print(f"done: {both}/{len(rows)} with both releases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
