"""Does the static transitive analysis reach what actually runs?

Ground truth is dynamic: ``trace_scenarios.py`` runs real ``requests`` and ``flask`` code under
a profiler and records every function executed inside their dependencies. For each executed
function ``f`` of a dependency ``D`` (parent ``P``), the analysis is asked whether ``P``'s public
API reaches ``f`` (seeds: ``f`` and its entry points inside ``D``). A miss is a function that
demonstrably ran from ``P`` and that the static analysis cannot connect: a false ``not_called``.

Recall is measured on those functions. As a cost, the share of ALL of ``D``'s functions that the
analysis marks reachable is reported next to the share that actually ran. Static analysis
over-approximates what a call can reach, and one scenario exercises only part of a library, so
the second number is an upper bound on how much the analysis over-reports.

    python -m venv /tmp/evalenv && /tmp/evalenv/bin/pip install requests flask
    /tmp/evalenv/bin/python scripts/symbols/trace_scenarios.py > /tmp/traces.json
    python scripts/symbols/eval_transitive.py --env /tmp/evalenv --traces /tmp/traces.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from scgraph.symbols import features
from scgraph.symbols.entry import entry_points
from scgraph.symbols.source import Release
from scgraph.symbols.transitive import propagate

ROOT = Path(__file__).resolve().parents[2]

# (scenario, chain of top-level packages: direct dependency first, dependency last)
CHAINS = [
    ("requests", ["requests", "urllib3"]),
    ("requests", ["requests", "idna"]),
    ("requests", ["requests", "charset_normalizer"]),
    ("requests", ["requests", "certifi"]),
    ("flask", ["flask", "werkzeug"]),
    ("flask", ["flask", "jinja2"]),
    ("flask", ["flask", "click"]),
    ("flask", ["flask", "itsdangerous"]),
    ("flask", ["flask", "blinker"]),
    ("flask", ["flask", "markupsafe"]),
    ("flask", ["flask", "jinja2", "markupsafe"]),
    ("flask", ["flask", "werkzeug", "markupsafe"]),
]


def site_packages(env: Path) -> Path:
    return next((env / "lib").glob("python*/site-packages"))


def release(sp: Path, top: str) -> Release:
    files = {}
    for f in (sp / top).rglob("*.py"):
        if "tests" not in f.relative_to(sp).parts:
            files[f.relative_to(sp).as_posix()] = f.read_text(encoding="utf-8", errors="replace")
    return Release("PyPI", top, "installed", files)


def evaluate(sp: Path, traces: dict, verbose: bool = False) -> tuple[list[dict], dict]:
    rels: dict[str, Release] = {}
    rows = []
    for scenario, chain in CHAINS:
        for top in chain:
            if top not in rels:
                rels[top] = release(sp, top)
        parent_chain = [rels[t] for t in chain]
        dep = parent_chain[-1]
        executed = set()
        for f, qn in traces[scenario]:
            rel = Path(f).relative_to(sp).as_posix() if f.startswith(str(sp)) else ""
            if rel.split("/")[0] == chain[-1] and "<" not in qn:
                mod = dep.module_of(rel)
                if dep.find(mod, qn) is not None:
                    executed.add((mod, qn))
        cache: dict[tuple[str, str], bool] = {}

        def reached(mod: str, qn: str, dep=dep, chain=parent_chain, cache=cache) -> bool:
            if (mod, qn) not in cache:
                seeds = entry_points(dep, mod, qn)
                if (mod, qn) not in seeds:
                    seeds.append((mod, qn))
                cache[(mod, qn)] = propagate(chain, seeds).reached
            return cache[(mod, qn)]

        hit = sum(reached(m, q) for m, q in executed)
        allf = {(m, f.qualname) for m, _, f in dep.functions()}
        static = sum(reached(m, q) for m, q in allf)
        rows.append(
            {
                "chain": " -> ".join(chain),
                "executed_functions": len(executed),
                "reached": hit,
                "recall": round(hit / len(executed), 4) if executed else None,
                "dependency_functions": len(allf),
                "static_reached": static,
                "static_reached_share": round(static / len(allf), 4) if allf else None,
                "dynamic_executed_share": round(len(executed) / len(allf), 4) if allf else None,
            }
        )
        if verbose:
            print(rows[-1], flush=True)
    tot = sum(r["executed_functions"] for r in rows)
    hit = sum(r["reached"] for r in rows)
    allfn = sum(r["dependency_functions"] for r in rows)
    sreach = sum(r["static_reached"] for r in rows)
    return rows, {
        "executed_functions": tot,
        "reached": hit,
        "recall": round(hit / tot, 4) if tot else None,
        "dependency_functions": allfn,
        "static_reached_share": round(sreach / allfn, 4) if allfn else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--traces", required=True)
    ap.add_argument("--ablation", action="store_true", help="also turn each mechanism off in turn")
    a = ap.parse_args()
    sp = site_packages(Path(a.env))
    traces = json.loads(Path(a.traces).read_text())
    t0 = time.time()
    rows, overall = evaluate(sp, traces, verbose=True)
    report = {
        "method": "dynamic ground truth: functions executed in the dependency while the parent "
        "ran a real scenario (requests: GET/POST/Session against a local server; flask: routes, "
        "templates, sessions, JSON via the test client)",
        "environment": {p.name.split("-")[0]: p.name for p in sp.glob("*.dist-info")},
        "chains": rows,
        "overall": overall,
    }
    if a.ablation:
        report["ablation"] = {"all mechanisms on": overall}
        for name in features.ON:
            features.ON[name] = False
            report["ablation"][f"without {name}"] = evaluate(sp, traces)[1]
            features.ON[name] = True
        for name in features.ON:
            features.ON[name] = False
        report["ablation"]["none (resolved calls by bare name only)"] = evaluate(sp, traces)[1]
        for name in features.ON:
            features.ON[name] = True
        for k, v in report["ablation"].items():
            print(f"{k:45} recall={v['recall']}  static share={v['static_reached_share']}")
    report["seconds"] = round(time.time() - t0, 1)
    report["generated"] = time.strftime("%Y-%m-%d")
    (ROOT / "results/metrics/symbols_transitive.json").write_text(
        json.dumps(report, indent=1) + "\n"
    )
    print(json.dumps(overall))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
