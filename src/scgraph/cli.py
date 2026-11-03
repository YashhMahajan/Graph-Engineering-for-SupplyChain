"""The ``scgraph`` command.

    scgraph scan [PATH ...] [--format text|json|sarif|markdown] [--fail-on P2]
    scgraph scan . --advisory CVE-2021-44228          incident mode: are we hit, and where?
    scgraph fetch-osv --dir osv npm pypi              OSV dumps for --offline

Exit codes: 0 no alert at or above --fail-on, 1 alerts, 2 error.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__

FAIL_LEVELS = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, "any": 4, "never": -1}


def _scan(a: argparse.Namespace) -> int:
    from .scan import engine, lockfiles, render
    from .scan.sources import Signals, default_osv

    files: list[Path] = []
    for p in a.paths or ["."]:
        pp = Path(p)
        if not pp.exists():
            print(f"scgraph: no such file or directory: {p}", file=sys.stderr)
            return 2
        found = lockfiles.find_lockfiles(pp)
        if pp.is_file() and not lockfiles.is_lockfile(pp):
            print(f"scgraph: not a supported lockfile: {p}", file=sys.stderr)
            return 2
        files += found
    if not files:
        print("scgraph: no lockfiles found", file=sys.stderr)
        return 2
    ignore_file = a.ignore_file or (".scgraph-ignore" if Path(".scgraph-ignore").exists() else None)
    policy = engine.Policy(
        min_severity=a.min_severity,
        include_dev=a.include_dev,
        ignores=engine.load_ignores(ignore_file) if ignore_file else [],
        only=set(a.advisory or []),
    )
    src = default_osv(a.offline)
    sig = Signals(enabled=not a.no_signals)
    results = []
    for f in files:
        try:
            g = lockfiles.parse(f)
        except Exception as e:
            print(f"scgraph: cannot parse {f}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        try:
            results.append(engine.scan_graph(g, src, sig, policy))
        except Exception as e:
            print(
                f"scgraph: advisory lookup failed for {f}: {type(e).__name__}: {e}", file=sys.stderr
            )
            return 2
    fmt = {
        "text": lambda: render.to_text(results, verbose=a.verbose),
        "json": lambda: render.to_json(results),
        "sarif": lambda: render.to_sarif(results),
        "markdown": lambda: render.to_markdown(results),
    }[a.format]()
    if a.output:
        Path(a.output).write_text(fmt, encoding="utf-8")
    else:
        sys.stdout.write(fmt)
    summary = a.summary or (os.environ.get("GITHUB_STEP_SUMMARY") if a.github_summary else None)
    if summary:
        with Path(summary).open("a", encoding="utf-8") as fh:
            fh.write(render.to_markdown(results) + "\n")
    level = FAIL_LEVELS[a.fail_on]
    worst = [int(f.priority[1]) for r in results for f in r.alerts]
    return 1 if level >= 0 and any(w <= level for w in worst) else 0


def _fetch_osv(a: argparse.Namespace) -> int:
    from .scan.sources import fetch_osv_dumps

    fetch_osv_dumps(a.ecosystems, a.dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="scgraph",
        description=(
            "Software supply-chain exposure as graph paths: "
            "alert with proof, or abstain with a reason."
        ),
    )
    ap.add_argument("--version", action="version", version=f"scgraph {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan lockfiles; every alert carries its dependency path")
    s.add_argument("paths", nargs="*", help="lockfiles or directories (default: .)")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report here instead of stdout")
    s.add_argument(
        "--min-severity", type=float, default=0.0, help="CVSS floor (KEV and malicious always pass)"
    )
    s.add_argument("--include-dev", action="store_true", help="alert on dev-only dependencies too")
    s.add_argument(
        "--advisory",
        action="append",
        metavar="ID",
        help="incident mode: only this advisory (repeatable)",
    )
    s.add_argument("--ignore-file", help="ignore list (default: .scgraph-ignore if present)")
    s.add_argument(
        "--offline", metavar="DIR", help="match against OSV all.zip dumps in DIR (see fetch-osv)"
    )
    s.add_argument("--no-signals", action="store_true", help="skip CISA KEV and EPSS lookups")
    s.add_argument(
        "--fail-on",
        choices=list(FAIL_LEVELS),
        default="any",
        help="exit 1 at this priority or worse",
    )
    s.add_argument("--summary", metavar="FILE", help="also append a Markdown summary to FILE")
    s.add_argument(
        "--github-summary", action="store_true", help="append Markdown to $GITHUB_STEP_SUMMARY"
    )
    s.add_argument("-v", "--verbose", action="store_true", help="list every abstention")
    s.set_defaults(fn=_scan)

    o = sub.add_parser("fetch-osv", help="download OSV all.zip dumps for --offline")
    o.add_argument("ecosystems", nargs="+", help="npm pypi cargo go maven rubygems packagist nuget")
    o.add_argument("--dir", default="osv")
    o.set_defaults(fn=_fetch_osv)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return int(a.fn(a))
    except KeyboardInterrupt:
        return 130
    except ValueError as e:
        print(f"scgraph: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
