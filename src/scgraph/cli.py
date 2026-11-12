"""The ``scgraph`` command.

    scgraph scan [PATH ...] [--format text|json|sarif|markdown|openvex|html] [--fail-on P2]
    scgraph scan . --advisory CVE-2021-44228          incident mode: are we hit, and where?
    scgraph scan . --vex supplier.vex.json            apply a supplier's VEX statements
    scgraph diff --base origin/main                   only what this change introduced
    scgraph check npm left-pad@1.3.0                  pre-install guard
    scgraph audit                                     audit agent and IDE config (.mcp.json, hooks)
    scgraph scan . --history .scgraph-history         record the scan
    scgraph history .scgraph-history --advisory CVE-X when were we first exposed?
    scgraph hook claude-code                          PreToolUse hook (reads the event on stdin)
    scgraph mcp                                       MCP server over stdio
    scgraph fetch-osv --dir osv npm pypi              OSV dumps for --offline

Exit codes. scan: 0 no alert at or above --fail-on, 1 alerts, 2 error.
diff: the same, counting only the alerts the change introduced.
check: 0 allow, 1 warn, 2 block. audit: 0 nothing above info, 1 warn, 2 block.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__

FAIL_LEVELS = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, "any": 4, "never": -1}


class _CliError(Exception):
    """A user-facing error: printed as ``scgraph: <message>`` with exit code 2."""


def _collect_lockfiles(paths: list[str]) -> list[Path]:
    from .scan import lockfiles

    files: list[Path] = []
    for p in paths or ["."]:
        pp = Path(p)
        if not pp.exists():
            raise _CliError(f"no such file or directory: {p}")
        found = lockfiles.find_lockfiles(pp)
        if pp.is_file() and not lockfiles.is_lockfile(pp):
            raise _CliError(f"not a supported lockfile: {p}")
        files += found
    if not files:
        raise _CliError("no lockfiles found")
    return files


def _scan_context(a: argparse.Namespace):
    """Policy, advisory source, signals and registry fetcher from the shared scan options."""
    from .scan import engine
    from .scan.sources import Signals, default_osv, http_json

    vex = None
    if a.vex:
        from .scan.vex import VexError, load_vex

        try:
            vex = load_vex(a.vex)
        except VexError as e:
            raise _CliError(str(e)) from e
    ignore_file = a.ignore_file or (".scgraph-ignore" if Path(".scgraph-ignore").exists() else None)
    policy = engine.Policy(
        min_severity=a.min_severity,
        include_dev=a.include_dev,
        ignores=engine.load_ignores(ignore_file) if ignore_file else [],
        only=set(getattr(a, "advisory", None) or []),
        vex=vex,
    )
    registry = None if a.no_registry else http_json
    return policy, default_osv(a.offline), Signals(enabled=not a.no_signals), registry


def _scan(a: argparse.Namespace) -> int:
    from .scan import engine, lockfiles, render

    if a.history and a.advisory:
        # incident mode scans a subset: recording it would "close" every other exposure
        print("scgraph: --history cannot be combined with --advisory", file=sys.stderr)
        return 2
    try:
        files = _collect_lockfiles(a.paths)
        policy, src, sig, registry = _scan_context(a)
    except _CliError as e:
        print(f"scgraph: {e}", file=sys.stderr)
        return 2
    results = []
    for f in files:
        try:
            g = lockfiles.parse(f)
        except Exception as e:
            print(f"scgraph: cannot parse {f}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        try:
            results.append(engine.scan_graph(g, src, sig, policy, registry=registry))
        except Exception as e:
            print(
                f"scgraph: advisory lookup failed for {f}: {type(e).__name__}: {e}", file=sys.stderr
            )
            return 2
    if a.imports:
        from .scan import imports as source_imports

        scanned: dict[Path, source_imports.Imports] = {}
        for r in results:
            root = Path(r.path).resolve().parent
            seen = scanned.setdefault(root, source_imports.scan_sources(root))
            for finding in r.alerts:
                finding.imported = source_imports.classify(finding.ecosystem, finding.path, seen)
    if a.reachability or a.deep:
        from .scan import reachability
        from .symbols import dataset as symbol_data

        try:
            inferred = symbol_data.load()  # offline; zero model calls at scan time
        except symbol_data.DatasetError as e:
            print(f"scgraph: ignoring the inferred-symbol dataset: {e}", file=sys.stderr)
            inferred = symbol_data.Index([])
        deep = None
        if a.deep:
            from .symbols.deep import DeepAnalyzer

            deep = DeepAnalyzer()
        called: dict[tuple[Path, str], set[str]] = {}
        for r in results:
            root = Path(r.path).resolve().parent
            for finding in r.alerts:
                key = (root, finding.ecosystem)
                if key not in called:  # one source scan per project and language
                    scan = (
                        reachability.scan_js
                        if finding.ecosystem == "npm"
                        else reachability.scan_python
                    )
                    called[key] = scan(root)
                names = called[key]
                if finding.symbols:
                    finding.symbols_source = "osv"
                elif finding.ecosystem in ("PyPI", "npm"):
                    rec = inferred.get(sorted(finding.all_ids()), package=finding.package)
                    if rec is not None:
                        finding.symbols = [rec["symbol"], *rec.get("entry_points", [])]
                        finding.symbols_source = "inferred"
                        ev = rec.get("evidence") or {}
                        finding.symbol_evidence = ev.get("fix") or "code search"
                        if deep is not None and finding.path and len(finding.path) > 2:
                            prop, note = deep.analyze(finding.path, rec)
                            if prop is None:
                                finding.symbols = []
                                finding.symbol_evidence += f" ({note})"
                            else:
                                finding.reach_hops = len(finding.path) - 1
                                finding.symbols = prop.names
                                if not prop.reached:
                                    finding.symbol_evidence += (
                                        f" (no call from {prop.broke_at} into the next package)"
                                    )
                finding.reachability = reachability.classify(
                    finding.ecosystem,
                    finding.path,
                    finding.symbols,
                    names,
                    deep=finding.reach_hops > 1,
                )
                if (
                    finding.reach_hops > 1
                    and not finding.symbols
                    and "(no call" in (finding.symbol_evidence)
                ):
                    finding.reachability = "not_called"  # analysed, and no path reaches it
    fmt = {
        "text": lambda: render.to_text(results, verbose=a.verbose),
        "json": lambda: render.to_json(results),
        "sarif": lambda: render.to_sarif(results),
        "markdown": lambda: render.to_markdown(results),
        "openvex": lambda: render.to_openvex(results),
        "html": lambda: render.to_html(results),
    }[a.format]()
    if a.output:
        Path(a.output).write_text(fmt, encoding="utf-8")
    else:
        sys.stdout.write(fmt)
    summary = a.summary or (os.environ.get("GITHUB_STEP_SUMMARY") if a.github_summary else None)
    if summary:
        with Path(summary).open("a", encoding="utf-8") as fh:
            fh.write(render.to_markdown(results) + "\n")
    if a.history:
        from .scan import history

        c = history.record_scan(history.open_history(a.history), results)
        print(
            f"scgraph: recorded in {a.history}: {c['opened']} exposure(s) opened, "
            f"{c['closed']} closed",
            file=sys.stderr,
        )
    level = FAIL_LEVELS[a.fail_on]
    worst = [int(f.priority[1]) for r in results for f in r.alerts]
    return 1 if level >= 0 and any(w <= level for w in worst) else 0


def _diff(a: argparse.Namespace) -> int:
    from .scan import diff, diff_render

    try:
        files = _collect_lockfiles(a.paths)
        policy, src, sig, _ = _scan_context(a)
        commit = diff.resolve_ref(a.base, Path.cwd())
        deltas = []
        for f in files:
            try:
                deltas.append(diff.diff_lockfile(f, commit, src, sig, policy))
            except (_CliError, diff.DiffError):
                raise
            except Exception as e:  # the advisory source failed: say so, do not guess
                raise _CliError(f"advisory lookup failed for {f}: {type(e).__name__}: {e}") from e
    except (_CliError, diff.DiffError) as e:
        print(f"scgraph: {e}", file=sys.stderr)
        return 2
    text = {
        "text": lambda: diff_render.delta_text(deltas, a.base),
        "json": lambda: diff_render.delta_json(deltas, a.base),
        "markdown": lambda: diff_render.delta_markdown(deltas, a.base),
    }[a.format]()
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    level = FAIL_LEVELS[a.fail_on]
    worst = [int(f.priority[1]) for d in deltas for f in d.new_alerts]  # new alerts only
    return 1 if level >= 0 and any(w <= level for w in worst) else 0


def _history(a: argparse.Namespace) -> int:
    from .scan import history

    if not (Path(a.dir) / "base").is_dir():
        print(
            f"scgraph: {a.dir} is not a scan history (record one with scan --history)",
            file=sys.stderr,
        )
        return 2
    ledger = history.open_history(a.dir)
    if a.verify:
        print(
            f"scgraph: history verified, {history.verify(ledger)} recorded change(s), chain intact"
        )
        return 0
    if a.check:
        from .core.ledger import Receipt

        ok = history.check_receipt(
            ledger, Receipt.from_json(Path(a.check).read_text(encoding="utf-8"))
        )
        print("receipt verified" if ok else "receipt does NOT match this history")
        return 0 if ok else 1
    eps, receipt = history.episodes(ledger, a.advisory)
    if a.receipt:
        Path(a.receipt).write_text(receipt.to_json(), encoding="utf-8")
    if a.json:
        print(
            json.dumps({"advisory": a.advisory, "episodes": [e.to_dict() for e in eps]}, indent=2)
        )
    else:
        print(f"{a.advisory}: {len(eps)} exposure episode(s)")
        for e in eps:
            end = (
                f"-> {e.exposed_until} (no longer an alert)"
                if e.exposed_until
                else "-> still exposed"
            )
            print(f"  {e.lockfile}  {e.exposed_from} {end}")
        print(
            "  (a window starts at the first recorded scan that alerted, "
            "not when the code became vulnerable)"
        )
    return 1 if any(e.exposed_until is None for e in eps) else 0


def _audit(a: argparse.Namespace) -> int:
    from .scan import agentconfig
    from .scan.guard import check_package

    paths = [Path(p) for p in a.paths or ["."]]
    for p in paths:
        if not p.exists():
            print(f"scgraph: no such file or directory: {p}", file=sys.stderr)
            return 2
    checker = None if a.offline_check else check_package
    findings = agentconfig.audit(paths, checker)
    if a.json:
        print(agentconfig.to_json(findings))
    else:
        for f in findings:
            if f.level == "info" and not a.verbose:
                continue
            where = f" {f.where}" if f.where else ""
            print(f"{f.level.upper():5} {f.file}{where}: [{f.code}] {f.message}")
        autos = sum(1 for f in findings if f.code == "runs_automatically")
        flagged = sum(1 for f in findings if f.level != "info")
        print(
            f"\n{autos} command(s) run automatically, {flagged} finding(s)"
            + ("" if a.verbose or not autos else " (-v lists every command)")
        )
    return {"info": 0, "warn": 1, "block": 2}[agentconfig.worst(findings)]


def _check(a: argparse.Namespace) -> int:
    from .scan.guard import check_package, normalize_ecosystem, parse_spec

    eco = normalize_ecosystem(a.ecosystem)
    worst = 0
    out = []
    for spec in a.packages:
        name, ver = parse_spec(spec, eco)
        c = check_package(eco, name, ver, cooldown_hours=a.cooldown)
        out.append(c)
        worst = max(worst, {"allow": 0, "warn": 1, "block": 2}[c.verdict])
    if a.json:
        print(json.dumps([c.to_dict() for c in out], indent=2))
    else:
        for c in out:
            print(c.line())
    return worst


def _hook(a: argparse.Namespace) -> int:
    from .scan.agent import claude_code_hook

    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    decision = claude_code_hook(event)
    if decision:
        print(json.dumps(decision))
    return 0


def _mcp(a: argparse.Namespace) -> int:
    from .scan.agent import serve_mcp

    serve_mcp()
    return 0


def _fetch_osv(a: argparse.Namespace) -> int:
    from .scan.sources import fetch_osv_dumps

    fetch_osv_dumps(a.ecosystems, a.dir)
    return 0


def _add_shared_scan_options(s: argparse.ArgumentParser) -> None:
    """Options that scan and diff share: how findings are judged and where advisories come from."""
    s.add_argument(
        "--min-severity", type=float, default=0.0, help="CVSS floor (KEV and malicious always pass)"
    )
    s.add_argument("--include-dev", action="store_true", help="alert on dev-only dependencies too")
    s.add_argument("--ignore-file", help="ignore list (default: .scgraph-ignore if present)")
    s.add_argument(
        "--vex",
        action="append",
        metavar="FILE",
        help="OpenVEX file whose not_affected/fixed statements suppress findings (repeatable)",
    )
    s.add_argument(
        "--offline", metavar="DIR", help="match against OSV all.zip dumps in DIR (see fetch-osv)"
    )
    s.add_argument("--no-signals", action="store_true", help="skip CISA KEV and EPSS lookups")
    s.add_argument(
        "--no-registry",
        action="store_true",
        help="skip registry lookups (direct-dependency bump planning)",
    )
    s.add_argument(
        "--fail-on",
        choices=list(FAIL_LEVELS),
        default="any",
        help="exit 1 at this priority or worse",
    )


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
    s.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif", "markdown", "openvex", "html"],
        default="text",
    )
    s.add_argument("-o", "--output", help="write the report here instead of stdout")
    _add_shared_scan_options(s)
    s.add_argument(
        "--advisory",
        action="append",
        metavar="ID",
        help="incident mode: only this advisory (repeatable)",
    )
    s.add_argument("--summary", metavar="FILE", help="also append a Markdown summary to FILE")
    s.add_argument(
        "--github-summary", action="store_true", help="append Markdown to $GITHUB_STEP_SUMMARY"
    )
    s.add_argument(
        "--history",
        metavar="DIR",
        help="record this scan in a ledger at DIR (see: scgraph history)",
    )
    s.add_argument(
        "--imports",
        action="store_true",
        help="hint whether project source imports each alert's dependency (never suppresses)",
    )
    s.add_argument(
        "--reachability",
        action="store_true",
        help="mark Python alerts whose vulnerable functions your source references (from the "
        "advisory, else from the inferred-symbol dataset; never suppresses)",
    )
    s.add_argument(
        "--deep",
        action="store_true",
        help="also follow transitive dependency paths through released source (implies "
        "--reachability; downloads each package on the path once, then caches)",
    )
    s.add_argument("-v", "--verbose", action="store_true", help="list every abstention")
    s.set_defaults(fn=_scan)

    d = sub.add_parser("diff", help="what did this change introduce? (new alerts vs a git ref)")
    d.add_argument("paths", nargs="*", help="lockfiles or directories (default: .)")
    d.add_argument("--base", required=True, metavar="REF", help="git ref to compare against")
    d.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    d.add_argument("-o", "--output", help="write the report here instead of stdout")
    _add_shared_scan_options(d)
    d.set_defaults(fn=_diff)

    hi = sub.add_parser(
        "history", help="when were we first exposed? (reads a scan --history ledger)"
    )
    hi.add_argument("dir", help="the ledger directory given to scan --history")
    how = hi.add_mutually_exclusive_group(required=True)
    how.add_argument("--advisory", metavar="ID", help="exposure episodes for this advisory id")
    how.add_argument("--verify", action="store_true", help="check the hash chain is intact")
    how.add_argument("--check", metavar="FILE", help="verify a receipt written by --receipt")
    hi.add_argument("--receipt", metavar="FILE", help="write a verifiable receipt for the answer")
    hi.add_argument("--json", action="store_true")
    hi.set_defaults(fn=_history)

    u = sub.add_parser(
        "audit",
        help="audit AI-agent and IDE config (.mcp.json, hooks, tasks) for supply-chain risk",
    )
    u.add_argument("paths", nargs="*", help="project directories or config files (default: .)")
    u.add_argument("--json", action="store_true")
    u.add_argument("-v", "--verbose", action="store_true", help="list every automatic command")
    u.add_argument(
        "--offline-check",
        action="store_true",
        help="skip the registry and OSV lookups, report only what the files themselves show",
    )
    u.set_defaults(fn=_audit)

    c = sub.add_parser("check", help="should this package be installed? (pre-install guard)")
    c.add_argument("ecosystem", help="npm, pypi, cargo, go, gem, composer")
    c.add_argument("packages", nargs="+", metavar="NAME[@VERSION]")
    c.add_argument(
        "--cooldown", type=float, default=48.0, help="hours a release must age (default 48)"
    )
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_check)

    h = sub.add_parser("hook", help="agent hooks (reads the hook event JSON on stdin)")
    h.add_argument("agent", choices=["claude-code"])
    h.set_defaults(fn=_hook)

    m = sub.add_parser("mcp", help="run the MCP server over stdio")
    m.set_defaults(fn=_mcp)

    o = sub.add_parser("fetch-osv", help="download OSV all.zip dumps for --offline")
    o.add_argument("ecosystems", nargs="+", help="npm pypi cargo go maven rubygems packagist nuget")
    o.add_argument("--dir", default="osv")
    o.set_defaults(fn=_fetch_osv)

    from .symbols.cli import add_parser as add_symbols

    add_symbols(sub)
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
