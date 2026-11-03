"""Scan results as terminal text, JSON, SARIF 2.1.0 and Markdown.

SARIF is what GitHub code scanning ingests, so alerts land in the Security tab with the
dependency path in the message. Markdown is for ``$GITHUB_STEP_SUMMARY`` and PR comments.
Abstentions are shown everywhere in summary form: nothing is hidden, only ranked.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .. import __version__
from ..versions import compare
from .engine import Finding, ScanResult

__all__ = ["portfolio_summary", "to_json", "to_markdown", "to_sarif", "to_text"]

_COLOR = {
    "P0": "1;97;41",
    "P1": "1;31",
    "P2": "31",
    "P3": "33",
    "P4": "36",
    "dim": "2",
    "ok": "32",
    "b": "1",
}
_TAG = {"P0": "MALICIOUS", "P1": "EXPLOITED", "P2": "CRITICAL", "P3": "HIGH", "P4": "ALERT"}


def _use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or (hasattr(stream, "isatty") and stream.isatty())


def _c(s: str, key: str, on: bool) -> str:
    return f"\033[{_COLOR[key]}m{s}\033[0m" if on else s


def _signal_bits(f: Finding) -> str:
    bits = []
    if f.score is not None and not f.malicious:
        bits.append(f"cvss {f.score:.1f}")
    if f.kev:
        bits.append("CISA KEV")
    if f.epss is not None:
        bits.append(f"epss {f.epss:.2f}")
    if f.dev_only:
        bits.append("dev")
    return " · ".join(bits)


def _path_lines(f: Finding, on: bool) -> list[str]:
    if not f.path:
        return []
    out = [f"   {f.path[0]}"]
    for k, hop in enumerate(f.path[1:], 1):
        last = k == len(f.path) - 1
        out.append("   " + "   " * (k - 1) + "└─ " + (_c(hop, "b", on) if last else hop))
    return out


def to_text(results: list[ScanResult], color: bool | None = None, verbose: bool = False) -> str:
    on = _use_color() if color is None else color
    lines: list[str] = []
    for r in results:
        sig = ", ".join(f"{k} {v}" for k, v in r.signals.items())
        head = f"{r.path}  ({r.format} · {r.n_packages} packages · {r.n_direct} direct · {r.source}"
        lines.append(_c(head + (f" · {sig}" if sig else "") + ")", "b", on))
        if not r.alerts:
            lines.append("  " + _c("no alerts", "ok", on))
        fixes = {(a["package"], a["from"]): a for a in r.remediation}
        groups: dict[tuple[str, str], list[Finding]] = {}
        for f in r.alerts:  # already in priority order, so groups are too
            groups.setdefault((f.package, f.version), []).append(f)
        for (pkg, ver), fs in groups.items():
            top = fs[0]
            n = len(fs)
            worst = max((f.score or 0 for f in fs), default=0)
            meta = [f"{n} advisor{'y' if n == 1 else 'ies'}"]
            if worst and not top.malicious:
                meta.append(f"worst cvss {worst:.1f}")
            if any(f.kev for f in fs):
                meta.append("CISA KEV")
            ep = max((f.epss or 0 for f in fs), default=0)
            if ep:
                meta.append(f"epss {ep:.2f}")
            tag = _c(f" {top.priority} {_TAG[top.priority]} ", top.priority, on)
            lines.append(
                f"\n {tag} {_c(f'{pkg}@{ver}', 'b', on)}  {_c(' · '.join(meta), 'dim', on)}"
            )
            lines.extend(_path_lines(top, on))
            shown = fs if verbose else fs[:3]
            width = max(len(f.id) for f in shown)
            for f in shown:
                sc = (
                    "MAL " if f.malicious else f"{f.score:>4.1f}" if f.score is not None else "  ? "
                )
                kev = " KEV" if f.kev else ""
                lines.append(f"   {f.id:<{width}}  {sc}{kev}  {_c(f.summary[:80], 'dim', on)}")
            if len(fs) > len(shown):
                lines.append("   " + _c(f"+{len(fs) - len(shown)} more (-v to list)", "dim", on))
            a = fixes.get((pkg, ver))
            if a and a["action"] == "upgrade":
                fx = f"upgrade {pkg} to {a['to']}" + (f" (clears all {n})" if n > 1 else "")
            else:
                fx = top.fix
            lines.append("   " + _c("fix ", "ok", on) + fx)
        ab = r.abstention_counts()
        if verbose and r.abstentions:
            lines.append("")
            for f in r.abstentions:
                lines.append(
                    _c(
                        f"  abstain [{f.reason}] {f.id} {f.package}@{f.version}: {f.detail}",
                        "dim",
                        on,
                    )
                )
        tail = [f"{len(r.alerts)} alert{'s' * (len(r.alerts) != 1)}"]
        if ab:
            tail.append(
                f"{sum(ab.values())} abstained ("
                + ", ".join(f"{n} {k}" for k, n in sorted(ab.items()))
                + ")"
            )
        if r.merged_duplicates:
            tail.append(f"{r.merged_duplicates} duplicate ids merged")
        if r.unpinned:
            tail.append(f"{len(r.unpinned)} unpinned requirement(s) not checked")
        lines.append("\n  " + " · ".join(tail) + f"  [{r.seconds * 1e3:.0f} ms]")
        if r.remediation:
            lines.append("  " + _c("fix plan", "b", on))
            for a in r.remediation:  # malicious first: nothing outranks removing malware
                if a["action"] == "remove":
                    lines.append(f"    {a['top_priority']}  remove {a['package']}@{a['from']}")
            covered: set[str] = {a["package"] for a in r.remediation if a["action"] == "remove"}
            own = {
                a["package"]: a for a in r.remediation if a["direct"] and a["action"] == "upgrade"
            }
            for b in r.parent_upgrades:
                covered.update(b["clears_packages"])
                mine = own.get(b["direct"])
                extra = ""
                if mine and compare(b["to"], mine["to"], "npm") >= 0:
                    covered.add(b["direct"])
                    extra = f" + {len(mine['clears'])} on {b['direct']} itself"
                warn = "  major version" if b["major"] else ""
                lines.append(
                    f"    {_c('bump', 'ok', on)} {b['direct']} {b['from']} -> {b['to']}  clears "
                    f"{len(b['clears'])} across {len(b['clears_packages'])} transitive "
                    f"package(s): {', '.join(b['clears_packages'][:6])}{extra}{_c(warn, 'P3', on)}"
                )
            for a in r.remediation:
                if a["package"] in covered:
                    continue
                via = (
                    ""
                    if a["direct"] or not a["via"]
                    else f"  (pulled in by {', '.join(a['via'][:3])})"
                )
                act = (
                    f"{a['package']} {a['from']} -> {a['to']}"
                    if a["action"] == "upgrade"
                    else f"{a['action']} {a['package']}@{a['from']}"
                )
                lines.append(f"    {a['top_priority']}  {act}  clears {len(a['clears'])}{via}")
        lines.append("")
    if len(results) > 1:
        lines.append(portfolio_summary(results, on))
    return "\n".join(lines).rstrip() + "\n"


def portfolio_summary(results: list[ScanResult], color: bool = False, limit: int = 12) -> str:
    """Package -> its advisories and every lockfile they reach: the incident view."""
    rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    by_pkg: dict[str, dict] = {}
    for r in results:
        for f in r.alerts:
            row = by_pkg.setdefault(f.package, {"ids": set(), "files": set(), "top": "P4"})
            row["ids"].add(f.id)
            row["files"].add(r.path)
            row["top"] = min(row["top"], f.priority, key=rank.__getitem__)
    exposed = {r.path for r in results if r.alerts}
    n_adv = len({f.id for r in results for f in r.alerts})
    out = [
        _c(
            f"portfolio: {len(results)} lockfiles · {len(exposed)} exposed · "
            f"{n_adv} distinct advisories in {len(by_pkg)} packages",
            "b",
            color,
        )
    ]
    rows = sorted(by_pkg.items(), key=lambda kv: (rank[kv[1]["top"]], -len(kv[1]["files"]), kv[0]))
    for name, row in rows[:limit]:
        ids = sorted(row["ids"])
        shown = ", ".join(ids[:2]) + (f" +{len(ids) - 2}" if len(ids) > 2 else "")
        out.append(f"  {row['top']}  {name:<24} {len(row['files'])} lockfile(s)  {shown}")
    if len(rows) > limit:
        out.append(f"  +{len(rows) - limit} more packages (use --format json for all)")
    return "\n".join(out)


def to_json(results: list[ScanResult]) -> str:
    doc: dict = {
        "tool": "scgraph",
        "version": __version__,
        "results": [r.to_dict() for r in results],
    }
    if len(results) > 1:
        by: dict[str, list[str]] = {}
        for r in results:
            for f in r.alerts:
                by.setdefault(f.id, []).append(r.path)
        doc["portfolio"] = {k: sorted(set(v)) for k, v in sorted(by.items())}
    return json.dumps(doc, indent=2)


def _line_of(path: str, needle: str, cache: dict[str, list[str]]) -> int:
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    for i, line in enumerate(cache[path], 1):
        if needle in line:
            return i
    return 1


def to_sarif(results: list[ScanResult], base: str | None = None) -> str:
    rules: dict[str, dict] = {}
    res = []
    cache: dict[str, list[str]] = {}
    for r in results:
        try:
            uri = os.path.relpath(r.path, base or Path.cwd()).replace(os.sep, "/")
        except ValueError:  # another drive on Windows: no relative path exists
            uri = Path(r.path).resolve().as_posix()
        for f in r.alerts:
            rid = f.id
            if rid not in rules:
                sev = 10.0 if f.malicious else 9.5 if f.kev else (f.score or 5.0)
                rules[rid] = {
                    "id": rid,
                    "name": rid.replace("-", ""),
                    "shortDescription": {"text": (f.summary or rid)[:120]},
                    "fullDescription": {"text": f.summary or rid},
                    "helpUri": f"https://osv.dev/vulnerability/{f.ids[0]}",
                    "help": {"text": f"{f.summary}\n\nIds: {', '.join(f.ids + f.aliases)}"},
                    "properties": {
                        "security-severity": f"{sev:.1f}",
                        "tags": [
                            "security",
                            "supply-chain",
                            f.severity,
                            *(["kev"] if f.kev else []),
                        ],
                    },
                }
            line = _line_of(r.path, f.package, cache)
            chain = " -> ".join(f.path or [])
            res.append(
                {
                    "ruleId": rid,
                    "level": "error" if f.priority in ("P0", "P1", "P2") else "warning",
                    "message": {
                        "text": f"[{f.priority}] {f.package}@{f.version} is affected by {rid}. "
                        f"Path: {chain}. Fix: {f.fix}."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": line},
                            },
                            "logicalLocations": [{"name": f.purl, "kind": "package"}],
                        }
                    ],
                    "partialFingerprints": {"scgraph/v1": f"{uri}|{f.purl}|{rid}"},
                    "properties": {"path": f.path, "priority": f.priority, "epss": f.epss},
                }
            )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scgraph",
                        "version": __version__,
                        "informationUri": "https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain",
                        "rules": list(rules.values()),
                    }
                },
                "results": res,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_markdown(results: list[ScanResult]) -> str:
    n = sum(len(r.alerts) for r in results)
    out = [f"## scgraph: {n} alert{'s' * (n != 1)} across {len(results)} lockfile(s)", ""]
    for r in results:
        ab = r.abstention_counts()
        out.append(
            f"### `{r.path}` · {r.n_packages} packages · {len(r.alerts)} alerts · "
            f"{sum(ab.values())} abstained"
        )
        if not r.alerts:
            out += ["", "No alert survived the gates.", ""]
            continue
        out += ["", "| | advisory | package | signals | fix |", "|---|---|---|---|---|"]
        for f in r.alerts:
            out.append(
                f"| **{f.priority}** | [{f.id}](https://osv.dev/vulnerability/{f.ids[0]}) | "
                f"`{f.package}@{f.version}` | {_signal_bits(f)} | {f.fix} |"
            )
        out += ["", "<details><summary>dependency paths (the evidence)</summary>", "", "```"]
        for f in r.alerts:
            out.append(f"{f.id}: " + " -> ".join(f.path or []))
        out += ["```", "</details>", ""]
        if ab:
            out.append("Abstained: " + ", ".join(f"{k} {v}" for k, v in sorted(ab.items())) + ".")
            out.append("")
    return "\n".join(out)
