"""scgraph as a tool: scan lockfiles, alert with a path or abstain with a reason.

    scgraph scan [PATH ...]          every alert with its dependency path, or an abstention

The scan runs on the same core engine as the ecosystem-scale graph: a lockfile becomes
a ``scgraph.core.TypedGraph``, exposure is ``find_paths`` and the verdict is a ``Ladder``.
"""

from __future__ import annotations

from .engine import Finding, Policy, ScanResult, load_ignores, scan_graph
from .lockfiles import DepGraph, Pkg, find_lockfiles, parse
from .sources import OSVApi, OSVOffline, Signals

__all__ = [
    "DepGraph",
    "Finding",
    "OSVApi",
    "OSVOffline",
    "Pkg",
    "Policy",
    "ScanResult",
    "Signals",
    "find_lockfiles",
    "load_ignores",
    "parse",
    "scan",
    "scan_graph",
]


def scan(path=".", *, offline=None, signals=True, policy=None) -> list[ScanResult]:
    """Scan every lockfile under ``path`` (or one lockfile)."""
    from pathlib import Path

    from .sources import default_osv

    src = default_osv(offline)
    sig = Signals(enabled=signals)
    return [scan_graph(parse(p), src, sig, policy) for p in find_lockfiles(Path(path))]
