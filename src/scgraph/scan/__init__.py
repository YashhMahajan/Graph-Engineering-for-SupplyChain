"""scgraph as a tool: lockfile scanning, a pre-install guard and agent integrations.

    scgraph scan [PATH ...]          every alert with its dependency path, or an abstention
    scgraph check ECOSYSTEM NAME     should this package be installed at all?
    scgraph hook claude-code         a PreToolUse hook that guards agent installs
    scgraph mcp                      a Model Context Protocol server

The scan runs on the same core engine as the ecosystem-scale graph: a lockfile becomes
a ``scgraph.core.TypedGraph``, exposure is ``find_paths`` and the verdict is a ``Ladder``.
"""

from __future__ import annotations

from .engine import Finding, Policy, ScanResult, load_ignores, scan_graph
from .guard import Check, check_package
from .lockfiles import DepGraph, Pkg, find_lockfiles, parse
from .sources import OSVApi, OSVOffline, Signals

__all__ = [
    "Check",
    "DepGraph",
    "Finding",
    "OSVApi",
    "OSVOffline",
    "Pkg",
    "Policy",
    "ScanResult",
    "Signals",
    "check_package",
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
