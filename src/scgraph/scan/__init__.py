"""scgraph as a tool: read lockfiles and match them against OSV.

``lockfiles``  lockfiles to dependency graphs, with no resolver and no network
"""

from __future__ import annotations

from .lockfiles import DepGraph, Pkg, find_lockfiles, parse

__all__ = ["DepGraph", "Pkg", "find_lockfiles", "parse"]
