"""scgraph as a tool: read lockfiles and match them against OSV.

``lockfiles``  lockfiles to dependency graphs, with no resolver and no network
``sources``    the OSV API, OSV dumps for offline use, CISA KEV and FIRST EPSS
"""

from __future__ import annotations

from .lockfiles import DepGraph, Pkg, find_lockfiles, parse
from .sources import OSVApi, OSVOffline, Signals

__all__ = ["DepGraph", "OSVApi", "OSVOffline", "Pkg", "Signals", "find_lockfiles", "parse"]
