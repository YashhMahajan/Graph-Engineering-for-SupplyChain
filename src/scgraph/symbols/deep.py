"""Scan-time glue for transitive reachability: dependency path + inferred symbol -> names.

Needs the released source of every package on the path, so it is online and opt-in
(``scgraph scan --deep``); each download is cached. No model is involved.
"""

from __future__ import annotations

from .entry import entry_points
from .fetch import Fetcher
from .source import Release, pypi_release
from .transitive import Propagation, propagate

__all__ = ["DeepAnalyzer"]

MAX_CHAIN = 6


def _split(label: str) -> tuple[str, str] | None:
    name, sep, version = label.rpartition("@")
    return (name, version) if sep and name and version else None


class DeepAnalyzer:
    def __init__(self, fetcher: Fetcher | None = None):
        self.fetcher = fetcher or Fetcher()
        self._releases: dict[tuple[str, str], Release | None] = {}

    def release(self, name: str, version: str) -> Release | None:
        key = (name, version)
        if key not in self._releases:
            self._releases[key] = pypi_release(self.fetcher, name, version)
        return self._releases[key]

    def analyze(self, path: list[str], record: dict) -> tuple[Propagation | None, str]:
        """(propagation, note). ``path`` is [root, direct, ..., affected]; a None propagation
        means the analysis could not run, and the note says why."""
        labels = path[1:]
        if len(labels) < 2:
            return None, "not a transitive dependency"
        if len(labels) > MAX_CHAIN:
            return None, f"dependency path longer than {MAX_CHAIN} packages"
        chain: list[Release] = []
        for lab in labels:
            nv = _split(lab)
            rel = self.release(*nv) if nv else None
            if rel is None:
                return None, f"released source of {lab} unavailable"
            chain.append(rel)
        mod, qn = record["module"], record["qualname"]
        if chain[-1].find(mod, qn) is None:
            return (
                None,
                f"{qn} is not in {labels[-1]} (the symbol was inferred for another version)",
            )
        seeds = entry_points(chain[-1], mod, qn)
        if (mod, qn) not in seeds:
            seeds.append((mod, qn))
        return propagate(chain, seeds), ""
