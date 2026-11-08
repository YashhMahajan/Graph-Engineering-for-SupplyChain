"""More input formats: each parser turns one file's text into a ``DepGraph``.

``lockfiles.parse`` looks a file name up in ``PARSERS`` after its own formats, so adding a
format is one function here plus its name in ``lockfiles.LOCKFILE_NAMES``. Parsers take the
path (for the graph's label and sibling files) and the text, and must not read anything
else: ``scgraph diff`` parses a file from git history through the same entry point.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .lockfiles import DepGraph

__all__ = ["PARSERS"]

PARSERS: dict[str, Callable[[Path, str], DepGraph]] = {}
