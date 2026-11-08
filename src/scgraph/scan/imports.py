"""Import-level hint: does the project's own source import the dependency behind an alert?

This is a *hint printed next to an alert*. It never suppresses one. A real answer to "is the
vulnerable function called" needs a call graph, which this is not. What it can say is narrower
and cheap:

  imported      project source imports the dependency at the top of the alert's path
                (the alert's own package when it is direct, otherwise the direct dependency
                that pulls it in)
  not_imported  no JavaScript or TypeScript source file imports it. This is only a hint:
                a package used through configuration (a Babel or ESLint plugin, a Jest
                preset, a bundler loader) is never imported in source and is not detected
  unknown       nothing can be said: another ecosystem, no source files, or a PyPI package
                that is not imported under its own name

PyPI is never ``not_imported``. A distribution and its import name differ (``pyyaml`` is
imported as ``yaml``, ``beautifulsoup4`` as ``bs4``), so "I did not see the name" would be a
wrong claim, not a hint. A PyPI package is ``imported`` only when the names match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .lockfiles import _SKIP_DIRS, pep503

__all__ = ["Imports", "classify", "scan_sources"]

_JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_MAX_FILES = 20_000
_MAX_BYTES = 1_000_000
_JS_SPEC = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)['"]([^'"\n]+)['"]"""
)
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w]*)|import\s+([A-Za-z_][\w]*))", re.MULTILINE)


@dataclass
class Imports:
    npm: set[str] = field(default_factory=set)
    pypi: set[str] = field(default_factory=set)  # PEP 503 normalised import names
    js_files: int = 0
    py_files: int = 0


def _package_of(spec: str) -> str | None:
    """``lodash/fp`` -> ``lodash``; ``@scope/pkg/sub`` -> ``@scope/pkg``; relative -> None."""
    if spec.startswith((".", "/", "node:", "#")) or ":" in spec.split("/")[0]:
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def scan_sources(root: Path) -> Imports:
    """Collect what ``root``'s own JS/TS and Python source imports, skipping vendored,
    build and hidden directories, huge files and anything past the file cap."""
    out = Imports()
    seen = 0
    stack = [root]
    while stack and seen < _MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
                continue
            ext = e.suffix.lower()
            if ext not in _JS_EXT and ext != ".py":
                continue
            seen += 1
            try:
                if e.stat().st_size > _MAX_BYTES:
                    continue
                text = e.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if ext == ".py":
                out.py_files += 1
                for m in _PY_IMPORT.finditer(text):
                    out.pypi.add(pep503(m.group(1) or m.group(2)))
            else:
                out.js_files += 1
                for m in _JS_SPEC.finditer(text):
                    pkg = _package_of(m.group(1))
                    if pkg:
                        out.npm.add(pkg)
    return out


def classify(ecosystem: str, path: list[str] | None, imports: Imports) -> str:
    """``imported``, ``not_imported`` or ``unknown`` for an alert's dependency path."""
    if not path or len(path) < 2:
        return "unknown"
    top = path[1].rpartition("@")[0]  # "@scope/pkg@1.0.0" -> "@scope/pkg"
    if ecosystem == "npm":
        if imports.js_files == 0:
            return "unknown"
        return "imported" if top in imports.npm else "not_imported"
    if ecosystem == "PyPI":
        return "imported" if pep503(top) in imports.pypi else "unknown"
    return "unknown"
